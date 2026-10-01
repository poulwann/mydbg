#include "backend/lldb/QemuProcess.h"
#include "backend/lldb/LldbEngineInternal.h"
#include "localization/Localization.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace debugger::lldb_detail {
namespace {

// Spawns an engine-owned qemu-user gdbstub: `qemu -g port [-L sysroot]
// target args`. Returns the child pid and a pipe the engine owns for the
// target's stdin (write end only; the read end is the child's fd 0, or the
// child reads `stdin_file` directly). POSIX spawn keeps the fork out of the
// worker thread's signal state.
struct QemuStubChild {
  pid_t pid{-1};
  int stdin_fd{-1};
  int stdout_fd{-1};
};

struct QemuSpawnFiles {
  int stdin_pipe[2]{-1, -1};
  int stdout_pipe[2]{-1, -1};
  int stdin_file_fd{-1};

  ~QemuSpawnFiles() {
    for (const int fd : {stdin_pipe[0], stdin_pipe[1], stdout_pipe[0],
                         stdout_pipe[1], stdin_file_fd}) {
      if (fd >= 0) {
        close(fd);
      }
    }
  }
};

struct QemuSpawnActions {
  posix_spawn_file_actions_t actions;
  QemuSpawnActions() { posix_spawn_file_actions_init(&actions); }
  ~QemuSpawnActions() { posix_spawn_file_actions_destroy(&actions); }
};

std::optional<QemuStubChild> spawn_qemu_stub(
    const std::string &qemu_executable, const std::string &sysroot,
    const std::string &target, const std::vector<std::string> &arguments,
    const std::string &working_directory, const std::string &stdin_file,
    std::uint16_t port, std::string &failure) {
  QemuSpawnFiles files;
  auto &stdin_pipe = files.stdin_pipe;
  auto &stdout_pipe = files.stdout_pipe;
  auto &stdin_file_fd = files.stdin_file_fd;
  if (stdin_file.empty() && pipe(stdin_pipe) != 0) {
    failure = "stdin pipe failed";
    return std::nullopt;
  }
  if (pipe(stdout_pipe) != 0) {
    failure = "stdout pipe failed";
    return std::nullopt;
  }

  std::vector<std::string> storage;
  // Reserve before taking .data() pointers: growth would dangle the argv
  // entries (this once turned -L into garbage bytes).
  storage.reserve(4 + arguments.size());
  std::vector<char *> argv;
  argv.push_back(const_cast<char *>(qemu_executable.c_str()));
  if (!sysroot.empty()) {
    storage.push_back("-L");
    argv.push_back(storage.back().data());
    storage.push_back(sysroot);
    argv.push_back(storage.back().data());
  }
  storage.push_back("-g");
  argv.push_back(storage.back().data());
  storage.push_back(std::to_string(port));
  argv.push_back(storage.back().data());
  argv.push_back(const_cast<char *>(target.c_str()));
  for (const std::string &argument : arguments) {
    argv.push_back(const_cast<char *>(argument.c_str()));
  }
  argv.push_back(nullptr);

  QemuSpawnActions spawn_actions;
  auto &actions = spawn_actions.actions;
  if (!stdin_file.empty()) {
    stdin_file_fd = open(stdin_file.c_str(), O_RDONLY);
    if (stdin_file_fd < 0) {
      failure = "cannot open " + stdin_file;
      return std::nullopt;
    }
    posix_spawn_file_actions_adddup2(&actions, stdin_file_fd, STDIN_FILENO);
    posix_spawn_file_actions_addclose(&actions, stdin_file_fd);
  } else {
    posix_spawn_file_actions_adddup2(&actions, stdin_pipe[0], STDIN_FILENO);
  }
  posix_spawn_file_actions_adddup2(&actions, stdout_pipe[1], STDOUT_FILENO);
  if (stdin_pipe[0] >= 0) {
    posix_spawn_file_actions_addclose(&actions, stdin_pipe[0]);
    posix_spawn_file_actions_addclose(&actions, stdin_pipe[1]);
  }
  posix_spawn_file_actions_addclose(&actions, stdout_pipe[0]);
  posix_spawn_file_actions_addclose(&actions, stdout_pipe[1]);
  posix_spawn_file_actions_addopen(&actions, STDERR_FILENO,
                                   "/tmp/mydbg-qemu.log",
                                   O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (!working_directory.empty()) {
    posix_spawn_file_actions_addchdir_np(&actions, working_directory.c_str());
  }

  pid_t pid = -1;
  // Minimal environment: an inherited nix-shell LD_LIBRARY_PATH breaks
  // qemu's interpreter mapping ("File exists").
  std::string path_storage =
      "PATH=" + std::string(getenv("PATH") ? getenv("PATH") : "/usr/bin:/bin");
  std::string home_storage =
      "HOME=" + std::string(getenv("HOME") ? getenv("HOME") : "/root");
  std::string lang_storage = "LANG=C";
  char *environment[] = {path_storage.data(), home_storage.data(),
                         lang_storage.data(), nullptr};
  const int spawn_error =
      posix_spawnp(&pid, argv[0], &actions, nullptr, argv.data(), environment);
  if (spawn_error != 0 || pid <= 0) {
    failure = "posix_spawnp failed: " + std::string(strerror(spawn_error));
    return std::nullopt;
  }
  // The target's stdout flows through the owned pipe: the run loop drains it
  // into the session's output chunks.
  fcntl(stdout_pipe[0], F_SETFL, fcntl(stdout_pipe[0], F_GETFL) | O_NONBLOCK);
  return QemuStubChild{pid, std::exchange(stdin_pipe[1], -1),
                       std::exchange(stdout_pipe[0], -1)};
}

// A bindable loopback port for the gdbstub; the brief bind/close race is
// acceptable because qemu exits with a diagnostic the connect flow reports.
std::optional<std::uint16_t> pick_stub_port(std::string &failure) {
  int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    failure = "socket failed";
    return std::nullopt;
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  for (int attempt = 0; attempt < 64; ++attempt) {
    address.sin_port = htons(static_cast<std::uint16_t>(
        26000 + ((rand() ^ static_cast<int>(getpid())) % 20000)));
    if (bind(socket_fd, reinterpret_cast<sockaddr *>(&address),
             sizeof(address)) == 0) {
      const std::uint16_t port = ntohs(address.sin_port);
      close(socket_fd);
      return port;
    }
  }
  close(socket_fd);
  failure = "no free loopback port";
  return std::nullopt;
}

// Waits until qemu's gdbstub port is claimed. /proc/net/tcp misses qemu's
// listener entirely, so claim detection uses a bind probe (EADDRINUSE), the
// same approach the test harness uses.
bool wait_stub_listen(std::uint16_t port) {
  for (int attempt = 0; attempt < 250; ++attempt) {
    const int probe = socket(AF_INET, SOCK_STREAM, 0);
    if (probe >= 0) {
      sockaddr_in address{};
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      address.sin_port = htons(port);
      const int bind_result =
          bind(probe, reinterpret_cast<sockaddr *>(&address), sizeof(address));
      close(probe);
      if (bind_result < 0 && errno == EADDRINUSE) {
        return true;
      }
      if (bind_result == 0) {
        // We briefly own the port; drop it and let qemu retry consumers.
      }
    }
    usleep(20 * 1000);
  }
  return false;
}

} // namespace

QemuProcess::~QemuProcess() { stop(); }

bool QemuProcess::start(const RemoteOptions &options, std::string &endpoint,
                        std::string &failure) {
  stop();
  std::string detail;
  const auto port = pick_stub_port(detail);
  if (!port) {
    failure =
        l10n::format(l10n::Key::EngineQemuPortUnavailable, detail.c_str());
    return false;
  }
  const auto child = spawn_qemu_stub(options.qemu_executable, options.sysroot,
                                     options.executable, options.arguments,
                                     options.working_directory,
                                     options.stdin_file, *port, detail);
  if (!child) {
    failure = l10n::format(l10n::Key::EngineQemuSpawnFailed, detail.c_str());
    return false;
  }
  pid_ = child->pid;
  stdin_fd_ = child->stdin_fd;
  stdout_fd_ = child->stdout_fd;
  if (!wait_stub_listen(*port)) {
    stop();
    failure = l10n::format(l10n::Key::EngineQemuSpawnFailed,
                           "the gdbstub port never listened");
    return false;
  }
  endpoint = "connect://127.0.0.1:" + std::to_string(*port);
  return true;
}

void QemuProcess::drain_output() {
  if (stdout_fd_ < 0) {
    return;
  }
  char buffer[8192];
  for (;;) {
    const ssize_t count = read(stdout_fd_, buffer, sizeof(buffer));
    if (count <= 0) {
      return;
    }
    append_output_chunk(
        output_, std::string_view{buffer, static_cast<std::size_t>(count)});
  }
}

void QemuProcess::stop() {
  // Drain before killing the child, including when unwinding the worker.
  drain_output();
  if (stdout_fd_ >= 0) {
    close(stdout_fd_);
    stdout_fd_ = -1;
  }
  if (pid_ > 0) {
    kill(pid_, SIGKILL);
    while (waitpid(pid_, nullptr, 0) < 0 && errno == EINTR) {
    }
    pid_ = -1;
  }
  if (stdin_fd_ >= 0) {
    close(stdin_fd_);
    stdin_fd_ = -1;
  }
}

bool QemuProcess::send_stdin(std::string_view bytes, std::string &failure) {
  std::size_t written = 0;
  while (written < bytes.size()) {
    const ssize_t count =
        write(stdin_fd_, bytes.data() + written, bytes.size() - written);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      failure = l10n::format(l10n::Key::EngineQemuStdinFailed,
                             count == 0 ? "short write" : strerror(errno));
      return false;
    }
    written += static_cast<std::size_t>(count);
  }
  return true;
}

} // namespace debugger::lldb_detail
