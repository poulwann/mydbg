#include "backend/decompiler/DecompilerEngine.h"
#include "backend/lldb/LldbEngine.h"
#include "backend/session/SessionStore.h"
#include "TestSupport.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

using namespace std::chrono_literals;
namespace {
using debugger::test::require;

struct TemporaryDirectory {
  std::filesystem::path path;
  TemporaryDirectory() {
    char name[] = "/tmp/mydbg-session-integration-XXXXXX";
    const char *created = ::mkdtemp(name);
    if (!created)
      throw std::system_error(errno, std::generic_category(), "mkdtemp");
    path = created;
  }
  ~TemporaryDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};

debugger::CommandResult complete(debugger::CommandTicket ticket) {
  require(ticket.valid() && ticket.wait_for(20s), "command did not complete");
  const auto result = ticket.get();
  require(result.success, result.message);
  return result;
}

debugger::SessionSnapshot stopped(debugger::LldbEngine &engine,
                                  std::uint64_t after_stop = 0) {
  auto state = engine.snapshot();
  const auto deadline = std::chrono::steady_clock::now() + 20s;
  while (state.state != debugger::SessionState::Stopped ||
         state.stop_revision <= after_stop || state.pc == 0) {
    require(state.state != debugger::SessionState::Error &&
                state.state != debugger::SessionState::Exited,
            "target left the expected stop: " + state.error);
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
    require(remaining > 0ms, "target did not stop");
    const auto next = engine.wait_for_update(state.revision, remaining);
    require(next.has_value(), "no target stop update");
    state = *next;
  }
  return state;
}

std::string hex(std::uint64_t value) {
  char buffer[32]{};
  std::snprintf(buffer, sizeof(buffer), "0x%llx",
                static_cast<unsigned long long>(value));
  return buffer;
}

debugger::BreakpointInfo add_breakpoint(debugger::LldbEngine &engine,
                                        const std::string &specification) {
  const auto before = engine.snapshot();
  complete(engine.set_breakpoint(specification));
  for (const auto &breakpoint : engine.snapshot().breakpoints) {
    if (std::none_of(before.breakpoints.begin(), before.breakpoints.end(),
                     [&](const auto &old) { return old.id == breakpoint.id; }))
      return breakpoint;
  }
  throw std::runtime_error("new breakpoint was not published");
}

debugger::DecompilerRequest request_at(debugger::LldbEngine &engine,
                                       debugger::SessionStore &store,
                                       std::uint64_t address) {
  complete(engine.read_instructions(address));
  const auto state = engine.snapshot();
  const auto row = std::find_if(
      state.instructions.begin(), state.instructions.end(),
      [&](const auto &candidate) { return candidate.address == address; });
  require(row != state.instructions.end() && row->has_file_address,
          "instruction has no file-backed address");
  const auto module = std::find_if(
      state.modules.begin(), state.modules.end(), [&](const auto &candidate) {
        return candidate.has_load_bias &&
               candidate.load_bias + row->file_address == address;
      });
  require(module != state.modules.end(),
          "instruction module was not identified");
  return {.executable_path = module->path,
          .module_id = module->uuid.empty() ? module->path : module->uuid,
          .file_address = row->file_address,
          .load_address = address,
          .generation = state.generation,
          .debug_info_path = module->debug_info_path,
          .session = state.session,
          .analysis_revision =
              store.status(state.session.sha256).analysis_revision};
}

std::shared_ptr<const debugger::DecompilerSnapshot>
wait_decompiled(debugger::DecompilerEngine &engine,
                const debugger::DecompilerRequest &request) {
  const auto deadline = std::chrono::steady_clock::now() + 30s;
  while (std::chrono::steady_clock::now() < deadline) {
    const auto result = engine.snapshot();
    if (!result->loading && result->request_serial != 0 &&
        result->session == request.session &&
        result->generation == request.generation &&
        result->executable_path == request.executable_path &&
        result->requested_file_address == request.file_address) {
      require(result->error.empty(), result->error);
      return result;
    }
    std::this_thread::sleep_for(10ms);
  }
  throw std::runtime_error("session decompilation did not finish");
}

std::string source(const debugger::DecompilerSnapshot &result) {
  std::string text;
  for (const auto &line : result.lines)
    text += line.text + '\n';
  return text;
}

void require_comment(const debugger::SessionSnapshot &snapshot,
                     std::uint64_t address, std::string_view text) {
  const auto row = std::find_if(
      snapshot.instructions.begin(), snapshot.instructions.end(),
      [&](const auto &candidate) { return candidate.address == address; });
  require(row != snapshot.instructions.end() && row->user_comment == text,
          "linear address comment was not restored/deleted");
  require(snapshot.disassembly_graph != nullptr, "comment graph is missing");
  bool found = false;
  for (const auto &block : snapshot.disassembly_graph->blocks)
    for (const auto &instruction : block.instructions)
      if (instruction.address == address) {
        require(instruction.user_comment == text,
                "graph address comment disagrees with linear view");
        found = true;
      }
  require(found, "commented instruction was missing from graph");
}

void exercise_analysis(const std::filesystem::path &fixture,
                       const std::filesystem::path &directory) {
  const auto original = directory / "original-binary";
  const auto moved = directory / "moved-identical-binary";
  const auto saved = directory / "sessions";
  std::filesystem::copy_file(fixture, original);
  std::filesystem::copy_file(fixture, moved);
  const std::string note =
      "iteration invariant\nUnicode note: \xCE\xBC-sized value";
  std::string binary_hash;
  std::uint64_t saved_file_address{};
  std::uint64_t original_load_address{};

  {
    auto store = std::make_shared<debugger::SessionStore>(saved);
    debugger::LldbEngine engine{store};
    complete(engine.launch(original.string()));
    auto state = stopped(engine);
    require(!state.session.epoch.empty(), "durable session did not open");
    binary_hash = state.session.sha256;
    auto named = add_breakpoint(engine, "dwarf_compute");
    require(!named.addresses.empty(), "fixture function did not resolve");
    original_load_address = named.addresses.front();
    auto address = add_breakpoint(engine, hex(original_load_address));
    complete(engine.set_breakpoint_script(address.id, "rsi == 3"));
    complete(engine.execute_command("breakpoint modify -c 'bias == 3' " +
                                    std::to_string(named.id)));
    complete(engine.set_breakpoint_enabled(named.id, false));
    add_breakpoint(engine, "session_future_symbol");
    complete(engine.execute_command("ctx-watch eval 2 + 3"));
    complete(engine.set_disassembly_graph_enabled(true));
    complete(engine.set_comment(original_load_address, note, state.generation));
    complete(engine.execute_command("cymbol saved_site " +
                                    hex(original_load_address)));
    auto request = request_at(engine, *store, original_load_address);
    saved_file_address = request.file_address;
    require_comment(engine.snapshot(), original_load_address, note);

    debugger::DecompilerEngine analysis{store};
    analysis.request(request);
    auto result = wait_decompiled(analysis, request);
    const auto annotated = source(*result);
    const auto note_start = annotated.find("iteration invariant");
    require(note_start != std::string::npos &&
                annotated.find("iteration invariant", note_start + 1) ==
                    std::string::npos &&
                annotated.find("Unicode note: \xCE\xBC-sized value") !=
                    std::string::npos,
            "authored multiline note was omitted, duplicated, or damaged");
    analysis.edit({.context = request,
                   .kind = debugger::DecompilerEditKind::Rename,
                   .target_kind = debugger::DecompilerSymbolKind::Parameter,
                   .target_name = "payload",
                   .value = "iteration_payload"});
    result = wait_decompiled(analysis, request);
    require(source(*result).find("iteration_payload") != std::string::npos,
            "first rename did not apply");
    request.analysis_revision = result->analysis_revision;
    // A distinct pointee is observable; Ghidra's output omits C qualifiers.
    analysis.edit({.context = request,
                   .kind = debugger::DecompilerEditKind::SetType,
                   .target_kind = debugger::DecompilerSymbolKind::Parameter,
                   .target_name = "iteration_payload",
                   .value = "DwarfChoice *"});
    result = wait_decompiled(analysis, request);
    require(source(*result).find("DwarfChoice") != std::string::npos,
            "parameter type override did not apply");
    request.analysis_revision = result->analysis_revision;
    analysis.edit({.context = request,
                   .kind = debugger::DecompilerEditKind::Rename,
                   .target_kind = debugger::DecompilerSymbolKind::Parameter,
                   .target_name = "iteration_payload",
                   .value = "invalid-name"});
    result = wait_decompiled(analysis, request);
    require(source(*result).find("iteration_payload") != std::string::npos,
            "invalid rename changed the live symbol");
    // An accepted edit must not disappear when navigation and shutdown follow.
    analysis.edit({.context = request,
                   .kind = debugger::DecompilerEditKind::Rename,
                   .target_kind = debugger::DecompilerSymbolKind::Parameter,
                   .target_name = "iteration_payload",
                   .value = "saved_payload"});
    auto library = add_breakpoint(engine, "dwarf_scale");
    require(!library.addresses.empty(),
            "shared-library function did not resolve");
    complete(engine.remove_breakpoint(library.id));
    complete(engine.set_comment(library.addresses.front(),
                                "library iteration note", state.generation));
    auto library_request =
        request_at(engine, *store, library.addresses.front());
    analysis.request(library_request);
    result = wait_decompiled(analysis, library_request);
    require(source(*result).find("library iteration note") != std::string::npos,
            "shared-library comment was not attached to its own module");
    library_request.analysis_revision = result->analysis_revision;
    analysis.edit({.context = library_request,
                   .kind = debugger::DecompilerEditKind::Rename,
                   .target_kind = debugger::DecompilerSymbolKind::Parameter,
                   .target_name = "factor",
                   .value = "persisted_factor"});
    analysis.request(request);
    complete(engine.terminate());
  }

  {
    auto store = std::make_shared<debugger::SessionStore>(saved);
    debugger::LldbEngine engine{store};
    complete(engine.load(moved.string()));
    require(engine.snapshot().session.sha256 == binary_hash,
            "identical bytes at a new path selected a different session");
    require(store->status(binary_hash).breakpoint_count == 3,
            "user breakpoints were lost or generated launch stops were saved");
    complete(engine.execute_command("settings set target.disable-aslr false"));
    complete(engine.execute_command("run"));
    auto state = stopped(engine);
    require(state.pc != original_load_address,
            "relocation fixture did not exercise different load addresses");
    const auto restored =
        std::find_if(state.breakpoints.begin(), state.breakpoints.end(),
                     [](const auto &breakpoint) {
                       return breakpoint.script_condition == "rsi == 3";
                     });
    require(restored != state.breakpoints.end() && restored->enabled &&
                std::find(restored->addresses.begin(),
                          restored->addresses.end(),
                          state.pc) != restored->addresses.end(),
            "file-address breakpoint or bounded condition was not restored");
    require(std::any_of(state.breakpoints.begin(), state.breakpoints.end(),
                        [](const auto &breakpoint) {
                          return !breakpoint.enabled &&
                                 breakpoint.condition == "bias == 3";
                        }),
            "disabled/native-conditional breakpoint lost its options");
    require(std::any_of(state.breakpoints.begin(), state.breakpoints.end(),
                        [](const auto &breakpoint) {
                          return breakpoint.addresses.empty() &&
                                 breakpoint.description.find(
                                     "session_future_symbol") !=
                                     std::string::npos;
                        }),
            "pending symbolic breakpoint was lost");
    complete(engine.execute_command("context expressions"));
    const auto watches = engine.snapshot().watches;
    require(std::any_of(
                watches.begin(), watches.end(),
                [](const auto &watch) { return watch.expression == "2 + 3"; }),
            "expression watch definition was not restored");
    const auto symbols = complete(engine.execute_command("cymbol -l")).message;
    const auto symbol_address = symbols.find("0x");
    require(symbols.find("saved_site") != std::string::npos &&
                symbol_address != std::string::npos &&
                std::stoull(symbols.substr(symbol_address + 2), nullptr, 16) ==
                    state.pc,
            "custom symbol did not relocate with the identical binary");
    complete(engine.set_disassembly_graph_enabled(true));
    auto request = request_at(engine, *store, state.pc);
    require(request.file_address == saved_file_address,
            "restored breakpoint used a section offset instead of file VA");
    require_comment(engine.snapshot(), state.pc, note);
    debugger::DecompilerEngine analysis{store};
    analysis.request(request);
    auto result = wait_decompiled(analysis, request);
    const auto text = source(*result);
    require(
        text.find("saved_payload") != std::string::npos &&
            text.find("DwarfChoice") != std::string::npos &&
            text.find("iteration invariant") != std::string::npos,
        "ordered edits/comments did not survive path move and engine restart");
    auto library = add_breakpoint(engine, "dwarf_scale");
    require(!library.addresses.empty(),
            "restored shared-library function did not resolve");
    complete(engine.remove_breakpoint(library.id));
    auto library_request =
        request_at(engine, *store, library.addresses.front());
    analysis.request(library_request);
    result = wait_decompiled(analysis, library_request);
    require(
        source(*result).find("persisted_factor") != std::string::npos &&
            source(*result).find("library iteration note") != std::string::npos,
        "shared-library overrides were not restored within the root session");
    const auto changed_library = directory / "changed-library.so";
    std::filesystem::copy_file(library_request.executable_path,
                               changed_library);
    {
      std::ofstream changed(changed_library, std::ios::binary | std::ios::app);
      changed.exceptions(std::ios::badbit | std::ios::failbit);
      changed.put('\0');
    }
    auto changed_request = library_request;
    changed_request.executable_path = changed_library.string();
    analysis.request(changed_request);
    result = wait_decompiled(analysis, changed_request);
    require(source(*result).find("persisted_factor") == std::string::npos &&
                source(*result).find("library iteration note") ==
                    std::string::npos,
            "changed library bytes inherited another module's annotations");

    complete(engine.terminate());
    {
      std::ofstream changed(moved, std::ios::binary | std::ios::app);
      changed.exceptions(std::ios::badbit | std::ios::failbit);
      changed.put('\0');
    }
    complete(engine.load(moved.string()));
    require(engine.snapshot().session.sha256 != binary_hash &&
                engine.snapshot().breakpoints.empty(),
            "changed bytes inherited state through a reused path/build ID");
    complete(engine.launch(original.string()));
    state = stopped(engine);
    require(engine.snapshot().session.sha256 == binary_hash &&
                store->status(binary_hash).breakpoint_count == 3,
            "public rerun duplicated or discarded saved user breakpoints");
    const auto address_bp =
        std::find_if(state.breakpoints.begin(), state.breakpoints.end(),
                     [](const auto &breakpoint) {
                       return breakpoint.script_condition == "rsi == 3";
                     });
    require(address_bp != state.breakpoints.end() &&
                !address_bp->addresses.empty(),
            "address breakpoint did not return with the original binary");
    request = request_at(engine, *store, address_bp->addresses.front());
    analysis.request(request);
    result = wait_decompiled(analysis, request);
    require(source(*result).find("saved_payload") != std::string::npos,
            "generation change discarded persistent analysis");
    // Either ordering is legal; neither may put pre-clear work in the new
    // epoch.
    analysis.edit({.context = request,
                   .kind = debugger::DecompilerEditKind::Rename,
                   .target_kind = debugger::DecompilerSymbolKind::Parameter,
                   .target_name = "saved_payload",
                   .value = "must_not_resurrect"});
    const auto old_identity = request.session;
    complete(engine.clear_saved_session(binary_hash));
    state = engine.snapshot();
    require(
        state.session != old_identity && state.breakpoints.empty() &&
            state.watches.empty(),
        "clear did not replace the epoch and remove active debugger intent");
    request.session = state.session;
    request.analysis_revision = store->status(binary_hash).analysis_revision;
    analysis.request(request);
    result = wait_decompiled(analysis, request);
    const auto baseline = source(*result);
    require(baseline.find("saved_payload") == std::string::npos &&
                baseline.find("must_not_resurrect") == std::string::npos &&
                baseline.find("iteration invariant") == std::string::npos &&
                baseline.find("DwarfPayload *payload") != std::string::npos,
            "clear reused mutated analysis instead of rebuilding the DWARF "
            "baseline");
    complete(engine.read_instructions(request.load_address));
    require_comment(engine.snapshot(), request.load_address, {});
    complete(engine.terminate());
  }

  {
    auto store = std::make_shared<debugger::SessionStore>(saved);
    debugger::LldbEngine engine{store};
    complete(engine.load(original.string()));
    const auto status = store->status(binary_hash);
    require(engine.snapshot().breakpoints.empty() && status.edit_count == 0 &&
                status.comment_count == 0 && status.watch_count == 0,
            "cleared state returned after another engine restart");
  }
}

void exercise_named_breakpoint(const std::filesystem::path &fixture,
                               const std::filesystem::path &directory) {
  for (unsigned run = 0; run != 3; ++run) {
    auto store =
        std::make_shared<debugger::SessionStore>(directory / "name-sessions");
    debugger::LldbEngine engine{store};
    complete(engine.launch(fixture.string()));
    auto state = stopped(engine);
    if (run == 0) {
      add_breakpoint(engine, "dwarf_compute");
      state = engine.snapshot();
    }
    require(state.breakpoints.size() == 1 &&
                !state.breakpoints.front().addresses.empty(),
            "restored automatic name resolver lost its function locations");
    const auto address = state.breakpoints.front().addresses.front();
    complete(engine.continue_execution());
    state = stopped(engine, state.stop_revision);
    require(state.pc == address && state.breakpoints.front().hit_count == 1,
            "restored named breakpoint did not stop in its function");
    complete(engine.terminate());
  }
}

void exercise_exception_defaults(const std::filesystem::path &fixture,
                                 const std::filesystem::path &directory) {
  const auto saved = directory / "exception-sessions";
  {
    auto store = std::make_shared<debugger::SessionStore>(saved);
    debugger::LldbEngine engine{store};
    complete(engine.launch({.executable = fixture.string(),
                            .arguments = {"saved argument"},
                            .environment = {},
                            .working_directory = directory.string(),
                            .stop_policy = debugger::LaunchStopPolicy::Main}));
    stopped(engine);
    complete(engine.execute_command("breakpoint set -E c++ -h false -w true"));
    complete(engine.terminate());
  }
  {
    auto store = std::make_shared<debugger::SessionStore>(saved);
    debugger::LldbEngine engine{store};
    complete(engine.launch(fixture.string()));
    auto state = stopped(engine);
    complete(engine.continue_execution());
    state = stopped(engine, state.stop_revision);
    require(std::any_of(state.breakpoints.begin(), state.breakpoints.end(),
                        [](const auto &breakpoint) {
                          return breakpoint.hit_count != 0;
                        }),
            "restored C++ exception breakpoint did not stop on throw");
    require(state.process_output.find("session-argument:saved argument") !=
                    std::string::npos &&
                state.process_output.find("session-directory:" +
                                          directory.string()) !=
                    std::string::npos,
            "rerun lost remembered arguments or working directory");
    complete(engine.terminate());
    complete(engine.launch({.executable = fixture.string(),
                            .arguments = {},
                            .environment = {},
                            .working_directory = directory.string(),
                            .stop_policy = debugger::LaunchStopPolicy::Main}));
    state = stopped(engine);
    complete(engine.continue_execution());
    state = stopped(engine, state.stop_revision);
    require(state.process_output.find("session-argument:<none>") !=
                std::string::npos,
            "saved arguments overrode an explicitly empty launch request");
    complete(engine.terminate());
  }
}
} // namespace

int main(int argc, char **argv) {
  try {
    require(argc == 3,
            "usage: session_persistence_tests DWARF_FIXTURE EXCEPTION_FIXTURE");
    TemporaryDirectory directory;
    exercise_analysis(std::filesystem::canonical(argv[1]), directory.path);
    exercise_named_breakpoint(std::filesystem::canonical(argv[1]),
                              directory.path);
    exercise_exception_defaults(std::filesystem::canonical(argv[2]),
                                directory.path);
    std::puts("Session restart, relocation, analysis replay, comments, clear, "
              "and launch defaults passed");
    return 0;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "Session regression failed: %s\n", error.what());
    return 1;
  }
}
