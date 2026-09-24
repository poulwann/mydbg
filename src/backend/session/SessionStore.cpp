#include "backend/session/SessionStore.h"
#include "localization/Localization.h"

#include <rz_hash.h>
#include <rz_util/rz_json.h>
#include <rz_util/rz_pj.h>
extern "C" {
#include <rz_util/rz_utf8.h>
}

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <initializer_list>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>

namespace debugger {
namespace {

constexpr std::size_t max_document = 16 * 1024 * 1024;
constexpr std::size_t max_string = 1024 * 1024;
constexpr std::size_t max_comment = 64 * 1024;
constexpr std::size_t max_records = 65536;
constexpr std::size_t max_nodes = 524288;
constexpr unsigned max_depth = 64;
constexpr std::uint64_t format_version = 1;

[[noreturn]] void fail(l10n::Key key) {
  throw std::runtime_error(l10n::text(key));
}

[[noreturn]] void system_error(l10n::Key operation, int error = errno) {
  throw std::runtime_error(l10n::format(l10n::Key::SessionStoreSystemError,
                                        l10n::text(operation),
                                        std::strerror(error)));
}

class File {
public:
  explicit File(int fd) : fd_(fd) {}
  ~File() {
    if (fd_ >= 0)
      ::close(fd_);
  }
  File(const File &) = delete;
  File &operator=(const File &) = delete;
  File(File &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
  int get() const { return fd_; }

private:
  int fd_;
};

void check_hash(std::string_view hash,
                l10n::Key error = l10n::Key::SessionStoreInvalidHash) {
  if (hash.size() != 64 || !std::all_of(hash.begin(), hash.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
      }))
    fail(error);
}

std::string hex_bytes(const unsigned char *bytes, std::size_t size) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result(size * 2, '0');
  for (std::size_t i = 0; i < size; ++i) {
    result[2 * i] = digits[bytes[i] >> 4];
    result[2 * i + 1] = digits[bytes[i] & 15];
  }
  return result;
}

std::string new_epoch() {
  File random(::open("/dev/urandom", O_RDONLY | O_CLOEXEC));
  if (random.get() < 0)
    system_error(l10n::Key::SessionStoreRandom);
  std::array<unsigned char, 32> bytes{};
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto count =
        ::read(random.get(), bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      system_error(l10n::Key::SessionStoreRandom, count == 0 ? EIO : errno);
    offset += static_cast<std::size_t>(count);
  }
  return hex_bytes(bytes.data(), bytes.size());
}

void check_text(std::string_view value) {
  if (value.size() > max_string)
    fail(l10n::Key::SessionStoreLimit);
  for (std::size_t i = 0; i < value.size();) {
    RzCodePoint point{};
    const auto length =
        rz_utf8_decode(reinterpret_cast<const ut8 *>(value.data() + i),
                       value.size() - i, &point);
    if (!length || point == 0 || point > 0x10ffff ||
        (point >= 0xd800 && point <= 0xdfff))
      fail(l10n::Key::SessionStoreInvalidText);
    i += length;
  }
}

// Rizin's parser accepts comments and trailing input, and recursively allocates
// nodes. Check the complete, bounded JSON grammar before handing it any bytes.
// The schema has only unsigned integers: never route addresses through doubles.
class JsonPreflight {
public:
  explicit JsonPreflight(std::string_view input) : input_(input) {}
  void check() {
    if (input_.size() > max_document)
      fail(l10n::Key::SessionStoreLimit);
    value(0);
    whitespace();
    if (position_ != input_.size())
      fail(l10n::Key::SessionStoreMalformed);
  }

private:
  char peek() const {
    return position_ < input_.size() ? input_[position_] : '\0';
  }
  void whitespace() {
    while (peek() == ' ' || peek() == '\t' || peek() == '\r' || peek() == '\n')
      ++position_;
  }
  bool take(char ch) {
    if (peek() != ch)
      return false;
    ++position_;
    return true;
  }
  void expect(char ch) {
    if (!take(ch))
      fail(l10n::Key::SessionStoreMalformed);
  }
  unsigned hex_quad() {
    unsigned value = 0;
    for (unsigned i = 0; i < 4; ++i) {
      const char ch = peek();
      unsigned digit;
      if (ch >= '0' && ch <= '9')
        digit = ch - '0';
      else if (ch >= 'a' && ch <= 'f')
        digit = ch - 'a' + 10;
      else if (ch >= 'A' && ch <= 'F')
        digit = ch - 'A' + 10;
      else
        fail(l10n::Key::SessionStoreMalformed);
      ++position_;
      value = value * 16 + digit;
    }
    return value;
  }
  void string() {
    expect('"');
    const auto start = position_;
    while (!take('"')) {
      const auto ch = static_cast<unsigned char>(peek());
      if (ch < 0x20)
        fail(l10n::Key::SessionStoreMalformed);
      ++position_;
      if (ch == '\\') {
        const char escape = peek();
        ++position_;
        if (escape == 'u') {
          const auto point = hex_quad();
          if (point == 0 || (point >= 0xdc00 && point <= 0xdfff))
            fail(l10n::Key::SessionStoreInvalidText);
          if (point >= 0xd800 && point <= 0xdbff) {
            expect('\\');
            expect('u');
            const auto low = hex_quad();
            if (low < 0xdc00 || low > 0xdfff)
              fail(l10n::Key::SessionStoreInvalidText);
          }
        } else if (escape != '"' && escape != '\\' && escape != '/' &&
                   escape != 'b' && escape != 'f' && escape != 'n' &&
                   escape != 'r' && escape != 't') {
          fail(l10n::Key::SessionStoreMalformed);
        }
      } else if (ch >= 0x80) {
        --position_;
        RzCodePoint point{};
        const auto length = rz_utf8_decode(
            reinterpret_cast<const ut8 *>(input_.data() + position_),
            input_.size() - position_, &point);
        if (!length || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff))
          fail(l10n::Key::SessionStoreInvalidText);
        position_ += length;
      }
      if (position_ - start > max_string * 6)
        fail(l10n::Key::SessionStoreLimit);
    }
  }
  void value(unsigned depth) {
    if (depth > max_depth || ++nodes_ > max_nodes)
      fail(l10n::Key::SessionStoreLimit);
    whitespace();
    if (peek() == '{' || peek() == '[') {
      const bool object = take('{');
      if (!object)
        expect('[');
      const char closing = object ? '}' : ']';
      whitespace();
      if (take(closing))
        return;
      do {
        whitespace();
        if (object) {
          string();
          whitespace();
          expect(':');
        }
        value(depth + 1);
        whitespace();
        if (take(closing))
          return;
        expect(',');
      } while (true);
    }
    if (peek() == '"') {
      string();
      return;
    }
    for (const auto literal :
         {std::string_view{"true"}, std::string_view{"false"}}) {
      if (input_.substr(position_, literal.size()) == literal) {
        position_ += literal.size();
        return;
      }
    }
    const auto start = position_;
    if (!take('0')) {
      if (peek() < '1' || peek() > '9')
        fail(l10n::Key::SessionStoreMalformed);
      while (peek() >= '0' && peek() <= '9')
        ++position_;
    }
    std::uint64_t number{};
    const auto parsed = std::from_chars(input_.data() + start,
                                        input_.data() + position_, number);
    if (parsed.ec != std::errc{})
      fail(l10n::Key::SessionStoreMalformed);
  }

  std::string_view input_;
  std::size_t position_{};
  std::size_t nodes_{};
};

// Exact key matching is intentional: rz_json_get in Rizin 0.8 matches prefixes.
class Object {
public:
  Object(const RzJson *node, std::initializer_list<std::string_view> fields)
      : node_(node) {
    if (!node || node->type != RZ_JSON_OBJECT ||
        node->children.count != fields.size())
      fail(l10n::Key::SessionStoreMalformed);
    for (const auto field : fields) {
      unsigned count = 0;
      for (auto child = node->children.first; child; child = child->next)
        count += child->key && field == child->key;
      if (count != 1)
        fail(l10n::Key::SessionStoreMalformed);
    }
  }
  const RzJson *get(std::string_view key) const {
    for (auto child = node_->children.first; child; child = child->next)
      if (child->key && key == child->key)
        return child;
    fail(l10n::Key::SessionStoreMalformed);
  }
  std::string text(std::string_view key) const {
    const auto node = get(key);
    if (node->type != RZ_JSON_STRING || !node->str_value)
      fail(l10n::Key::SessionStoreMalformed);
    check_text(node->str_value);
    return node->str_value;
  }
  std::uint64_t number(std::string_view key) const {
    const auto node = get(key);
    if (node->type != RZ_JSON_INTEGER)
      fail(l10n::Key::SessionStoreMalformed);
    return node->num.u_value;
  }
  bool boolean(std::string_view key) const {
    const auto node = get(key);
    if (node->type != RZ_JSON_BOOLEAN)
      fail(l10n::Key::SessionStoreMalformed);
    return node->num.u_value != 0;
  }

private:
  const RzJson *node_;
};

const RzJson *array(const RzJson *node, std::size_t limit = max_records) {
  if (!node || node->type != RZ_JSON_ARRAY)
    fail(l10n::Key::SessionStoreMalformed);
  if (node->children.count > limit)
    fail(l10n::Key::SessionStoreLimit);
  return node->children.first;
}

std::vector<std::string> strings(const RzJson *node) {
  std::vector<std::string> result;
  for (auto item = array(node, 4096); item; item = item->next) {
    if (item->type != RZ_JSON_STRING || !item->str_value)
      fail(l10n::Key::SessionStoreMalformed);
    check_text(item->str_value);
    result.emplace_back(item->str_value);
  }
  return result;
}

SessionAddress decode_address(const RzJson *node) {
  const Object object(node, {"module_sha256", "module_path", "file_address"});
  SessionAddress address{object.text("module_sha256"),
                         object.text("module_path"),
                         object.number("file_address")};
  check_hash(address.module_sha256);
  return address;
}

constexpr std::array analysis_kinds{std::string_view{"rename"},
                                    std::string_view{"set_type"},
                                    std::string_view{"mark_string"}};
constexpr std::array symbol_kinds{
    std::string_view{"none"},   std::string_view{"function"},
    std::string_view{"global"}, std::string_view{"constant"},
    std::string_view{"local"},  std::string_view{"parameter"}};

template <typename Enum, std::size_t N>
Enum decode_enum(const std::string &name,
                 const std::array<std::string_view, N> &names) {
  const auto it = std::find(names.begin(), names.end(), name);
  if (it == names.end())
    fail(l10n::Key::SessionStoreInvalidRecord);
  return static_cast<Enum>(it - names.begin());
}

template <typename Enum, std::size_t N>
const char *encode_enum(Enum value,
                        const std::array<std::string_view, N> &names) {
  const auto index = static_cast<std::size_t>(value);
  if (index >= names.size())
    fail(l10n::Key::SessionStoreInvalidRecord);
  return names[index].data();
}

SessionData decode(std::string contents, const std::string &sha256) {
  JsonPreflight(contents).check();
  std::unique_ptr<RzJson, decltype(&rz_json_free)> json(
      rz_json_parse(contents.data()), rz_json_free);
  const Object root(json.get(),
                    {"version", "sha256", "epoch", "binary_path", "revision",
                     "analysis_revision", "debugger", "analysis", "comments"});
  if (root.number("version") != format_version)
    fail(l10n::Key::SessionStoreVersion);
  SessionData data;
  data.identity = {root.text("sha256"), root.text("epoch")};
  if (data.identity.sha256 != sha256)
    fail(l10n::Key::SessionStoreHashMismatch);
  check_hash(data.identity.epoch, l10n::Key::SessionStoreInvalidEpoch);
  data.binary_path = root.text("binary_path");
  data.revision = root.number("revision");
  data.analysis_revision = root.number("analysis_revision");
  if (data.analysis_revision > data.revision)
    fail(l10n::Key::SessionStoreInvalidRecord);
  const Object debugger(
      root.get("debugger"),
      {"breakpoints", "watches", "symbols", "arguments", "working_directory"});
  for (auto node = array(debugger.get("breakpoints"), 4096); node;
       node = node->next) {
    const Object breakpoint(node, {"serialized", "script_condition",
                                   "module_sha256", "module_path"});
    SessionBreakpoint item{
        breakpoint.text("serialized"), breakpoint.text("script_condition"),
        breakpoint.text("module_sha256"), breakpoint.text("module_path")};
    if (!item.module_sha256.empty())
      check_hash(item.module_sha256);
    if (item.serialized.empty())
      fail(l10n::Key::SessionStoreInvalidRecord);
    data.debugger.breakpoints.push_back(std::move(item));
  }
  data.debugger.watches = strings(debugger.get("watches"));
  data.debugger.arguments = strings(debugger.get("arguments"));
  data.debugger.working_directory = debugger.text("working_directory");
  for (auto node = array(debugger.get("symbols"), 16384); node;
       node = node->next) {
    const Object symbol(node, {"name", "address"});
    data.debugger.symbols.push_back(
        {symbol.text("name"), decode_address(symbol.get("address"))});
  }
  std::set<std::string> module_keys;
  std::size_t edit_count = 0;
  for (auto node = array(root.get("analysis"), 1024); node; node = node->next) {
    const Object module(node, {"sha256", "path", "edits"});
    SessionModuleAnalysis item{module.text("sha256"), module.text("path"), {}};
    check_hash(item.sha256);
    if (!module_keys.insert(item.sha256).second)
      fail(l10n::Key::SessionStoreInvalidRecord);
    for (auto entry = array(module.get("edits")); entry; entry = entry->next) {
      if (++edit_count > max_records)
        fail(l10n::Key::SessionStoreLimit);
      const Object edit(entry, {"kind", "target_kind", "function_file_address",
                                "target_name", "target_file_address",
                                "has_target_file_address", "value"});
      item.edits.push_back(
          {decode_enum<SavedAnalysisKind>(edit.text("kind"), analysis_kinds),
           decode_enum<SavedSymbolKind>(edit.text("target_kind"), symbol_kinds),
           edit.number("function_file_address"), edit.text("target_name"),
           edit.number("target_file_address"),
           edit.boolean("has_target_file_address"), edit.text("value")});
    }
    data.analysis.push_back(std::move(item));
  }
  std::set<std::pair<std::string, std::uint64_t>> comment_keys;
  for (auto node = array(root.get("comments")); node; node = node->next) {
    const Object comment(node, {"address", "text"});
    SessionComment item{decode_address(comment.get("address")),
                        comment.text("text")};
    if (item.text.size() > max_comment)
      fail(l10n::Key::SessionStoreLimit);
    if (item.text.empty() ||
        !comment_keys
             .emplace(item.address.module_sha256, item.address.file_address)
             .second)
      fail(l10n::Key::SessionStoreInvalidRecord);
    data.comments.push_back(std::move(item));
  }
  return data;
}

class JsonWriter {
public:
  JsonWriter() : pj_(pj_new(), pj_free) {
    if (!pj_)
      throw std::bad_alloc();
  }
  void object() {
    charge(2);
    pj_o(pj_.get());
  }
  void list() {
    charge(2);
    pj_a(pj_.get());
  }
  void end() { pj_end(pj_.get()); }
  void key(const char *key) {
    charge(std::strlen(key) + 4);
    pj_k(pj_.get(), key);
  }
  void text(const std::string &value) {
    text_bytes(value.c_str(), value.size());
  }
  void text(const char *value) { text_bytes(value, std::strlen(value)); }
  void text(const char *key, const std::string &value) {
    this->key(key);
    text(value);
  }
  void number(const char *key, std::uint64_t value) {
    this->key(key);
    charge(21);
    pj_n(pj_.get(), value);
  }
  void boolean(const char *key, bool value) {
    this->key(key);
    charge(6);
    pj_b(pj_.get(), value);
  }
  void list(const char *key, std::size_t count, std::size_t limit) {
    if (count > limit)
      fail(l10n::Key::SessionStoreLimit);
    this->key(key);
    list();
  }
  std::string finish() const {
    const auto result = pj_string(pj_.get());
    if (!result)
      throw std::bad_alloc();
    return result;
  }

private:
  void text_bytes(const char *value, std::size_t size) {
    check_text(std::string_view(value, size));
    // Bound PJ's allocation before escaping, without copying strings that are
    // already null-terminated at the public API or enum table boundary.
    charge(size * 6 + 3);
    pj_s(pj_.get(), value);
  }
  void charge(std::size_t bytes) {
    if (bytes > max_document - budget_)
      fail(l10n::Key::SessionStoreLimit);
    budget_ += bytes;
  }
  std::unique_ptr<PJ, decltype(&pj_free)> pj_;
  std::size_t budget_{};
};

void encode_address(JsonWriter &json, const SessionAddress &address) {
  check_hash(address.module_sha256);
  json.object();
  json.text("module_sha256", address.module_sha256);
  json.text("module_path", address.module_path);
  json.number("file_address", address.file_address);
  json.end();
}

std::string encode(const SessionData &data) {
  check_hash(data.identity.sha256);
  check_hash(data.identity.epoch, l10n::Key::SessionStoreInvalidEpoch);
  JsonWriter json;
  json.object();
  json.number("version", format_version);
  json.text("sha256", data.identity.sha256);
  json.text("epoch", data.identity.epoch);
  json.text("binary_path", data.binary_path);
  json.number("revision", data.revision);
  json.number("analysis_revision", data.analysis_revision);
  json.key("debugger");
  json.object();
  json.list("breakpoints", data.debugger.breakpoints.size(), 4096);
  for (const auto &breakpoint : data.debugger.breakpoints) {
    if (breakpoint.serialized.empty())
      fail(l10n::Key::SessionStoreInvalidRecord);
    if (!breakpoint.module_sha256.empty())
      check_hash(breakpoint.module_sha256);
    json.object();
    json.text("serialized", breakpoint.serialized);
    json.text("script_condition", breakpoint.script_condition);
    json.text("module_sha256", breakpoint.module_sha256);
    json.text("module_path", breakpoint.module_path);
    json.end();
  }
  json.end();
  for (const auto &[name, values] :
       {std::pair{"watches", &data.debugger.watches},
        std::pair{"arguments", &data.debugger.arguments}}) {
    json.list(name, values->size(), 4096);
    for (const auto &value : *values)
      json.text(value);
    json.end();
  }
  json.list("symbols", data.debugger.symbols.size(), 16384);
  for (const auto &symbol : data.debugger.symbols) {
    json.object();
    json.text("name", symbol.name);
    json.key("address");
    encode_address(json, symbol.address);
    json.end();
  }
  json.end();
  json.text("working_directory", data.debugger.working_directory);
  json.end();
  json.list("analysis", data.analysis.size(), 1024);
  std::size_t edits = 0;
  for (const auto &module : data.analysis) {
    check_hash(module.sha256);
    if (module.edits.size() > max_records - edits)
      fail(l10n::Key::SessionStoreLimit);
    edits += module.edits.size();
    json.object();
    json.text("sha256", module.sha256);
    json.text("path", module.path);
    json.list("edits", module.edits.size(), max_records);
    for (const auto &edit : module.edits) {
      json.object();
      json.key("kind");
      json.text(encode_enum(edit.kind, analysis_kinds));
      json.key("target_kind");
      json.text(encode_enum(edit.target_kind, symbol_kinds));
      json.number("function_file_address", edit.function_file_address);
      json.text("target_name", edit.target_name);
      json.number("target_file_address", edit.target_file_address);
      json.boolean("has_target_file_address", edit.has_target_file_address);
      json.text("value", edit.value);
      json.end();
    }
    json.end();
    json.end();
  }
  json.end();
  json.list("comments", data.comments.size(), max_records);
  for (const auto &comment : data.comments) {
    if (comment.text.empty())
      fail(l10n::Key::SessionStoreInvalidRecord);
    if (comment.text.size() > max_comment)
      fail(l10n::Key::SessionStoreLimit);
    json.object();
    json.key("address");
    encode_address(json, comment.address);
    json.text("text", comment.text);
    json.end();
  }
  json.end();
  json.end();
  return json.finish();
}

void private_file(int fd, bool allow_backup_links = false) {
  struct stat info{};
  if (::fstat(fd, &info) < 0)
    system_error(l10n::Key::SessionStoreRead);
  if (!S_ISREG(info.st_mode) || info.st_uid != ::geteuid() ||
      (!allow_backup_links && info.st_nlink != 1))
    fail(l10n::Key::SessionStoreUnsafeStorage);
  if (::fchmod(fd, 0600) < 0)
    system_error(l10n::Key::SessionStoreWrite);
}

void sync_file(int fd, l10n::Key operation = l10n::Key::SessionStoreWrite) {
  while (::fsync(fd) < 0) {
    if (errno != EINTR)
      system_error(operation);
  }
}

File open_directory(const std::filesystem::path &directory) {
  std::filesystem::path prefix;
  for (const auto &component : directory) {
    prefix /= component;
    if (::mkdir(prefix.c_str(), 0700) == 0) {
      File parent(::open(prefix.parent_path().c_str(),
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC));
      if (parent.get() < 0)
        system_error(l10n::Key::SessionStoreOpenDirectory);
      sync_file(parent.get(), l10n::Key::SessionStoreOpenDirectory);
    } else if (errno != EEXIST) {
      system_error(l10n::Key::SessionStoreOpenDirectory);
    }
  }
  File result(::open(directory.c_str(),
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (result.get() < 0)
    system_error(l10n::Key::SessionStoreOpenDirectory);
  struct stat info{};
  if (::fstat(result.get(), &info) < 0)
    system_error(l10n::Key::SessionStoreOpenDirectory);
  if (!S_ISDIR(info.st_mode) || info.st_uid != ::geteuid())
    fail(l10n::Key::SessionStoreUnsafeStorage);
  if (::fchmod(result.get(), 0700) < 0)
    system_error(l10n::Key::SessionStoreOpenDirectory);
  return result;
}

File lock_session(int directory, const std::string &sha256) {
  const auto name = sha256 + ".lock";
  File lock(::openat(directory, name.c_str(),
                     O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                     0600));
  if (lock.get() < 0)
    system_error(l10n::Key::SessionStoreLock);
  private_file(lock.get());
  while (::flock(lock.get(), LOCK_EX) < 0) {
    if (errno != EINTR)
      system_error(l10n::Key::SessionStoreLock);
  }
  return lock;
}

std::optional<SessionData> read_disk(int directory, const std::string &sha256) {
  const auto name = sha256 + ".json";
  File file(::openat(directory, name.c_str(),
                     O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (file.get() < 0) {
    if (errno == ENOENT)
      return std::nullopt;
    system_error(l10n::Key::SessionStoreRead);
  }
  // A crash before replacement can leave a private rollback hard link.
  private_file(file.get(), true);
  struct stat info{};
  if (::fstat(file.get(), &info) < 0)
    system_error(l10n::Key::SessionStoreRead);
  if (info.st_size < 0 ||
      static_cast<std::uint64_t>(info.st_size) > max_document)
    fail(l10n::Key::SessionStoreLimit);
  std::string contents;
  contents.reserve(static_cast<std::size_t>(info.st_size));
  std::array<char, 65536> buffer{};
  while (true) {
    const auto count = ::read(file.get(), buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR)
      continue;
    if (count < 0)
      system_error(l10n::Key::SessionStoreRead);
    if (count == 0)
      break;
    if (static_cast<std::size_t>(count) > max_document - contents.size())
      fail(l10n::Key::SessionStoreLimit);
    contents.append(buffer.data(), static_cast<std::size_t>(count));
  }
  return decode(std::move(contents), sha256);
}

void write_disk(int directory, const SessionData &data) {
  const auto contents = encode(data);
  const auto name = data.identity.sha256 + ".json";
  const auto temporary = "." + data.identity.sha256 + "." + new_epoch();
  const auto previous = temporary + ".previous";
  File file(::openat(directory, temporary.c_str(),
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                     0600));
  if (file.get() < 0)
    system_error(l10n::Key::SessionStoreWrite);
  bool backup = false;
  bool committed = false;
  try {
    std::size_t offset = 0;
    while (offset < contents.size()) {
      const auto count = ::write(file.get(), contents.data() + offset,
                                 contents.size() - offset);
      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0)
        system_error(l10n::Key::SessionStoreWrite, count == 0 ? EIO : errno);
      offset += static_cast<std::size_t>(count);
    }
    sync_file(file.get());
    // Keep the old inode until the replacement's directory entry is durable.
    // In particular, a failed parent fsync must not discard the previous state.
    if (::linkat(directory, name.c_str(), directory, previous.c_str(), 0) == 0)
      backup = true;
    else if (errno != ENOENT)
      system_error(l10n::Key::SessionStoreWrite);
    sync_file(directory);
    if (::renameat(directory, temporary.c_str(), directory, name.c_str()) < 0)
      system_error(l10n::Key::SessionStoreWrite);
    committed = true;
    sync_file(directory);
  } catch (const std::exception &error) {
    if (committed) {
      const int restored = backup ? ::renameat(directory, previous.c_str(),
                                               directory, name.c_str())
                                  : ::unlinkat(directory, name.c_str(), 0);
      if (restored < 0) {
        const int restore_error = errno;
        // Keep the backup for recovery if the filesystem also refuses rollback.
        throw std::runtime_error(
            l10n::format(l10n::Key::SessionStoreRollbackError, error.what(),
                         std::strerror(restore_error)));
      }
      backup = false;
      ::fsync(directory);
    }
    ::unlinkat(directory, temporary.c_str(), 0);
    if (backup)
      ::unlinkat(directory, previous.c_str(), 0);
    throw;
  }
  if (backup) {
    // The new document is already durable. A failed cleanup cannot undo that
    // success, and leftover private backup names are never considered sessions.
    ::unlinkat(directory, previous.c_str(), 0);
    ::fsync(directory);
  }
}

SessionStatus data_status(const SessionData &data) {
  SessionStatus status;
  status.identity = data.identity;
  status.revision = data.revision;
  status.analysis_revision = data.analysis_revision;
  status.breakpoint_count = data.debugger.breakpoints.size();
  status.watch_count = data.debugger.watches.size();
  for (const auto &module : data.analysis)
    status.edit_count += module.edits.size();
  status.comment_count = data.comments.size();
  status.writable = true;
  return status;
}

void advance_revision(SessionData &data, bool analysis) {
  if (data.revision == std::numeric_limits<std::uint64_t>::max() ||
      (analysis &&
       data.analysis_revision == std::numeric_limits<std::uint64_t>::max()))
    fail(l10n::Key::SessionStoreRevisionOverflow);
  ++data.revision;
  if (analysis)
    ++data.analysis_revision;
}

bool same_file(const struct stat &before, const struct stat &after) {
  return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
         before.st_size == after.st_size &&
         before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
         before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
         before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
         before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

} // namespace

struct SessionStore::Impl {
  struct Cached {
    std::optional<SessionData> data;
    SessionStatus status;
    // Paired with the debugger subsection only when native records are saved.
    // load must return their old locator so LLDB can relocate them first.
    std::optional<std::string> loaded_binary_path;
  };
  explicit Impl(std::filesystem::path path) : directory(std::move(path)) {}

  void remember(SessionData data) {
    auto status = data_status(data);
    auto &entry = cache[data.identity.sha256];
    entry.data = std::move(data);
    entry.status = std::move(status);
  }
  void error(const std::string &sha256, const std::exception &error,
             bool invalidate = false) {
    auto &entry = cache[sha256];
    if (invalidate) {
      entry.data.reset();
      entry.status = {};
    }
    entry.status.identity.sha256 = sha256;
    entry.status.writable = false;
    entry.status.error = error.what();
  }
  template <typename Mutation>
  SessionStatus mutate(const SessionIdentity &identity, bool analysis,
                       Mutation mutation) {
    std::lock_guard guard(mutex);
    try {
      check_hash(identity.sha256);
      check_hash(identity.epoch, l10n::Key::SessionStoreInvalidEpoch);
      auto dir = open_directory(directory);
      auto lock = lock_session(dir.get(), identity.sha256);
      auto current = read_disk(dir.get(), identity.sha256);
      if (!current || current->identity != identity) {
        if (current)
          remember(std::move(*current));
        else {
          auto &entry = cache[identity.sha256];
          entry.data.reset();
          entry.status = {};
        }
        fail(l10n::Key::SessionStoreStaleEpoch);
      }
      mutation(*current);
      advance_revision(*current, analysis);
      write_disk(dir.get(), *current);
      remember(std::move(*current));
      return cache.at(identity.sha256).status;
    } catch (const std::exception &failure) {
      error(identity.sha256, failure);
      throw;
    }
  }

  std::filesystem::path directory;
  mutable std::mutex mutex;
  std::unordered_map<std::string, Cached> cache;
};

SessionStore::SessionStore(std::filesystem::path directory) {
  if (directory.empty() || !directory.is_absolute() ||
      directory.native().find('\0') != std::string::npos)
    fail(l10n::Key::SessionStoreInvalidDirectory);
  impl_ = std::make_unique<Impl>(std::move(directory));
}

SessionStore::~SessionStore() = default;

std::filesystem::path SessionStore::default_directory() {
  const auto configured = [](const char *value) {
    const std::filesystem::path path(value);
    if (path.empty() || !path.is_absolute())
      fail(l10n::Key::SessionStoreInvalidDirectory);
    return path;
  };
  if (const char *override = std::getenv("MYDBG_SESSION_DIR"))
    return configured(override);
  if (const char *state = std::getenv("XDG_STATE_HOME"))
    return configured(state) / "mydbg" / "sessions";
  if (const char *home = std::getenv("HOME"))
    return configured(home) / ".local" / "state" / "mydbg" / "sessions";
  fail(l10n::Key::SessionStoreInvalidDirectory);
}

std::string SessionStore::hash_file(const std::filesystem::path &path) {
  if (path.native().find('\0') != std::string::npos)
    fail(l10n::Key::SessionStoreHashNotRegular);
  File file(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK));
  if (file.get() < 0)
    system_error(l10n::Key::SessionStoreHashRead);
  struct stat before{};
  if (::fstat(file.get(), &before) < 0)
    system_error(l10n::Key::SessionStoreHashRead);
  if (!S_ISREG(before.st_mode) || before.st_size < 0)
    fail(l10n::Key::SessionStoreHashNotRegular);
  // Use the existing SHA-256 algorithm context directly. RzHash's general
  // registry mutates global OpenSSL provider bookkeeping during construction;
  // this standalone context needs neither that registry nor a shared RzCore.
  const auto &algorithm = rz_hash_plugin_sha256;
  std::unique_ptr<void, void (*)(void *)> context(algorithm.context_new(),
                                                  algorithm.context_free);
  if (!context || !algorithm.init(context.get()))
    fail(l10n::Key::SessionStoreHashFailed);
  std::array<ut8, 128 * 1024> buffer{};
  std::uint64_t total = 0;
  while (true) {
    const auto count = ::read(file.get(), buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR)
      continue;
    if (count < 0)
      system_error(l10n::Key::SessionStoreHashRead);
    if (count == 0)
      break;
    total += static_cast<std::uint64_t>(count);
    if (total > static_cast<std::uint64_t>(before.st_size))
      fail(l10n::Key::SessionStoreHashChanged);
    if (!algorithm.update(context.get(), buffer.data(),
                          static_cast<std::uint64_t>(count)))
      fail(l10n::Key::SessionStoreHashFailed);
  }
  struct stat after{}, named{};
  if (::fstat(file.get(), &after) < 0)
    system_error(l10n::Key::SessionStoreHashRead);
  if (::stat(path.c_str(), &named) < 0 || !same_file(before, after) ||
      !same_file(before, named) ||
      total != static_cast<std::uint64_t>(before.st_size))
    fail(l10n::Key::SessionStoreHashChanged);
  std::array<ut8, 32> digest{};
  if (algorithm.digest_size(context.get()) != digest.size() ||
      !algorithm.final(context.get(), digest.data()))
    fail(l10n::Key::SessionStoreHashFailed);
  return hex_bytes(digest.data(), digest.size());
}

SessionData SessionStore::load(const std::string &sha256,
                               const std::string &binary_path) {
  std::lock_guard guard(impl_->mutex);
  try {
    check_hash(sha256);
    check_text(binary_path);
    impl_->cache[sha256].loaded_binary_path = binary_path;
    auto dir = open_directory(impl_->directory);
    auto lock = lock_session(dir.get(), sha256);
    auto current = read_disk(dir.get(), sha256);
    if (!current) {
      current.emplace();
      current->identity = {sha256, new_epoch()};
      current->binary_path = binary_path;
      write_disk(dir.get(), *current);
    }
    auto result = *current;
    impl_->remember(std::move(*current));
    return result;
  } catch (const std::exception &failure) {
    impl_->error(sha256, failure, true);
    throw;
  }
}

SessionData SessionStore::read(const SessionIdentity &identity) const {
  std::lock_guard guard(impl_->mutex);
  const auto it = impl_->cache.find(identity.sha256);
  if (it == impl_->cache.end() || !it->second.data)
    fail(l10n::Key::SessionStoreNotLoaded);
  if (it->second.data->identity != identity)
    fail(l10n::Key::SessionStoreStaleEpoch);
  return *it->second.data;
}

SessionStatus SessionStore::status(const std::string &sha256) const {
  std::lock_guard guard(impl_->mutex);
  const auto it = impl_->cache.find(sha256);
  if (it != impl_->cache.end())
    return it->second.status;
  SessionStatus status;
  status.identity.sha256 = sha256;
  return status;
}

SessionStatus SessionStore::save_debugger(const SessionIdentity &identity,
                                          const SessionDebuggerState &state) {
  return impl_->mutate(identity, false, [&](SessionData &data) {
    data.debugger = state;
    const auto cached = impl_->cache.find(identity.sha256);
    if (cached != impl_->cache.end() && cached->second.loaded_binary_path)
      data.binary_path = *cached->second.loaded_binary_path;
  });
}

SessionStatus SessionStore::append_analysis(const SessionIdentity &identity,
                                            const std::string &module_sha256,
                                            const std::string &module_path,
                                            const SessionAnalysisEdit &edit) {
  return impl_->mutate(identity, true, [&](SessionData &data) {
    check_hash(module_sha256);
    auto module = std::find_if(data.analysis.begin(), data.analysis.end(),
                               [&](const SessionModuleAnalysis &item) {
                                 return item.sha256 == module_sha256;
                               });
    if (module == data.analysis.end()) {
      data.analysis.push_back({module_sha256, module_path, {edit}});
    } else {
      module->path = module_path;
      module->edits.push_back(edit);
    }
  });
}

SessionStatus SessionStore::set_comment(const SessionIdentity &identity,
                                        const SessionAddress &address,
                                        const std::string &text) {
  return impl_->mutate(identity, true, [&](SessionData &data) {
    check_hash(address.module_sha256);
    check_text(address.module_path);
    if (text.size() > max_comment)
      fail(l10n::Key::SessionStoreLimit);
    check_text(text);
    auto comment = std::find_if(
        data.comments.begin(), data.comments.end(),
        [&](const SessionComment &item) {
          return item.address.module_sha256 == address.module_sha256 &&
                 item.address.file_address == address.file_address;
        });
    if (text.empty()) {
      if (comment != data.comments.end())
        data.comments.erase(comment);
    } else if (comment == data.comments.end()) {
      data.comments.push_back({address, text});
    } else {
      *comment = {address, text};
    }
  });
}

SessionData SessionStore::clear(const std::string &sha256) {
  std::lock_guard guard(impl_->mutex);
  try {
    check_hash(sha256);
    auto dir = open_directory(impl_->directory);
    auto lock = lock_session(dir.get(), sha256);
    SessionData cleared;
    // Corruption, unknown versions and read errors do not veto explicit clear.
    // Epochs, not monotonic revisions across epochs, are the stale-write fence.
    try {
      if (auto previous = read_disk(dir.get(), sha256)) {
        cleared.binary_path = std::move(previous->binary_path);
        if (previous->revision < std::numeric_limits<std::uint64_t>::max())
          cleared.revision = previous->revision;
        if (previous->analysis_revision <
            std::numeric_limits<std::uint64_t>::max())
          cleared.analysis_revision = previous->analysis_revision;
      }
    } catch (const std::runtime_error &) {
      const auto cached = impl_->cache.find(sha256);
      if (cached != impl_->cache.end()) {
        if (cached->second.loaded_binary_path)
          cleared.binary_path = *cached->second.loaded_binary_path;
        else if (cached->second.data)
          cleared.binary_path = cached->second.data->binary_path;
      }
    }
    // Reset both counters together if the previous revision was exhausted.
    if (cleared.analysis_revision > cleared.revision)
      cleared.analysis_revision = 0;
    cleared.identity = {sha256, new_epoch()};
    advance_revision(cleared, true);
    write_disk(dir.get(), cleared);
    auto result = cleared;
    impl_->remember(std::move(cleared));
    return result;
  } catch (const std::exception &failure) {
    impl_->error(sha256, failure);
    throw;
  }
}

} // namespace debugger
