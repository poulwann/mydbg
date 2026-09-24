#include "backend/lldb/LldbSessions.h"
#include "backend/lldb/LldbEngineInternal.h"
#include "localization/Localization.h"
#include <fcntl.h>
#include <rz_util/rz_json.h>
#include <unistd.h>

namespace debugger::lldb_detail {
namespace {

struct JsonDocument {
  std::string storage;
  std::unique_ptr<RzJson, decltype(&rz_json_free)> root{nullptr, rz_json_free};
  explicit JsonDocument(std::string text) : storage(std::move(text)) {
    // Store bounds the outer document, not the encoded native JSON string.
    if (storage.size() > 1024 * 1024)
      return;
    unsigned depth = 0;
    bool quoted = false, escaped = false;
    for (char c : storage) {
      if (quoted) {
        if (escaped)
          escaped = false;
        else if (c == '\\')
          escaped = true;
        else if (c == '"')
          quoted = false;
      } else if (c == '"')
        quoted = true;
      else if (c == '{' || c == '[') {
        if (++depth > 32)
          return;
      } else if (c == '}' || c == ']') {
        if (!depth--)
          return;
      }
    }
    if (depth || quoted)
      return;
    root.reset(rz_json_parse(storage.data()));
  }
};

const RzJson *member(const RzJson *node, const char *key) {
  return node && node->type == RZ_JSON_OBJECT ? rz_json_get(node, key)
                                              : nullptr;
}
std::string_view string_value(const RzJson *node) {
  return node && node->type == RZ_JSON_STRING ? node->str_value : "";
}
const RzJson *resolver(const RzJson *root) {
  return member(member(root, "Breakpoint"), "BKPTResolver");
}
bool supported(const RzJson *root) {
  const auto type = string_value(member(resolver(root), "Type"));
  return type == "Address" || type == "FileAndLine" || type == "SymbolName" ||
         type == "SourceRegex" || type == "Exception";
}

struct Rewrite {
  std::optional<SessionAddress> address{};
  std::string_view old_path{};
  std::string_view new_path{};
  bool stripped{};
  bool strip_unsafe{true};
  std::optional<std::uint32_t> ignore_count{};
};
void emit_json(PJ *out, const RzJson *node, Rewrite &rewrite,
               std::string_view parent = {}) {
  if (node->type == RZ_JSON_OBJECT || node->type == RZ_JSON_ARRAY) {
    const bool object = node->type == RZ_JSON_OBJECT;
    object ? pj_o(out) : pj_a(out);
    bool has_module = false;
    for (const RzJson *child = node->children.first; child;
         child = child->next) {
      const std::string_view key = child->key ? child->key : "";
      if (rewrite.strip_unsafe &&
          (key == "BKPTCMDData" || key == "ScriptSource" ||
           key == "UserSource" || key == "ScriptArgs" ||
           ((parent == "ThreadSpec" || parent == "BKPTThreadSpec") &&
            (key == "ID" || key == "Index")))) {
        rewrite.stripped = true;
        continue;
      }
      if (object)
        pj_k(out, child->key);
      if (rewrite.ignore_count && key == "IgnoreCount") {
        pj_n(out, *rewrite.ignore_count);
      } else if (rewrite.address && key == "AddressOffset") {
        pj_n(out, rewrite.address->file_address);
      } else if (rewrite.address && key == "ModuleName") {
        pj_s(out, rewrite.address->module_path.c_str());
        has_module = true;
      } else {
        emit_json(out, child, rewrite, object ? key : parent);
      }
    }
    if (object && rewrite.address && member(node, "AddressOffset") &&
        !has_module)
      pj_ks(out, "ModuleName", rewrite.address->module_path.c_str());
    pj_end(out);
  } else if (node->type == RZ_JSON_INTEGER && parent == "NameMask") {
    constexpr auto selector =
        static_cast<std::uint64_t>(lldb::eFunctionNameTypeSelector);
    constexpr auto other_kinds =
        static_cast<std::uint64_t>(lldb::eFunctionNameTypeFull) |
        static_cast<std::uint64_t>(lldb::eFunctionNameTypeBase) |
        static_cast<std::uint64_t>(lldb::eFunctionNameTypeMethod);
    const auto mask = node->num.u_value;
    // LLDB serializes Auto as a cross-language union, but reads an explicit
    // union through only its first matching language (often Objective-C).
    // Such a union comes from Auto, not an explicit single-language lookup.
    const bool expanded_auto = (mask & selector) && (mask & other_kinds) &&
                               !(mask & ~(selector | other_kinds));
    pj_n(out, expanded_auto
                  ? static_cast<std::uint64_t>(lldb::eFunctionNameTypeAuto)
                  : mask);
  } else if (node->type == RZ_JSON_STRING && !rewrite.old_path.empty() &&
             string_value(node) == rewrite.old_path) {
    const std::string replacement{rewrite.new_path};
    pj_s(out, replacement.c_str());
  } else {
    rz_json_to_pj(node, out, false);
  }
}
std::string sanitized(const RzJson *root, Rewrite &rewrite) {
  std::unique_ptr<PJ, decltype(&pj_free)> out{pj_new(), pj_free};
  if (!out)
    throw std::bad_alloc{};
  emit_json(out.get(), root, rewrite);
  return pj_string(out.get());
}

void emit_options(PJ *out, lldb::SBBreakpoint bp, std::uint32_t ignore_count) {
  pj_ko(out, "BKPTOptions");
  pj_kb(out, "EnabledState", bp.IsEnabled());
  pj_kb(out, "OneShotState", false);
  pj_kn(out, "IgnoreCount", ignore_count);
  pj_kb(out, "AutoContinue", bp.GetAutoContinue());
  pj_ks(out, "ConditionText", safe_string(bp.GetCondition()).c_str());
  pj_ko(out, "ThreadSpec");
  if (const char *name = bp.GetThreadName())
    pj_ks(out, "Name", name);
  if (const char *queue = bp.GetQueueName())
    pj_ks(out, "QueueName", queue);
  pj_end(out);
  pj_end(out);
}

void apply_options(lldb::SBBreakpoint &bp, const RzJson *root) {
  const auto *contents = member(root, "Breakpoint");
  const auto *options = member(contents, "BKPTOptions");
  if (const auto *value = member(options, "EnabledState");
      value && value->type == RZ_JSON_BOOLEAN)
    bp.SetEnabled(value->num.u_value != 0);
  if (const auto *value = member(options, "IgnoreCount");
      value && value->type == RZ_JSON_INTEGER &&
      value->num.u_value <= std::numeric_limits<std::uint32_t>::max())
    bp.SetIgnoreCount(static_cast<std::uint32_t>(value->num.u_value));
  if (const auto *value = member(options, "AutoContinue");
      value && value->type == RZ_JSON_BOOLEAN)
    bp.SetAutoContinue(value->num.u_value != 0);
  const std::string condition{string_value(member(options, "ConditionText"))};
  bp.SetCondition(condition.c_str());
  const auto *thread = member(options, "ThreadSpec");
  const std::string name{string_value(member(thread, "Name"))};
  const std::string queue{string_value(member(thread, "QueueName"))};
  bp.SetThreadName(name.c_str());
  bp.SetQueueName(queue.c_str());
  if (const auto *hardware = member(contents, "Hardware");
      hardware && hardware->type == RZ_JSON_BOOLEAN && hardware->num.u_value) {
    const auto error = bp.SetIsHardware(true);
    if (error.Fail())
      throw std::runtime_error(error_text(error));
  }
  if (const auto *names = member(contents, "Names");
      names && names->type == RZ_JSON_ARRAY) {
    for (const auto *entry = names->children.first; entry;
         entry = entry->next) {
      if (entry->type == RZ_JSON_STRING) {
        const auto error = bp.AddNameWithErrorHandling(entry->str_value);
        if (error.Fail())
          throw std::runtime_error(error_text(error));
      }
    }
  }
}

class ImportFile final {
public:
  explicit ImportFile(const std::string &document) {
    std::string pattern =
        (std::filesystem::temp_directory_path() / "mydbg-breakpoints-XXXXXX")
            .string();
    fd_ = mkstemp(pattern.data());
    if (fd_ < 0)
      throw std::system_error(errno, std::generic_category());
    path_ = std::move(pattern);
    std::size_t written = 0;
    while (written < document.size()) {
      const auto n =
          ::write(fd_, document.data() + written, document.size() - written);
      if (n < 0 && errno == EINTR)
        continue;
      if (n <= 0) {
        const int error = n < 0 ? errno : EIO;
        ::close(fd_);
        fd_ = -1;
        ::unlink(path_.c_str());
        throw std::system_error(error, std::generic_category());
      }
      written += static_cast<std::size_t>(n);
    }
  }
  ~ImportFile() {
    if (fd_ >= 0)
      ::close(fd_);
    ::unlink(path_.c_str());
  }
  const char *path() const { return path_.c_str(); }

private:
  int fd_{-1};
  std::string path_;
};

bool same(const SessionDebuggerState &a, const SessionDebuggerState &b) {
  if (a.arguments != b.arguments ||
      a.working_directory != b.working_directory || a.watches != b.watches ||
      a.breakpoints.size() != b.breakpoints.size() ||
      a.symbols.size() != b.symbols.size())
    return false;
  for (std::size_t i = 0; i < a.breakpoints.size(); ++i) {
    const auto &x = a.breakpoints[i];
    const auto &y = b.breakpoints[i];
    if (x.serialized != y.serialized ||
        x.script_condition != y.script_condition ||
        x.module_sha256 != y.module_sha256 || x.module_path != y.module_path)
      return false;
  }
  for (std::size_t i = 0; i < a.symbols.size(); ++i) {
    const auto &x = a.symbols[i];
    const auto &y = b.symbols[i];
    if (x.name != y.name ||
        x.address.module_sha256 != y.address.module_sha256 ||
        x.address.module_path != y.address.module_path ||
        x.address.file_address != y.address.file_address)
      return false;
  }
  return true;
}

} // namespace

LldbSessions::LldbSessions(std::shared_ptr<SessionStore> store)
    : store_(std::move(store)) {}

void LldbSessions::reset(SessionSnapshot &state) {
  state.session = {};
  state.session_error.clear();
  state.session_analysis_revision = 0;
  module_hashes_.clear();
  pending_.clear();
  restored_.clear();
  transient_.clear();
  exceptions_.clear();
  ignore_counts_.clear();
  restored_ignore_events_.clear();
  annotated_graph_.reset();
  last_saved_.reset();
  original_path_.clear();
  current_path_.clear();
  notice_.clear();
  io_error_.clear();
  comments_.clear();
  comments_revision_ = ~std::uint64_t{0};
}

void LldbSessions::notice(SessionSnapshot &state, const std::string &message) {
  if (notice_.find(message) == std::string::npos) {
    if (!notice_.empty())
      notice_ += '\n';
    notice_ += message;
  }
  state.session_error = notice_;
  if (!io_error_.empty())
    state.session_error += '\n' + io_error_;
}

std::string LldbSessions::module_hash(lldb::SBModule module) {
  if (!module.IsValid())
    return {};
  for (const auto &[cached, hash] : module_hashes_)
    if (cached == module)
      return hash;
  const std::string path = module_path(module);
  if (path.empty())
    return {};
  const std::string hash = SessionStore::hash_file(path);
  module_hashes_.emplace_back(module, hash);
  return hash;
}

std::optional<SessionAddress> LldbSessions::address(lldb::SBAddress value) {
  if (!store_ || !value.IsValid() || !value.GetSection().IsValid() ||
      value.GetFileAddress() == LLDB_INVALID_ADDRESS)
    return std::nullopt;
  lldb::SBModule module = value.GetModule();
  const std::string hash = module_hash(module);
  if (hash.empty())
    return std::nullopt;
  return SessionAddress{hash, module_path(module), value.GetFileAddress()};
}

lldb::SBModule LldbSessions::matching_module(lldb::SBTarget &target,
                                             const std::string &hash) {
  for (std::uint32_t i = 0; i < target.GetNumModules(); ++i) {
    auto module = target.GetModuleAtIndex(i);
    try {
      if (module_hash(module) == hash)
        return module;
    } catch (const std::exception &) { /* Unavailable images stay unresolved. */
    }
  }
  return {};
}

lldb::SBAddress LldbSessions::resolve(lldb::SBTarget &target,
                                      const SessionAddress &saved) {
  auto module = matching_module(target, saved.module_sha256);
  return module.IsValid() ? module.ResolveFileAddress(saved.file_address)
                          : lldb::SBAddress{};
}

std::optional<SessionDebuggerState> LldbSessions::open(lldb::SBTarget &target,
                                                       const std::string &path,
                                                       SessionSnapshot &state) {
  if (!store_ || path.empty())
    return std::nullopt;
  try {
    current_path_ = std::filesystem::canonical(path).string();
    state.session.sha256 = SessionStore::hash_file(current_path_);
    auto data = store_->load(state.session.sha256, current_path_);
    state.session = data.identity;
    original_path_ = data.binary_path;
    // The root was just hashed; don't read it again while annotating/restoring.
    for (std::uint32_t i = 0; i < target.GetNumModules(); ++i) {
      auto module = target.GetModuleAtIndex(i);
      std::error_code error;
      if (std::filesystem::equivalent(module_path(module), path, error) &&
          !error)
        module_hashes_.emplace_back(module, state.session.sha256);
    }
    for (auto &[breakpoint, intent] : exception_cache_) {
      if (breakpoint.IsValid() && breakpoint.GetTarget() == target)
        exceptions_.insert_or_assign(
            static_cast<std::uint32_t>(breakpoint.GetID()), intent);
    }
    pending_ = data.debugger.breakpoints;
    last_saved_ = data.debugger;
    comments_ = std::move(data.comments);
    comments_revision_ = data.analysis_revision;
    return std::move(data.debugger);
  } catch (const std::exception &error) {
    io_error_ = error.what();
    state.session_error = io_error_;
    return std::nullopt;
  }
}

void LldbSessions::transient(lldb::SBBreakpoint breakpoint) {
  if (breakpoint.IsValid())
    transient_.push_back(breakpoint);
}

void LldbSessions::remove_transients(lldb::SBTarget &target) {
  for (auto &breakpoint : transient_) {
    if (breakpoint.IsValid() && breakpoint.GetTarget() == target)
      target.BreakpointDelete(breakpoint.GetID());
  }
  transient_.clear();
}
bool LldbSessions::is_transient(lldb::SBBreakpoint breakpoint) const {
  return breakpoint.IsInternal() || breakpoint.IsOneShot() ||
         std::any_of(transient_.begin(), transient_.end(),
                     [&](const auto &saved) { return breakpoint == saved; });
}

void LldbSessions::remember_exception_command(lldb::SBTarget &target,
                                              std::string_view command,
                                              std::uint32_t previous_id) {
  const auto tokens = split_arguments(command);
  if (tokens.size() < 4 || tokens[0] != "breakpoint" || tokens[1] != "set")
    return;
  ExceptionIntent intent;
  for (std::size_t i = 2; i < tokens.size(); ++i) {
    std::string_view option = tokens[i], value;
    const auto equal = option.find('=');
    if (equal != std::string_view::npos) {
      value = option.substr(equal + 1);
      option = option.substr(0, equal);
    } else if (option == "-E" || option == "--language-exception" ||
               option == "-h" || option == "--on-catch" || option == "-w" ||
               option == "--on-throw") {
      if (++i == tokens.size())
        return;
      value = tokens[i];
    } else if (option.starts_with("-E") && option.size() > 2) {
      value = option.substr(2);
      option = "-E";
    }
    if (option == "-E" || option == "--language-exception")
      intent.language = lldb::SBLanguageRuntime::GetLanguageTypeFromString(
          std::string{value}.c_str());
    else if (option == "-h" || option == "--on-catch")
      intent.catch_exception = lowercase(value) == "true" || value == "1" ||
                               lowercase(value) == "yes" ||
                               lowercase(value) == "on";
    else if (option == "-w" || option == "--on-throw")
      intent.throw_exception = lowercase(value) == "true" || value == "1" ||
                               lowercase(value) == "yes" ||
                               lowercase(value) == "on";
  }
  if (intent.language == lldb::eLanguageTypeUnknown)
    return;
  for (std::uint32_t i = 0; i < target.GetNumBreakpoints(); ++i) {
    auto bp = target.GetBreakpointAtIndex(i);
    const auto id = static_cast<std::uint32_t>(bp.GetID());
    if (id > previous_id) {
      exceptions_.insert_or_assign(id, intent);
      exception_cache_.emplace_back(bp, intent);
    }
  }
}

std::vector<std::pair<std::uint32_t, std::string>>
LldbSessions::restore(lldb::SBTarget &target, SessionSnapshot &state) {
  std::vector<std::pair<std::uint32_t, std::string>> result;
  if (!store_ || state.session.epoch.empty())
    return result;
  auto pending = std::move(pending_);
  pending_.clear();
  for (auto &saved : pending) {
    try {
      JsonDocument document{saved.serialized};
      if (!document.root || !supported(document.root.get()))
        throw std::runtime_error(l10n::text(l10n::Key::LldbSessionUnsupported));
      if (const auto *one_shot =
              member(member(document.root.get(), "Breakpoint"), "BKPTOptions");
          one_shot && member(one_shot, "OneShotState") &&
          member(one_shot, "OneShotState")->type == RZ_JSON_BOOLEAN &&
          member(one_shot, "OneShotState")->num.u_value)
        throw std::runtime_error(
            l10n::text(l10n::Key::LldbSessionUnsafeSkipped));
      if (string_value(member(resolver(document.root.get()), "Type")) ==
          "Exception") {
        const auto *options = member(resolver(document.root.get()), "Options");
        const std::string language{string_value(member(options, "Language"))};
        const auto *catch_value = member(options, "Catch");
        const auto *throw_value = member(options, "Throw");
        ExceptionIntent intent{
            lldb::SBLanguageRuntime::GetLanguageTypeFromString(
                language.c_str()),
            catch_value && catch_value->type == RZ_JSON_BOOLEAN &&
                catch_value->num.u_value != 0,
            throw_value && throw_value->type == RZ_JSON_BOOLEAN &&
                throw_value->num.u_value != 0};
        if (intent.language == lldb::eLanguageTypeUnknown || !catch_value ||
            !throw_value || catch_value->type != RZ_JSON_BOOLEAN ||
            throw_value->type != RZ_JSON_BOOLEAN)
          throw std::runtime_error(
              l10n::text(l10n::Key::LldbSessionUnsupported));
        if (!saved.script_condition.empty() &&
            !conditions::compile(saved.script_condition))
          throw std::runtime_error(
              l10n::text(l10n::Key::LldbSessionConditionInvalid));
        lldb::SBBreakpoint bp;
        for (const auto &[candidate_id, candidate] : exceptions_) {
          if (restored_.contains(candidate_id) ||
              candidate.language != intent.language ||
              candidate.catch_exception != intent.catch_exception ||
              candidate.throw_exception != intent.throw_exception)
            continue;
          bp = target.FindBreakpointByID(candidate_id);
          if (bp.IsValid())
            break;
        }
        if (!bp.IsValid()) {
          bp = target.BreakpointCreateForException(
              intent.language, intent.catch_exception, intent.throw_exception);
          if (bp.IsValid())
            exception_cache_.emplace_back(bp, intent);
        }
        if (!bp.IsValid())
          throw std::runtime_error(
              l10n::text(l10n::Key::LldbSessionUnresolved));
        const auto previous_ignore = bp.GetIgnoreCount();
        try {
          apply_options(bp, document.root.get());
        } catch (...) {
          target.BreakpointDelete(bp.GetID());
          throw;
        }
        const auto id = static_cast<std::uint32_t>(bp.GetID());
        ignore_counts_[id] = bp.GetIgnoreCount();
        if (bp.GetIgnoreCount() != previous_ignore)
          restored_ignore_events_.insert(id);
        exceptions_.insert_or_assign(id, intent);
        restored_.insert_or_assign(id, saved);
        result.emplace_back(id, saved.script_condition);
        continue;
      }
      Rewrite rewrite{.old_path = original_path_, .new_path = current_path_};
      if (string_value(member(resolver(document.root.get()), "Type")) ==
          "Address") {
        const auto *offset = member(
            member(resolver(document.root.get()), "Options"), "AddressOffset");
        auto module = matching_module(target, saved.module_sha256);
        if (saved.module_sha256.empty() || !module.IsValid() || !offset ||
            offset->type != RZ_JSON_INTEGER ||
            !module.ResolveFileAddress(offset->num.u_value)
                 .GetSection()
                 .IsValid()) {
          pending_.push_back(std::move(saved));
          notice(state, l10n::text(l10n::Key::LldbSessionUnresolved));
          continue;
        }
        rewrite.address = SessionAddress{
            saved.module_sha256, module_path(module), offset->num.u_value};
      }
      // Compile before creating any breakpoint; failed sources remain saved.
      if (!saved.script_condition.empty() &&
          !conditions::compile(saved.script_condition))
        throw std::runtime_error(
            l10n::text(l10n::Key::LldbSessionConditionInvalid));
      const std::string normalized = sanitized(document.root.get(), rewrite);
      // A selected target can already own these records. Reuse equivalent
      // native breakpoints instead of appending another copy on target select.
      std::uint32_t existing_id = 0;
      const auto *saved_ignore =
          member(member(document.root.get(), "Breakpoint"), "BKPTOptions");
      saved_ignore = member(saved_ignore, "IgnoreCount");
      const auto ignore_count =
          saved_ignore && saved_ignore->type == RZ_JSON_INTEGER &&
                  saved_ignore->num.u_value <=
                      std::numeric_limits<std::uint32_t>::max()
              ? std::optional<std::uint32_t>{static_cast<std::uint32_t>(
                    saved_ignore->num.u_value)}
              : std::nullopt;
      for (std::uint32_t i = 0; i < target.GetNumBreakpoints(); ++i) {
        auto candidate = target.GetBreakpointAtIndex(i);
        const auto id = static_cast<std::uint32_t>(candidate.GetID());
        if (is_transient(candidate) || restored_.contains(id))
          continue;
        auto native = candidate.SerializeToStructuredData();
        lldb::SBStream stream;
        if (!native.IsValid() || native.GetAsJSON(stream).Fail())
          continue;
        JsonDocument existing{safe_string(stream.GetData())};
        if (!existing.root)
          continue;
        Rewrite normalize{.ignore_count = ignore_count};
        if (string_value(member(resolver(existing.root.get()), "Type")) ==
            "Address") {
          if (!candidate.GetNumLocations())
            continue;
          normalize.address =
              address(candidate.GetLocationAtIndex(0).GetAddress());
          if (!normalize.address)
            continue;
          const auto *offset = member(
              member(resolver(existing.root.get()), "Options"), "Offset");
          if (offset && offset->type == RZ_JSON_INTEGER)
            normalize.address->file_address -= offset->num.u_value;
        }
        if (sanitized(existing.root.get(), normalize) == normalized) {
          existing_id = id;
          break;
        }
      }
      if (existing_id) {
        auto existing = target.FindBreakpointByID(existing_id);
        if (ignore_count && existing.GetIgnoreCount() != *ignore_count) {
          existing.SetIgnoreCount(*ignore_count);
          restored_ignore_events_.insert(existing_id);
        }
        ignore_counts_[existing_id] = existing.GetIgnoreCount();
        restored_.insert_or_assign(existing_id, saved);
        result.emplace_back(existing_id, saved.script_condition);
        continue;
      }
      ImportFile file{'[' + normalized + ']'};
      lldb::SBFileSpec spec{file.path()};
      lldb::SBBreakpointList imported{target};
      const auto error = target.BreakpointsCreateFromFile(spec, imported);
      if (error.Fail() || imported.GetSize() != 1) {
        for (std::size_t i = 0; i < imported.GetSize(); ++i)
          target.BreakpointDelete(imported.GetBreakpointAtIndex(i).GetID());
        throw std::runtime_error(
            error.Fail() ? error_text(error)
                         : l10n::text(l10n::Key::LldbSessionUnresolved));
      }
      const auto id =
          static_cast<std::uint32_t>(imported.GetBreakpointAtIndex(0).GetID());
      ignore_counts_[id] = imported.GetBreakpointAtIndex(0).GetIgnoreCount();
      restored_.insert_or_assign(id, saved);
      result.emplace_back(id, saved.script_condition);
      if (rewrite.stripped)
        notice(state, l10n::text(l10n::Key::LldbSessionUnsafeSkipped));
    } catch (const std::exception &error) {
      pending_.push_back(std::move(saved));
      notice(state, std::string{l10n::text(l10n::Key::LldbSessionUnresolved)} +
                        " " + error.what());
    }
  }
  return result;
}

void LldbSessions::save(
    lldb::SBTarget &target, SessionDebuggerState authored,
    const std::function<std::string(std::uint32_t)> &condition,
    SessionSnapshot &state) {
  if (!store_ || state.session.epoch.empty() || !target.IsValid())
    return;
  authored.breakpoints = pending_;
  try {
    // The store updates the root locator with this subsection. Carry unresolved
    // records forward in the same locator coordinate system as live records.
    if (!original_path_.empty() && original_path_ != current_path_) {
      for (auto &saved : authored.breakpoints) {
        JsonDocument document{saved.serialized};
        if (!document.root)
          continue;
        Rewrite rewrite{.old_path = original_path_,
                        .new_path = current_path_,
                        .strip_unsafe = false};
        saved.serialized = sanitized(document.root.get(), rewrite);
        if (saved.module_path == original_path_)
          saved.module_path = current_path_;
      }
    }
    for (std::uint32_t i = 0; i < target.GetNumBreakpoints(); ++i) {
      auto bp = target.GetBreakpointAtIndex(i);
      if (is_transient(bp)) {
        if (!bp.IsInternal() &&
            std::none_of(
                transient_.begin(), transient_.end(),
                [&](const auto &generated) { return bp == generated; }))
          notice(state, l10n::text(l10n::Key::LldbSessionUnsafeSkipped));
        continue;
      }
      const auto id = static_cast<std::uint32_t>(bp.GetID());
      const auto configured_ignore =
          ignore_counts_.try_emplace(id, bp.GetIgnoreCount()).first->second;
      try {
        if (const auto exception = exceptions_.find(id);
            exception != exceptions_.end()) {
          std::unique_ptr<PJ, decltype(&pj_free)> out{pj_new(), pj_free};
          if (!out)
            throw std::bad_alloc{};
          pj_o(out.get());
          pj_ko(out.get(), "Breakpoint");
          pj_kb(out.get(), "Hardware", bp.IsHardware());
          pj_ko(out.get(), "BKPTResolver");
          pj_ks(out.get(), "Type", "Exception");
          pj_ko(out.get(), "Options");
          pj_ks(out.get(), "Language",
                lldb::SBLanguageRuntime::GetNameForLanguageType(
                    exception->second.language));
          pj_kb(out.get(), "Catch", exception->second.catch_exception);
          pj_kb(out.get(), "Throw", exception->second.throw_exception);
          pj_end(out.get());
          pj_end(out.get());
          emit_options(out.get(), bp, configured_ignore);
          lldb::SBStringList names;
          bp.GetNames(names);
          pj_ka(out.get(), "Names");
          for (std::uint32_t j = 0; j < names.GetSize(); ++j)
            pj_s(out.get(), names.GetStringAtIndex(j));
          pj_end(out.get());
          pj_end(out.get());
          pj_end(out.get());
          authored.breakpoints.push_back(
              SessionBreakpoint{.serialized = pj_string(out.get()),
                                .script_condition = condition(id),
                                .module_sha256 = {},
                                .module_path = {}});
          lldb::SBStringList commands;
          if (bp.GetCommandLineCommands(commands) ||
              bp.GetThreadID() != LLDB_INVALID_THREAD_ID ||
              (bp.GetThreadIndex() != 0 &&
               bp.GetThreadIndex() !=
                   std::numeric_limits<std::uint32_t>::max()))
            notice(state, l10n::text(l10n::Key::LldbSessionUnsafeSkipped));
          continue;
        }
        auto native = bp.SerializeToStructuredData();
        lldb::SBStream stream;
        if (!native.IsValid() || native.GetAsJSON(stream).Fail()) {
          notice(state, l10n::text(l10n::Key::LldbSessionUnsupported));
          if (auto previous = restored_.find(id); previous != restored_.end())
            authored.breakpoints.push_back(previous->second);
          continue;
        }
        JsonDocument document{safe_string(stream.GetData())};
        if (!document.root || !supported(document.root.get())) {
          notice(state, l10n::text(l10n::Key::LldbSessionUnsupported));
          continue;
        }
        Rewrite rewrite{.ignore_count = configured_ignore};
        SessionBreakpoint saved;
        if (string_value(member(resolver(document.root.get()), "Type")) ==
            "Address") {
          if (bp.GetNumLocations())
            rewrite.address = address(bp.GetLocationAtIndex(0).GetAddress());
          if (rewrite.address) {
            const auto *offset = member(
                member(resolver(document.root.get()), "Options"), "Offset");
            if (offset && offset->type == RZ_JSON_INTEGER)
              rewrite.address->file_address -= offset->num.u_value;
          }
          if (!rewrite.address) {
            // Never mistake LLDB's raw AddressOffset for a module's file VA.
            if (auto previous = restored_.find(id);
                previous != restored_.end()) {
              saved = previous->second;
              JsonDocument old{saved.serialized};
              const auto *offset = member(
                  member(resolver(old.root.get()), "Options"), "AddressOffset");
              if (offset && offset->type == RZ_JSON_INTEGER)
                rewrite.address =
                    SessionAddress{saved.module_sha256, saved.module_path,
                                   offset->num.u_value};
            }
          }
          if (!rewrite.address) {
            notice(state, l10n::text(l10n::Key::LldbSessionUnsafeSkipped));
            continue;
          }
          saved.module_sha256 = rewrite.address->module_sha256;
          saved.module_path = rewrite.address->module_path;
        }
        saved.serialized = sanitized(document.root.get(), rewrite);
        saved.script_condition = condition(id);
        if (rewrite.stripped)
          notice(state, l10n::text(l10n::Key::LldbSessionUnsafeSkipped));
        // LLDB's format has no per-location options. Make this limitation
        // visible.
        for (std::uint32_t j = 0; j < bp.GetNumLocations(); ++j) {
          auto location = bp.GetLocationAtIndex(j);
          if (location.IsEnabled() != bp.IsEnabled() ||
              safe_string(location.GetCondition()) !=
                  safe_string(bp.GetCondition()) ||
              location.GetIgnoreCount() != bp.GetIgnoreCount()) {
            notice(state, l10n::text(l10n::Key::LldbSessionLocationOptions));
            break;
          }
        }
        restored_.insert_or_assign(id, saved);
        authored.breakpoints.push_back(std::move(saved));
      } catch (const std::exception &error) {
        if (auto previous = restored_.find(id); previous != restored_.end())
          authored.breakpoints.push_back(previous->second);
        notice(state, error.what());
      }
    }
    if (target.GetNumWatchpoints())
      notice(state, l10n::text(l10n::Key::LldbSessionUnsafeSkipped));
    if (last_saved_ && same(*last_saved_, authored))
      return;
    store_->save_debugger(state.session, authored);
    pending_.assign(authored.breakpoints.begin(),
                    authored.breakpoints.begin() +
                        static_cast<std::ptrdiff_t>(pending_.size()));
    original_path_ = current_path_;
    last_saved_ = std::move(authored);
    io_error_.clear();
  } catch (const std::exception &error) {
    io_error_ = error.what();
    state.session_error = io_error_;
  }
}

SessionData LldbSessions::clear(const std::string &expected,
                                SessionSnapshot &state) {
  if (!store_ || expected.empty() || state.session.sha256 != expected)
    throw std::runtime_error(l10n::text(l10n::Key::LldbSessionWrongTarget));
  auto data =
      store_->clear(expected); // Durable tombstone precedes all live removal.
  state.session = data.identity;
  pending_.clear();
  restored_.clear();
  last_saved_ = data.debugger;
  exceptions_.clear();
  ignore_counts_.clear();
  restored_ignore_events_.clear();
  comments_.clear();
  comments_revision_ = data.analysis_revision;
  io_error_.clear();
  notice_.clear();
  state.session_error.clear();
  return data;
}

void LldbSessions::comment(lldb::SBTarget &target, std::uint64_t load_address,
                           const std::string &text, SessionSnapshot &state) {
  if (!store_ || state.session.epoch.empty())
    throw std::runtime_error(l10n::text(l10n::Key::LldbSessionUnavailable));
  auto saved = address(target.ResolveLoadAddress(load_address));
  if (!saved)
    throw std::runtime_error(l10n::text(l10n::Key::LldbSessionUnsafeAddress));
  store_->set_comment(state.session, *saved, text);

  io_error_.clear();
}
void LldbSessions::ignore_count_changed(lldb::SBBreakpoint breakpoint,
                                        bool observed_command) {
  const auto id = static_cast<std::uint32_t>(breakpoint.GetID());
  if (!observed_command && restored_ignore_events_.erase(id))
    return;
  ignore_counts_.insert_or_assign(id, breakpoint.GetIgnoreCount());
  if (observed_command)
    restored_ignore_events_.insert(id);
}

void LldbSessions::annotate(lldb::SBTarget &target, SessionSnapshot &state) {
  if (!store_ || state.session.sha256.empty())
    return;
  const auto status = store_->status(state.session.sha256);
  state.session_analysis_revision = status.analysis_revision;
  io_error_ = status.error;
  if (!comments_.empty() && !status.identity.epoch.empty() &&
      status.identity != state.session) {
    annotated_graph_.reset();
    comments_.clear();
  }
  try {
    if (!state.session.epoch.empty() && status.identity == state.session &&
        comments_revision_ != status.analysis_revision) {
      comments_ = store_->read(state.session).comments;
      comments_revision_ = status.analysis_revision;
    }
    auto annotate_rows = [&](std::vector<InstructionRow> &rows) {
      for (auto &row : rows) {
        row.user_comment.clear();
        if (comments_.empty() || !row.has_file_address)
          continue;
        // Only modules that could contain an authored file VA are hashed.
        if (std::none_of(
                comments_.begin(), comments_.end(), [&](const auto &comment) {
                  return comment.address.file_address == row.file_address;
                }))
          continue;
        auto native = target.ResolveLoadAddress(row.address);
        if (!native.IsValid())
          continue;
        const auto saved = address(native);
        if (!saved)
          continue;
        for (const auto &comment : comments_) {
          if (comment.address.module_sha256 == saved->module_sha256 &&
              comment.address.file_address == saved->file_address) {
            row.user_comment = comment.text;
            break;
          }
        }
      }
    };
    annotate_rows(state.instructions);
    if (state.disassembly_graph &&
        (annotated_graph_.lock() != state.disassembly_graph ||
         annotated_graph_revision_ != comments_revision_)) {
      auto graph = std::make_shared<DisassemblyGraph>(*state.disassembly_graph);
      for (auto &block : graph->blocks)
        annotate_rows(block.instructions);
      state.disassembly_graph = std::move(graph);
      annotated_graph_ = state.disassembly_graph;
      annotated_graph_revision_ = comments_revision_;
    }
  } catch (const std::exception &error) {
    io_error_ = error.what();
  }
  state.session_error = notice_;
  if (!io_error_.empty()) {
    if (!state.session_error.empty())
      state.session_error += '\n';
    state.session_error += io_error_;
  }
}

} // namespace debugger::lldb_detail
