#pragma once

#include "backend/lldb/LldbEngine.h"
#include <functional>
#include <lldb/API/LLDB.h>
#include <optional>
#include <unordered_map>

#include <unordered_set>
namespace debugger::lldb_detail {

// Worker-owned bridge. Native IDs and module hashes are scoped to one target;
// saved records that cannot currently be resolved remain independent of it.
class LldbSessions final {
public:
  explicit LldbSessions(std::shared_ptr<SessionStore> store);
  void reset(SessionSnapshot &state);
  std::optional<SessionDebuggerState>
  open(lldb::SBTarget &target, const std::string &path, SessionSnapshot &state);
  std::vector<std::pair<std::uint32_t, std::string>>
  restore(lldb::SBTarget &target, SessionSnapshot &state);
  void save(lldb::SBTarget &target, SessionDebuggerState authored,
            const std::function<std::string(std::uint32_t)> &condition,
            SessionSnapshot &state);
  SessionData clear(const std::string &expected, SessionSnapshot &state);
  void comment(lldb::SBTarget &target, std::uint64_t address,
               const std::string &text, SessionSnapshot &state);
  void annotate(lldb::SBTarget &target, SessionSnapshot &state);
  std::optional<SessionAddress> address(lldb::SBAddress address);
  lldb::SBAddress resolve(lldb::SBTarget &target,
                          const SessionAddress &address);
  void remember_exception_command(lldb::SBTarget &target,
                                  std::string_view command,
                                  std::uint32_t previous_id);
  void transient(lldb::SBBreakpoint breakpoint);
  void remove_transients(lldb::SBTarget &target);
  bool is_transient(lldb::SBBreakpoint breakpoint) const;
  void notice(SessionSnapshot &state, const std::string &message);
  void ignore_count_changed(lldb::SBBreakpoint breakpoint,
                            bool observed_command = false);

private:
  std::string module_hash(lldb::SBModule module);
  lldb::SBModule matching_module(lldb::SBTarget &target,
                                 const std::string &hash);
  std::shared_ptr<SessionStore> store_;
  std::vector<std::pair<lldb::SBModule, std::string>> module_hashes_;
  std::vector<SessionBreakpoint> pending_;
  std::unordered_map<std::uint32_t, SessionBreakpoint> restored_;
  std::unordered_map<std::uint32_t, std::uint32_t> ignore_counts_;
  std::unordered_set<std::uint32_t> restored_ignore_events_;
  std::vector<lldb::SBBreakpoint> transient_;
  std::optional<SessionDebuggerState> last_saved_;
  std::string original_path_;
  std::string current_path_;
  std::string notice_;
  std::string io_error_;
  struct ExceptionIntent {
    lldb::LanguageType language{lldb::eLanguageTypeUnknown};
    bool catch_exception{};
    bool throw_exception{true};
  };
  std::unordered_map<std::uint32_t, ExceptionIntent> exceptions_;
  std::vector<std::pair<lldb::SBBreakpoint, ExceptionIntent>> exception_cache_;
  std::weak_ptr<const DisassemblyGraph> annotated_graph_;
  std::uint64_t annotated_graph_revision_{~std::uint64_t{0}};
  std::uint64_t comments_revision_{~std::uint64_t{0}};
  std::vector<SessionComment> comments_;
};

} // namespace debugger::lldb_detail
