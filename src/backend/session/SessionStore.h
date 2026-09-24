#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace debugger {

// The epoch changes on clear, not on process restart. Every mutation carries it
// so a worker finishing old work cannot resurrect a cleared session.
struct SessionIdentity {
  std::string sha256;
  std::string epoch;
  bool operator==(const SessionIdentity &) const = default;
};

struct SessionAddress {
  std::string module_sha256;
  std::string module_path; // Locator only; never a substitute for the hash.
  std::uint64_t file_address{}; // ELF file VA, not disk offset or load address.
};

struct SessionBreakpoint {
  std::string serialized; // Sanitized native resolver/options; never commands.
  std::string script_condition; // The application's bounded condition language.
  std::string module_sha256;    // Required for an address resolver.
  std::string module_path;
};

struct SessionSymbol {
  std::string name;
  SessionAddress address;
};

struct SessionDebuggerState {
  std::vector<SessionBreakpoint> breakpoints;
  std::vector<std::string>
      watches; // Expression definitions, not command watches.
  std::vector<SessionSymbol> symbols;
  std::vector<std::string> arguments;
  std::string working_directory;
};

enum class SavedAnalysisKind { Rename, SetType, MarkString };
enum class SavedSymbolKind {
  None,
  Function,
  Global,
  Constant,
  Local,
  Parameter
};

struct SessionAnalysisEdit {
  SavedAnalysisKind kind{SavedAnalysisKind::Rename};
  SavedSymbolKind target_kind{SavedSymbolKind::None};
  std::uint64_t function_file_address{};
  std::string target_name;
  std::uint64_t target_file_address{};
  bool has_target_file_address{};
  std::string value;
};

struct SessionModuleAnalysis {
  std::string sha256;
  std::string path;
  // Application order is significant: rename a->b, retype b, rename b->c.
  std::vector<SessionAnalysisEdit> edits;
};

struct SessionComment {
  SessionAddress address;
  std::string text; // Empty text is deletion, not a stored comment.
};

struct SessionData {
  SessionIdentity identity;
  std::string binary_path;
  std::uint64_t revision{};
  std::uint64_t analysis_revision{};
  SessionDebuggerState debugger;
  std::vector<SessionModuleAnalysis> analysis;
  std::vector<SessionComment> comments;
};

struct SessionStatus {
  SessionIdentity identity;
  std::uint64_t revision{};
  std::uint64_t analysis_revision{};
  std::size_t breakpoint_count{};
  std::size_t watch_count{};
  std::size_t edit_count{};
  std::size_t comment_count{};
  bool writable{};
  std::string error;
};

// Thread-safe shared ownership across debugger and decompiler workers. Mutating
// methods merge only their own section under an interprocess lock, then
// atomically replace the file. Failures throw and are also retained in
// status(); callers report them without stopping debugging. read()/status() are
// cached, without IO.
class SessionStore final {
public:
  explicit SessionStore(std::filesystem::path directory);
  ~SessionStore();
  SessionStore(const SessionStore &) = delete;
  SessionStore &operator=(const SessionStore &) = delete;

  static std::filesystem::path default_directory();
  static std::string hash_file(const std::filesystem::path &path);

  // Reloads disk state at a target boundary. Creates an empty versioned record
  // on first use. An unreadable/corrupt record is never silently overwritten.
  SessionData load(const std::string &sha256, const std::string &binary_path);
  SessionData read(const SessionIdentity &identity) const;
  SessionStatus status(const std::string &sha256) const;
  SessionStatus save_debugger(const SessionIdentity &identity,
                              const SessionDebuggerState &state);
  SessionStatus append_analysis(const SessionIdentity &identity,
                                const std::string &module_sha256,
                                const std::string &module_path,
                                const SessionAnalysisEdit &edit);
  SessionStatus set_comment(const SessionIdentity &identity,
                            const SessionAddress &address,
                            const std::string &text);
  // Explicitly replaces even a corrupt record with an empty, new-epoch record.
  // Keeping the epoch tombstone prevents stale processes from recreating data.
  SessionData clear(const std::string &sha256);

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace debugger
