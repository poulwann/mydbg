#pragma once

#include "backend/session/SessionStore.h"

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace debugger {

enum class DecompilerTokenKind {
  Plain,
  Keyword,
  Comment,
  DataType,
  Function,
  Parameter,
  Local,
  Constant,
  Global,
};

enum class DecompilerSymbolKind {
  None,
  Function,
  Global,
  Constant,
  Local,
  Parameter,
};

struct DecompilerSpan {
  std::size_t start{};
  std::size_t length{};
  DecompilerTokenKind kind{DecompilerTokenKind::Plain};
  DecompilerSymbolKind symbol_kind{DecompilerSymbolKind::None};
  std::string symbol_name;
  std::uint64_t reference_file_address{};
  std::uint64_t file_address{};
  bool has_file_address{};
  bool has_reference_file_address{};
};

struct DecompiledLine {
  std::string text;
  std::vector<DecompilerSpan> spans;
  std::vector<std::uint64_t> file_addresses;
};

struct DecompilerRequest {
  std::string executable_path;
  std::string module_id;
  std::uint64_t file_address{};
  std::uint64_t load_address{};
  std::uint64_t generation{};
  std::string debug_info_path;
  SessionIdentity session{};
  std::uint64_t analysis_revision{};
};

enum class DecompilerEditKind {
  Rename,
  SetType,
  MarkString,
};

struct DecompilerEditRequest {
  DecompilerRequest context;
  DecompilerEditKind kind{DecompilerEditKind::Rename};
  DecompilerSymbolKind target_kind{DecompilerSymbolKind::None};
  std::string target_name;
  std::uint64_t target_file_address{};
  bool has_target_file_address{};
  std::string value;
};

struct DecompilerMemoryHint {
  std::uint64_t file_address{};
  std::string label;
  std::string type;
  bool is_string{};
};

struct DecompilerSnapshot {
  std::string executable_path;
  std::string debug_info_path;
  std::uint64_t requested_file_address{};
  std::string module_id;
  std::uint64_t requested_load_address{};
  std::uint64_t generation{};
  std::uint64_t request_serial{};
  std::uint64_t function_file_address{};
  std::uint64_t function_min_file_address{};
  std::uint64_t function_max_file_address{};
  bool loading{};
  std::string error;
  std::vector<DecompiledLine> lines;
  std::string notice;
  SessionIdentity session{};
  std::uint64_t analysis_revision{};
  std::vector<DecompilerMemoryHint> memory_hints;
  std::vector<SessionComment> comments;
};

class DecompilerEngine {
public:
  explicit DecompilerEngine(std::shared_ptr<SessionStore> sessions = {});
  ~DecompilerEngine();

  DecompilerEngine(const DecompilerEngine &) = delete;
  DecompilerEngine &operator=(const DecompilerEngine &) = delete;

  void request(DecompilerRequest request);
  void edit(DecompilerEditRequest edit);
  void cancel(std::uint64_t generation);
  [[nodiscard]] std::shared_ptr<const DecompilerSnapshot> snapshot() const;

private:
  struct Request {
    DecompilerRequest identity;
    std::optional<DecompilerEditRequest> edit;
    std::uint64_t serial{};
  };

  void run();

  mutable std::mutex mutex_;
  std::condition_variable wake_;
  std::optional<Request> request_;
  std::deque<Request> edits_;
  std::shared_ptr<SessionStore> sessions_;
  std::shared_ptr<const DecompilerSnapshot> snapshot_;
  bool shutdown_{};
  std::thread worker_;
};

} // namespace debugger
