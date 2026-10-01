#pragma once

#include <mutex>
#include <optional>
#include <string>

namespace mydbg::app {

struct FileDialogState {
  std::mutex mutex;
  std::optional<std::string> selected_executable;
  std::optional<std::string> selected_script;
  std::string error;
  std::string location;
  bool open{};
  bool script_dialog{};
};

} // namespace mydbg::app
