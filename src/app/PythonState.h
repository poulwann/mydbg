#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace mydbg::app {

struct PythonEditorState;

struct PythonState {
  PythonState();
  ~PythonState();

  std::array<char, 4096> path{};
  std::array<char, 1024> console_command{};
  std::string console_message;
  std::unique_ptr<PythonEditorState> editor;
  std::string loaded_path;
  std::string file_error;
  bool dirty{};
  bool editor_initialized{};
  bool editor_theme_dark{};
  std::size_t selected_frame{};
  std::uint32_t execution_line{};
  bool window_focused{};
};

} // namespace mydbg::app
