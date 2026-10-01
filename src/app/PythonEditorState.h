#pragma once

#include <TextEditor.h>

namespace mydbg::app {

struct PythonEditorState {
  TextEditor text;
  TextEditor::Breakpoints breakpoints;
};

} // namespace mydbg::app
