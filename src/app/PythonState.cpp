#include "app/PythonState.h"
#include "app/PythonEditorState.h"

namespace mydbg::app {

PythonState::PythonState() : editor{std::make_unique<PythonEditorState>()} {}
PythonState::~PythonState() = default;

} // namespace mydbg::app
