#pragma once

#include <TextEditor.h>

#include <string>

namespace mydbg::app::python_syntax {

void colorize(TextEditor::Lines &lines);

// The source is after selection deletion and before newline insertion. The
// column is a UTF-8 byte offset, not TextEditor's tab-expanded visual column.
std::string indentation(const TextEditor::Lines &lines, int line,
                        int byte_column, int tab_size);

} // namespace mydbg::app::python_syntax
