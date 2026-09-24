#include "app/PythonSyntax.h"
#include "TestSupport.h"

#include <imgui.h>

#include <cstdio>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
using Color = TextEditor::PaletteIndex;
namespace syntax = mydbg::app::python_syntax;

using debugger::test::require;

TextEditor::Lines glyphs(std::string_view source) {
  TextEditor::Lines lines(1);
  for (const unsigned char byte : source) {
    if (byte == '\n')
      lines.emplace_back();
    else
      lines.back().emplace_back(byte, Color::Default);
  }
  return lines;
}

void check_indentation() {
  struct Case {
    const char *source;
    const char *expected;
  };
  const Case cases[] = {
      {"if ready: # comment with a quote '\"", "    "},
      {"    async def work(value: int) -> str:", "        "},
      {"if ready: work()", ""},
      {"    values = {'key':", "              "},
      {"    text = 'if ready:'", "    "},
      {"    # if ready:", "    "},
      {"if (ready\n        and enabled):", "    "},
      {"values = call(first,", "              "},
      {"values = [\n    first,", "    "},
      {"    return (\n        value\n    )", ""},
      {"    text = '''example\n    if ready:", "    "},
      {"\tif ready:", "\t\t"},
      {"    value = lambda item:", "    "},
  };
  for (const auto &test : cases) {
    const auto lines = glyphs(test.source);
    const auto actual =
        syntax::indentation(lines, static_cast<int>(lines.size() - 1),
                            static_cast<int>(lines.back().size()), 4);
    if (actual != test.expected) {
      std::fprintf(
          stderr,
          "indentation for [%s]: expected %zu whitespace bytes, got %zu\n",
          test.source, std::string_view{test.expected}.size(), actual.size());
      throw std::runtime_error(
          "Python indentation disagrees with logical statement context");
    }
  }
  const auto split = glyphs("if ready: work()");
  require(syntax::indentation(split, 0, 9, 4) == "    ",
          "newline must analyze only text before the insertion point");
}

void color_at(const TextEditor::Lines &lines, int line, std::string_view source,
              std::string_view token, Color expected) {
  const auto offset = source.find(token);
  require(offset != std::string_view::npos, "invalid color test token");
  for (std::size_t index = offset; index < offset + token.size(); ++index) {
    if (lines.at(static_cast<std::size_t>(line)).at(index).mColorIndex !=
        expected) {
      std::fprintf(stderr, "unexpected Python color for [%.*s] at byte %zu\n",
                   static_cast<int>(token.size()), token.data(), index);
      throw std::runtime_error("Python syntax category is incorrect");
    }
  }
}

void check_highlighting() {
  const std::string first =
      "text = '# not a comment'; if_ready = 0x_FF_12 # comment";
  auto lines = glyphs(first);
  syntax::colorize(lines);
  color_at(lines, 0, first, "# not a comment", Color::String);
  color_at(lines, 0, first, "if_ready", Color::Identifier);
  color_at(lines, 0, first, "0x_FF_12", Color::Number);
  color_at(lines, 0, first, "# comment", Color::Comment);

  lines = glyphs("'''documentation\n# still a string\nend'''\nif ready:");
  syntax::colorize(lines);
  color_at(lines, 1, "# still a string", "# still a string", Color::String);
  color_at(lines, 3, "if ready:", "if", Color::Keyword);
  lines[0] = glyphs("# documentation").front();
  syntax::colorize(lines);
  color_at(lines, 1, "# still a string", "# still a string", Color::Comment);
  color_at(lines, 3, "if ready:", "if", Color::String);

  const std::string formatted =
      "value = f\"answer {len(items):>{width}} # literal\"";
  lines = glyphs(formatted);
  syntax::colorize(lines);
  color_at(lines, 0, formatted, "answer", Color::String);
  color_at(lines, 0, formatted, "len", Color::KnownIdentifier);
  color_at(lines, 0, formatted, "items", Color::Identifier);
  color_at(lines, 0, formatted, "width", Color::Identifier);
  color_at(lines, 0, formatted, "# literal", Color::String);

  const std::string nested = "value = f\"{ {'key': f'{count}'} }\"";
  lines = glyphs(nested);
  syntax::colorize(lines);
  color_at(lines, 0, nested, "key", Color::String);
  color_at(lines, 0, nested, "count", Color::Identifier);

  const std::string raw =
      R"py(path = r"C:\data\file"; text = "\n"; number = .5e-2j)py";
  lines = glyphs(raw);
  syntax::colorize(lines);
  color_at(lines, 0, raw, R"(\data\file)", Color::String);
  color_at(lines, 0, raw, R"(\n)", Color::CharLiteral);
  color_at(lines, 0, raw, ".5e-2j", Color::Number);
}

void frame(TextEditor &editor) {
  ImGui::NewFrame();
  ImGui::SetNextWindowPos(ImVec2(0, 0));
  ImGui::SetNextWindowSize(ImVec2(800, 600));
  ImGui::Begin("Python editor regression");
  ImGui::SetWindowFocus();
  editor.Render("source", ImVec2(760, 540));
  ImGui::End();
  ImGui::Render();
}

void press(TextEditor &editor, ImGuiKey key) {
  ImGui::GetIO().AddKeyEvent(key, true);
  frame(editor);
  ImGui::GetIO().AddKeyEvent(key, false);
  frame(editor);
}

void check_editor() {
  ImGui::CreateContext();
  auto &io = ImGui::GetIO();
  io.IniFilename = nullptr;
  io.LogFilename = nullptr;
  io.DisplaySize = ImVec2(800, 600);
  io.DeltaTime = 1.0F / 60.0F;
  io.Fonts->AddFontDefaultVector();
  io.Fonts->Build();
  {
    TextEditor editor;
    TextEditor::LanguageDefinition language;
    language.mColorize = syntax::colorize;
    language.mIndentation = syntax::indentation;
    language.mInsertSpaces = true;
    editor.SetLanguageDefinition(language);
    editor.SetTabSize(4);
    editor.SetImGuiChildIgnored(true);
    editor.SetText("if ready:");
    editor.SetCursorPosition({0, 9});
    frame(editor);
    press(editor, ImGuiKey_Enter);
    require(editor.GetTextLines() ==
                std::vector<std::string>{"if ready:", "    "},
            "Enter did not insert suite indentation");
    require(editor.GetCursorPosition() == TextEditor::Coordinates{1, 4},
            "Enter left cursor before the automatic indentation");
    editor.Undo();
    require(editor.GetTextLines() == std::vector<std::string>{"if ready:"},
            "newline and indentation must undo together");
    editor.Redo();
    require(editor.GetTextLines() ==
                std::vector<std::string>{"if ready:", "    "},
            "redo lost automatic indentation");
    require(editor.GetCursorPosition() == TextEditor::Coordinates{1, 4},
            "redo restored an incorrect cursor column");

    editor.SetText("if ready:discard");
    editor.SetSelection({0, 9}, {0, 16});
    editor.SetCursorPosition({0, 16});
    frame(editor);
    press(editor, ImGuiKey_Enter);
    require(editor.GetTextLines() ==
                std::vector<std::string>{"if ready:", "    "},
            "selection replacement used stale indentation context");
    editor.Undo();
    require(editor.GetTextLines() ==
                    std::vector<std::string>{"if ready:discard"} &&
                editor.GetSelectedText() == "discard",
            "undo must restore replaced text and selection");

    editor.SetText("x");
    editor.SetSelection({0, 1}, {0, 1});
    editor.SetCursorPosition({0, 1});
    frame(editor);
    press(editor, ImGuiKey_Tab);
    require(editor.GetTextLines() == std::vector<std::string>{"x   "},
            "Python Tab must insert spaces to the next tab stop");
    editor.SetReadOnly(true);
    press(editor, ImGuiKey_Enter);
    require(editor.GetTextLines() == std::vector<std::string>{"x   "},
            "automatic indentation modified a read-only editor");
  }
  ImGui::DestroyContext();
}
} // namespace

int main() {
  try {
    check_indentation();
    check_highlighting();
    check_editor();
    std::puts("Python indentation, lexical boundaries, and atomic editor undo "
              "verified");
    return 0;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "Python editor regression: %s\n", error.what());
    if (ImGui::GetCurrentContext())
      ImGui::DestroyContext();
    return 1;
  }
}
