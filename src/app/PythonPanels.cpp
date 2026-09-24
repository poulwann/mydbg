#include "app/PythonPanels.h"
#include "app/AppState.h"
#include "app/PythonController.h"
#include "app/PythonSyntax.h"
#include "app/UiSupport.h"
#include "localization/Localization.h"
#include "scripting/PythonRuntime.h"

#include <imgui_internal.h>

#include <filesystem>

namespace mydbg::app {

namespace {

const char *
script_debug_state_text(debugger::scripting::ScriptDebugState state) {
  using debugger::scripting::ScriptDebugState;
  switch (state) {
  case ScriptDebugState::Inactive:
    return l10n::text(l10n::Key::GuiPythonDebugStateInactive);
  case ScriptDebugState::Running:
    return l10n::text(l10n::Key::GuiPythonDebugStateRunning);
  case ScriptDebugState::Paused:
    return l10n::text(l10n::Key::GuiPythonDebugStatePaused);
  }
  return l10n::text(l10n::Key::GuiPythonStatusUnknown);
}

const TextEditor::Palette &python_palette(bool dark) {
  const auto make_palette = [](bool use_dark) {
    TextEditor::Palette palette =
        use_dark ? TextEditor::GetDarkPalette() : TextEditor::GetLightPalette();
    const auto set = [&](TextEditor::PaletteIndex role, ImU32 dark_color,
                         ImU32 light_color) {
      palette[static_cast<std::size_t>(role)] =
          use_dark ? dark_color : light_color;
    };
    using Role = TextEditor::PaletteIndex;
    set(Role::Default, IM_COL32(220, 224, 232, 255), IM_COL32(36, 41, 47, 255));
    set(Role::Identifier, IM_COL32(220, 224, 232, 255),
        IM_COL32(36, 41, 47, 255));
    set(Role::Keyword, IM_COL32(198, 146, 234, 255),
        IM_COL32(130, 42, 160, 255));
    set(Role::Number, IM_COL32(244, 176, 112, 255), IM_COL32(157, 70, 0, 255));
    set(Role::String, IM_COL32(152, 195, 121, 255), IM_COL32(44, 108, 48, 255));
    set(Role::CharLiteral, IM_COL32(240, 207, 126, 255),
        IM_COL32(145, 97, 0, 255));
    set(Role::Punctuation, IM_COL32(170, 182, 198, 255),
        IM_COL32(79, 91, 108, 255));
    set(Role::KnownIdentifier, IM_COL32(86, 199, 209, 255),
        IM_COL32(0, 111, 119, 255));
    set(Role::PreprocIdentifier, IM_COL32(97, 175, 239, 255),
        IM_COL32(0, 86, 179, 255));
    set(Role::Preprocessor, IM_COL32(229, 140, 174, 255),
        IM_COL32(164, 41, 94, 255));
    set(Role::Comment, IM_COL32(137, 148, 163, 255),
        IM_COL32(101, 112, 125, 255));
    return palette;
  };
  static const TextEditor::Palette dark_palette = make_palette(true);
  static const TextEditor::Palette light_palette = make_palette(false);
  return dark ? dark_palette : light_palette;
}

} // namespace

const TextEditor::LanguageDefinition &python_language_definition() {
  static const TextEditor::LanguageDefinition definition = [] {
    TextEditor::LanguageDefinition value;
    value.mName = "Python";
    value.mColorize = python_syntax::colorize;
    value.mIndentation = python_syntax::indentation;
    value.mInsertSpaces = true;
    return value;
  }();
  return definition;
}

void draw_script_values(
    const char *id,
    const std::vector<debugger::scripting::ScriptValue> &values) {
  if (!ImGui::BeginTable(id, 3,
                         ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_RowBg |
                             ImGuiTableFlags_ScrollY)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPythonValueName),
                          ImGuiTableColumnFlags_WidthStretch, 0.30F);
  ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPythonValueType),
                          ImGuiTableColumnFlags_WidthStretch, 0.20F);
  ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPythonValueValue),
                          ImGuiTableColumnFlags_WidthStretch, 0.50F);
  ImGui::TableHeadersRow();
  for (const auto &value : values) {
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::TextUnformatted(value.name.c_str());
    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(value.type.c_str());
    ImGui::TableSetColumnIndex(2);
    ImGui::TextUnformatted(value.value.c_str());
  }
  ImGui::EndTable();
}

void arrange_python_debug_workspace() {
  const ImGuiViewport *viewport = ImGui::GetMainViewport();
  const ImVec2 origin = viewport->WorkPos;
  const ImVec2 size = viewport->WorkSize;
  const float script_width = size.x * 0.5F;
  const float debuggee_width = size.x - script_width;
  const float debuggee_height = size.y * 0.5F;

  const auto place_window = [](l10n::Key key, ImVec2 position, ImVec2 extent) {
    const char *window = l10n::label(key);
    ImGui::SetWindowCollapsed(window, false);
    ImGui::SetWindowPos(window, position);
    ImGui::SetWindowSize(window, extent);
  };
  place_window(l10n::Key::WindowPythonDebugger, origin,
               ImVec2(script_width, size.y));
  place_window(l10n::Key::WindowDisassembly,
               ImVec2(origin.x + script_width, origin.y),
               ImVec2(debuggee_width, debuggee_height));
  place_window(l10n::Key::WindowDecompiler,
               ImVec2(origin.x + script_width, origin.y + debuggee_height),
               ImVec2(debuggee_width, size.y - debuggee_height));

  ImGui::SetWindowFocus(l10n::label(l10n::Key::WindowDecompiler));
  ImGui::SetWindowFocus(l10n::label(l10n::Key::WindowDisassembly));
  ImGui::SetWindowFocus(l10n::label(l10n::Key::WindowPythonDebugger));
  ImGui::MarkIniSettingsDirty();
}

void dispatch_contextual_shortcuts(
    const debugger::SessionSnapshot &snapshot, debugger::LldbEngine &engine,
    debugger::scripting::PythonRuntime &runtime, UiState &ui,
    const debugger::scripting::ScriptSnapshot &script) {
  if (!ui.python_window_focused) {
    const bool control_lease =
        script.control_lease &&
        script.debug_state != debugger::scripting::ScriptDebugState::Paused;
    dispatch_debugger_shortcuts(snapshot, engine, ui, control_lease);
    return;
  }
  if (ui.keybinding_capture) {
    return;
  }
  constexpr ImGuiInputFlags route = ImGuiInputFlags_RouteGlobal;
  for (const ScriptActionDefinition &definition : script_actions) {
    const ImGuiKeyChord binding =
        ui.script_keybindings[action_index(definition.action)];
    if (binding != 0 && ImGui::Shortcut(binding, route) &&
        script_action_enabled(definition.action, script, ui)) {
      if (execute_script_action(definition.action, script, runtime, ui)) {
        arrange_python_debug_workspace();
      }
      break;
    }
  }
}

bool script_action_button(const char *label, ScriptAction action,
                          const UiState &ui) {
  const bool activated = ImGui::Button(label);
  if (ImGui::IsItemHovered()) {
    const ImGuiKeyChord binding = ui.script_keybindings[action_index(action)];
    if (binding == 0) {
      ImGui::SetTooltip("%s", l10n::text(l10n::Key::GuiPythonShortcutUnbound));
    } else {
      ImGui::SetTooltip(l10n::text(l10n::Key::GuiPythonShortcut),
                        ImGui::GetKeyChordName(binding));
    }
  }
  return activated;
}

void draw_python_panel(debugger::scripting::PythonRuntime &runtime,
                       UiState &ui) {
  if (!ui.script_editor_initialized) {
    ui.script_editor.SetLanguageDefinition(python_language_definition());
    ui.script_editor.SetTabSize(4);
    ui.script_editor.SetShowWhitespaces(false);
    ui.script_editor.SetPalette(python_palette(ui.theme_dark));
    ui.script_editor_theme_dark = ui.theme_dark;
    ui.script_editor_initialized = true;
  }
  if (ui.script_editor_theme_dark != ui.theme_dark) {
    ui.script_editor.SetPalette(python_palette(ui.theme_dark));
    ui.script_editor_theme_dark = ui.theme_dark;
  }

  const PythonFileDialogState file_dialog = python_sync_script_file(ui);

  const debugger::scripting::ScriptSnapshot script = runtime.snapshot();
  python_sync_editor_execution(script, ui);

  ImGui::Begin(l10n::label(l10n::Key::WindowPythonDebugger));
  ui.python_window_focused =
      ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
  const float button_width =
      ImGui::CalcTextSize(l10n::text(l10n::Key::GuiPythonBrowse)).x +
      ImGui::GetStyle().FramePadding.x * 2.0F;
  ImGui::SetNextItemWidth(
      -(button_width * 4.0F + ImGui::GetStyle().ItemSpacing.x * 4.0F));
  ImGui::InputTextWithHint("##python-script",
                           l10n::text(l10n::Key::GuiPythonScriptPathHint),
                           ui.script_path.data(), ui.script_path.size());
  ImGui::SameLine();
  ImGui::BeginDisabled(script.control_lease);
  if (ImGui::Button(l10n::label(l10n::Key::GuiPythonLoad))) {
    load_script_source(ui, ui.script_path.data());
  }
  ImGui::SameLine();
  if (ImGui::Button(l10n::label(l10n::Key::GuiPythonSave)) ||
      (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
       ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_S,
                       ImGuiInputFlags_RouteFocused))) {
    save_script_source(ui);
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  ImGui::BeginDisabled(script.control_lease || file_dialog.open);
  if (ImGui::Button(file_dialog.open
                        ? l10n::label(l10n::Key::GuiPythonSelecting)
                        : l10n::label(l10n::Key::GuiPythonBrowse))) {
    show_script_dialog(ui);
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  ImGui::BeginDisabled(script.control_lease);
  if (ImGui::Button(l10n::label(l10n::Key::GuiPythonCtfDemo))) {
    python_load_ctf_demo(runtime, ui);
  }
  ImGui::EndDisabled();

  const auto action_button = [&](l10n::Key label, ScriptAction action) {
    if (script_action_button(l10n::label(label), action, ui)) {
      if (execute_script_action(action, script, runtime, ui)) {
        arrange_python_debug_workspace();
      }
    }
  };
  ImGui::BeginDisabled(script.control_lease || ui.script_loaded_path.empty());
  action_button(l10n::Key::GuiPythonRun, ScriptAction::Run);
  ImGui::SameLine();
  if (script_action_button(l10n::label(l10n::Key::GuiPythonDebug),
                           ScriptAction::DebugContinue, ui)) {
    if (start_python_debugger(runtime, ui)) {
      arrange_python_debug_workspace();
    }
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  action_button(l10n::Key::GuiPythonToggleBreakpoint,
                ScriptAction::ToggleBreakpoint);
  ImGui::SameLine();

  ImGui::BeginDisabled(script.debug_state !=
                       debugger::scripting::ScriptDebugState::Paused);
  action_button(l10n::Key::GuiPythonContinue, ScriptAction::DebugContinue);
  ImGui::SameLine();
  action_button(l10n::Key::GuiPythonStepInto, ScriptAction::StepInto);
  ImGui::SameLine();
  action_button(l10n::Key::GuiPythonStepOver, ScriptAction::StepOver);
  ImGui::SameLine();
  action_button(l10n::Key::GuiPythonStepOut, ScriptAction::StepOut);
  ImGui::EndDisabled();
  ImGui::SameLine();
  ImGui::BeginDisabled(script.debug_state !=
                       debugger::scripting::ScriptDebugState::Running);
  action_button(l10n::Key::GuiPythonPause, ScriptAction::Pause);
  ImGui::EndDisabled();
  ImGui::SameLine();
  ImGui::BeginDisabled(!script.control_lease);
  action_button(l10n::Key::GuiPythonStop, ScriptAction::Stop);
  ImGui::EndDisabled();
  ImGui::SameLine();
  if (ImGui::Button(l10n::label(l10n::Key::GuiPythonDebuggeeSplit))) {
    arrange_python_debug_workspace();
  }

  ImGui::Text(l10n::text(ui.script_dirty
                             ? l10n::Key::GuiPythonModifiedScriptState
                             : l10n::Key::GuiPythonScriptState),
              script_status_text(script.status),
              script_debug_state_text(script.debug_state));
  if (!file_dialog.error.empty() || !ui.script_file_error.empty()) {
    const std::string &error =
        !file_dialog.error.empty() ? file_dialog.error : ui.script_file_error;
    ImGui::TextColored(ImVec4(1.0F, 0.35F, 0.35F, 1.0F), "%s", error.c_str());
  } else if (!ui.python_console_message.empty()) {
    ImGui::TextUnformatted(ui.python_console_message.c_str());
  }

  if (ImGui::BeginTable("script-debugger-layout", 2,
                        ImGuiTableFlags_Resizable |
                            ImGuiTableFlags_BordersInnerV,
                        ImVec2(0.0F, 0.0F))) {
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPythonSource),
                            ImGuiTableColumnFlags_WidthStretch, 0.68F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPythonInspector),
                            ImGuiTableColumnFlags_WidthStretch, 0.32F);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ui.script_editor.Render("##python-source", ImVec2(0.0F, 0.0F), false);
    if (ui.script_editor.IsTextChanged()) {
      ui.script_dirty = true;
    }

    ImGui::TableSetColumnIndex(1);
    if (ImGui::BeginTabBar("script-inspector-tabs")) {
      if (ImGui::BeginTabItem(l10n::label(l10n::Key::GuiPythonStack))) {
        if (ui.selected_script_frame >= script.frames.size()) {
          ui.selected_script_frame = 0;
        }
        for (std::size_t index = 0; index < script.frames.size(); ++index) {
          const auto &frame = script.frames[index];
          const std::string label =
              frame.function + " — " +
              std::filesystem::path{frame.file}.filename().string() + ":" +
              std::to_string(frame.line);
          if (ImGui::Selectable(label.c_str(),
                                ui.selected_script_frame == index)) {
            ui.selected_script_frame = index;
          }
        }
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem(l10n::label(l10n::Key::GuiPythonLocals))) {
        if (ui.selected_script_frame < script.frames.size()) {
          draw_script_values("script-locals",
                             script.frames[ui.selected_script_frame].locals);
        }
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem(l10n::label(l10n::Key::GuiPythonGlobals))) {
        draw_script_values("script-globals", script.globals);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem(l10n::label(l10n::Key::GuiPythonOutput))) {
        ImGui::BeginChild("python-output");
        if (!script.output.empty()) {
          ImGui::TextUnformatted(script.output.c_str());
        }
        if (!script.traceback.empty()) {
          ImGui::SeparatorText(l10n::text(l10n::Key::GuiPythonTraceback));
          ImGui::TextColored(ImVec4(1.0F, 0.35F, 0.35F, 1.0F), "%s",
                             script.traceback.c_str());
        }
        ImGui::EndChild();
        ImGui::EndTabItem();
      }
      ImGui::EndTabBar();
    }
    ImGui::EndTable();
  }
  ImGui::End();
}

void draw_console_panel(const debugger::SessionSnapshot &snapshot,
                        debugger::LldbEngine &engine,
                        debugger::scripting::PythonRuntime &runtime,
                        UiState &ui, bool control_lease) {
  ImGui::Begin(l10n::label(l10n::Key::WindowCommand));
  if (ImGui::BeginTabBar("output-tabs")) {
    if (ImGui::BeginTabItem(l10n::label(l10n::Key::GuiPythonDebuggerConsole))) {
      ImGui::BeginChild(
          "console-scroll",
          ImVec2(0.0F, -ImGui::GetFrameHeightWithSpacing() * 2.0F),
          ImGuiChildFlags_Borders);
      ImGui::TextUnformatted(snapshot.console_output.c_str());
      ImGui::EndChild();
      const bool submitted = ImGui::InputTextWithHint(
          "##command", l10n::text(l10n::Key::GuiPythonCommandHint),
          ui.console_command.data(), ui.console_command.size(),
          ImGuiInputTextFlags_EnterReturnsTrue);
      ImGui::SameLine();
      if (submitted || ImGui::Button(l10n::label(l10n::Key::GuiPythonRun))) {
        execute_console_input(ui.console_command.data(), engine, runtime, ui,
                              control_lease);
        ui.console_command.front() = '\0';
      }
      if (!ui.python_console_message.empty()) {
        ImGui::TextWrapped("%s", ui.python_console_message.c_str());
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem(l10n::label(l10n::Key::GuiPythonDebuggeeOutput))) {
      ImGui::TextUnformatted(snapshot.process_output.c_str());
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }
  ImGui::End();
}

} // namespace mydbg::app
