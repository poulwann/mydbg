#include "app/AppState.h"
#include "app/Headless.h"
#include "app/UiSupport.h"
#include "localization/Localization.h"

#include <cstdio>
#include <string>
#include <string_view>

namespace mydbg::app {

int run_keybinding_headless() {
  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  UiState ui;
  register_ui_settings(ui);

  const std::string settings = "[MyDbg][Settings]\n"
                               "WindowX=123\n"
                               "WindowY=234\n"
                               "WindowWidth=1280\n"
                               "WindowHeight=720\n"
                               "WindowPositionSaved=1\n"
                               "WindowMaximized=1\n"
                               "Keybinding.start-continue=" +
                               std::to_string(static_cast<int>(ImGuiKey_F8)) +
                               "\nPythonKeybinding.debug-continue=" +
                               std::to_string(static_cast<int>(ImGuiKey_F8)) +
                               "\n\n";
  ImGui::LoadIniSettingsFromMemory(settings.c_str(), settings.size());
  if (ui.keybindings[action_index(DebugAction::StartContinue)] != ImGuiKey_F8) {
    std::fprintf(stderr, l10n::text(l10n::Key::HeadlessKeybindingLoadFailed),
                 ui.keybindings[action_index(DebugAction::StartContinue)],
                 ImGuiKey_F8);
    ImGui::DestroyContext();
    return 40;
  }
  if (ui.script_keybindings[action_index(ScriptAction::DebugContinue)] !=
      ImGuiKey_F8) {
    std::fprintf(
        stderr, l10n::text(l10n::Key::HeadlessPythonKeybindingLoadFailed),
        ui.script_keybindings[action_index(ScriptAction::DebugContinue)],
        ImGuiKey_F8);
    ImGui::DestroyContext();
    return 45;
  }
  if (ui.script_keybindings[action_index(ScriptAction::StepInto)] !=
          ImGuiKey_F11 ||
      ui.script_keybindings[action_index(ScriptAction::StepOver)] !=
          ImGuiKey_F10 ||
      ui.script_keybindings[action_index(ScriptAction::StepOut)] !=
          (ImGuiMod_Shift | ImGuiKey_F11)) {
    std::fputs(
        l10n::text(l10n::Key::HeadlessPythonCallNavigationDefaultsIncorrect),
        stderr);
    ImGui::DestroyContext();
    return 46;
  }
  if (ui.window_x != 123 || ui.window_y != 234 || ui.window_width != 1280 ||
      ui.window_height != 720 || !ui.window_position_saved ||
      !ui.window_maximized) {
    std::fputs(l10n::text(l10n::Key::HeadlessWindowStateLoadFailed), stderr);
    ImGui::DestroyContext();
    return 43;
  }

  std::size_t output_size = 0;
  const char *saved = ImGui::SaveIniSettingsToMemory(&output_size);
  const std::string_view output{saved, output_size};
  const std::string expected_native =
      "Keybinding.start-continue=" +
      std::to_string(static_cast<int>(ImGuiKey_F8));
  const std::string expected_python =
      "PythonKeybinding.debug-continue=" +
      std::to_string(static_cast<int>(ImGuiKey_F8));
  if (output.find(expected_native) == std::string_view::npos ||
      output.find(expected_python) == std::string_view::npos) {
    std::fputs(l10n::text(l10n::Key::HeadlessKeybindingSaveFailed), stderr);
    ImGui::DestroyContext();
    return 41;
  }
  if (output.find("WindowX=123") == std::string_view::npos ||
      output.find("WindowY=234") == std::string_view::npos ||
      output.find("WindowWidth=1280") == std::string_view::npos ||
      output.find("WindowHeight=720") == std::string_view::npos ||
      output.find("WindowPositionSaved=1") == std::string_view::npos ||
      output.find("WindowMaximized=1") == std::string_view::npos) {
    std::fputs(l10n::text(l10n::Key::HeadlessWindowStateSaveFailed), stderr);
    ImGui::DestroyContext();
    return 44;
  }

  ImGuiIO &io = ImGui::GetIO();
  io.DisplaySize = ImVec2(800.0F, 600.0F);
  io.DeltaTime = 1.0F / 60.0F;
  io.Fonts->AddFontDefaultVector();
  io.Fonts->Build();
  ImGui::NewFrame();
  (void)ImGui::Shortcut(
      ui.keybindings[action_index(DebugAction::StartContinue)],
      ImGuiInputFlags_RouteGlobal);
  ImGui::EndFrame();
  io.AddKeyEvent(ImGuiKey_F8, true);
  ImGui::NewFrame();
  const bool dispatched =
      ImGui::Shortcut(ui.keybindings[action_index(DebugAction::StartContinue)],
                      ImGuiInputFlags_RouteGlobal);
  ImGui::EndFrame();
  ImGui::DestroyContext();
  if (!dispatched) {
    std::fputs(l10n::text(l10n::Key::HeadlessKeybindingDispatchFailed), stderr);
    return 42;
  }
  std::fputs(l10n::text(l10n::Key::HeadlessKeybindingSummary), stdout);
  return 0;
}

} // namespace mydbg::app
