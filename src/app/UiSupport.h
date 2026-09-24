#pragma once

#include "localization/Localization.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

struct SDL_Window;

namespace debugger {
class LldbEngine;
struct SessionSnapshot;
} // namespace debugger

namespace mydbg::app {

struct UiState;
enum class DebugAction : std::size_t;
enum class AppNavigationTarget;

struct UiPanelSetting {
  const char *name;
  l10n::Key label;
  bool UiState::*visible;
};

extern const std::array<UiPanelSetting, 8> ui_panel_settings;

float configured_ui_scale(float fallback);
float window_display_scale(SDL_Window *window);
void capture_window_state(SDL_Window *window, UiState &ui);
void show_executable_dialog(UiState &ui);
void show_script_dialog(UiState &ui);
float effective_ui_scale(const UiState &ui);
void apply_ui_style(bool dark, float scale);
void load_ui_fonts(UiState &ui);
void select_ui_font(UiState &ui);
void register_ui_settings(UiState &ui);
std::string migrate_window_layout(std::string_view layout);
std::uint32_t panel_visibility(const UiState &ui);
bool follow_address(const debugger::SessionSnapshot &snapshot,
                    debugger::LldbEngine &engine, UiState &ui,
                    std::uint64_t address);
bool navigation_input_allowed(const UiState &ui);
void dispatch_navigation_shortcuts(const debugger::SessionSnapshot &snapshot,
                                   debugger::LldbEngine &engine, UiState &ui,
                                   bool decompiler_view, bool control_lease);
std::string keybinding_name(const UiState &ui, DebugAction action);
void dispatch_debugger_shortcuts(const debugger::SessionSnapshot &snapshot,
                                 debugger::LldbEngine &engine,
                                 const UiState &ui, bool control_lease);
void ui_focus_navigation_target(AppNavigationTarget target);
void ui_capture_keybinding(UiState &ui);
void ui_restore_keybindings(UiState &ui);

} // namespace mydbg::app
