#pragma once

#include "localization/Localization.h"

#include <imgui.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace mydbg::app {

struct UiFontChoice {
  std::string id;
  std::string label;
  ImFont *font{};
};

enum class DebugAction : std::size_t {
  StartContinue,
  Pause,
  Terminate,
  StartMain,
  StartEntry,
  ToggleBreakpoint,
  RunToCursor,
  SourceStepInto,
  SourceStepOver,
  InstructionStepInto,
  InstructionStepOver,
  FinishFunction,
  NextCall,
  NextBranch,
  NextReturn,
  NextSystemCall,
  Count,
};
enum class ScriptAction : std::size_t {
  DebugContinue,
  Run,
  ToggleBreakpoint,
  StepInto,
  StepOver,
  StepOut,
  Pause,
  Stop,
  Count,
};
enum class NavigationAction : std::size_t {
  Back,
  Forward,
  Follow,
  JumpAddress,
  ToggleGraph,
  SwitchView,
  MouseBack,
  MouseForward,
  Count,
};

template <typename Action> struct ActionDefinition {
  Action action;
  const char *id;
  l10n::Key label;
  ImGuiKeyChord default_binding;
};

using DebugActionDefinition = ActionDefinition<DebugAction>;
using ScriptActionDefinition = ActionDefinition<ScriptAction>;
using NavigationActionDefinition = ActionDefinition<NavigationAction>;

constexpr std::array<DebugActionDefinition,
                     static_cast<std::size_t>(DebugAction::Count)>
    debug_actions{{
        {DebugAction::StartContinue, "start-continue",
         l10n::Key::GuiSupportStartContinue, ImGuiKey_F9},
        {DebugAction::Pause, "pause", l10n::Key::GuiSupportPause, ImGuiKey_F12},
        {DebugAction::Terminate, "terminate", l10n::Key::GuiSupportTerminate,
         ImGuiMod_Ctrl | ImGuiKey_F2},
        {DebugAction::StartMain, "start-main", l10n::Key::GuiSupportStartMain,
         0},
        {DebugAction::StartEntry, "start-entry",
         l10n::Key::GuiSupportStartEntry, 0},
        {DebugAction::ToggleBreakpoint, "toggle-breakpoint",
         l10n::Key::GuiSupportToggleBreakpoint, ImGuiKey_F2},
        {DebugAction::RunToCursor, "run-to-cursor",
         l10n::Key::GuiSupportRunToCursor, ImGuiKey_F4},
        {DebugAction::SourceStepInto, "source-step-into",
         l10n::Key::GuiSupportSourceStepInto, ImGuiKey_F11},
        {DebugAction::SourceStepOver, "source-step-over",
         l10n::Key::GuiSupportSourceStepOver, ImGuiKey_F10},
        {DebugAction::InstructionStepInto, "instruction-step-into",
         l10n::Key::GuiSupportInstructionStepInto, ImGuiKey_F7},
        {DebugAction::InstructionStepOver, "instruction-step-over",
         l10n::Key::GuiSupportInstructionStepOver, ImGuiKey_F8},
        {DebugAction::FinishFunction, "finish-function",
         l10n::Key::GuiSupportFinishFunction, ImGuiMod_Shift | ImGuiKey_F11},
        {DebugAction::NextCall, "next-call", l10n::Key::GuiSupportRunUntilCall,
         ImGuiMod_Shift | ImGuiKey_F7},
        {DebugAction::NextBranch, "next-branch",
         l10n::Key::GuiSupportRunUntilBranch, ImGuiMod_Ctrl | ImGuiKey_F7},
        {DebugAction::NextReturn, "next-return",
         l10n::Key::GuiSupportRunUntilReturn, ImGuiMod_Shift | ImGuiKey_F8},
        {DebugAction::NextSystemCall, "next-system-call",
         l10n::Key::GuiSupportRunUntilSystemCall, ImGuiMod_Ctrl | ImGuiKey_F8},
    }};
constexpr std::array<ScriptActionDefinition,
                     static_cast<std::size_t>(ScriptAction::Count)>
    script_actions{{
        {ScriptAction::DebugContinue, "debug-continue",
         l10n::Key::GuiSupportDebugContinue, ImGuiKey_F9},
        {ScriptAction::Run, "run", l10n::Key::GuiSupportRunWithoutDebugging,
         ImGuiMod_Ctrl | ImGuiKey_F9},
        {ScriptAction::ToggleBreakpoint, "toggle-breakpoint",
         l10n::Key::GuiSupportToggleBreakpoint, ImGuiKey_F2},
        {ScriptAction::StepInto, "step-into", l10n::Key::GuiSupportStepInto,
         ImGuiKey_F11},
        {ScriptAction::StepOver, "step-over", l10n::Key::GuiSupportStepOver,
         ImGuiKey_F10},
        {ScriptAction::StepOut, "step-out", l10n::Key::GuiSupportStepOut,
         ImGuiMod_Shift | ImGuiKey_F11},
        {ScriptAction::Pause, "pause", l10n::Key::GuiSupportPause,
         ImGuiKey_F12},
        {ScriptAction::Stop, "stop", l10n::Key::GuiSupportStopScript,
         ImGuiMod_Ctrl | ImGuiKey_F2},
    }};
constexpr std::array<NavigationActionDefinition,
                     static_cast<std::size_t>(NavigationAction::Count)>
    navigation_actions{{
        {NavigationAction::Back, "back", l10n::Key::GuiSupportNavigateBack,
         ImGuiKey_Escape},
        {NavigationAction::Forward, "forward",
         l10n::Key::GuiSupportNavigateForward, ImGuiMod_Ctrl | ImGuiKey_Enter},
        {NavigationAction::Follow, "follow",
         l10n::Key::GuiSupportNavigateFollow, ImGuiKey_Enter},
        {NavigationAction::JumpAddress, "jump-address",
         l10n::Key::GuiSupportNavigateAddress, ImGuiKey_G},
        {NavigationAction::ToggleGraph, "toggle-graph",
         l10n::Key::GuiSupportNavigateGraph, ImGuiKey_Space},
        {NavigationAction::SwitchView, "switch-view",
         l10n::Key::GuiSupportNavigateSwitchView, ImGuiKey_Tab},
        {NavigationAction::MouseBack, "mouse-back",
         l10n::Key::GuiSupportNavigateMouseBack, ImGuiKey_MouseX1},
        {NavigationAction::MouseForward, "mouse-forward",
         l10n::Key::GuiSupportNavigateMouseForward, ImGuiKey_MouseX2},
    }};

constexpr auto default_keybindings() {
  std::array<ImGuiKeyChord, static_cast<std::size_t>(DebugAction::Count)>
      bindings{};
  for (const DebugActionDefinition &action : debug_actions) {
    bindings[static_cast<std::size_t>(action.action)] = action.default_binding;
  }
  return bindings;
}
constexpr auto default_script_keybindings() {
  std::array<ImGuiKeyChord, static_cast<std::size_t>(ScriptAction::Count)>
      bindings{};
  for (const ScriptActionDefinition &action : script_actions) {
    bindings[static_cast<std::size_t>(action.action)] = action.default_binding;
  }
  return bindings;
}
constexpr auto default_navigation_keybindings() {
  std::array<ImGuiKeyChord, static_cast<std::size_t>(NavigationAction::Count)>
      bindings{};
  for (const NavigationActionDefinition &action : navigation_actions) {
    bindings[static_cast<std::size_t>(action.action)] = action.default_binding;
  }
  return bindings;
}

constexpr std::size_t action_index(DebugAction action) {
  return static_cast<std::size_t>(action);
}
constexpr std::size_t action_index(ScriptAction action) {
  return static_cast<std::size_t>(action);
}
constexpr std::size_t action_index(NavigationAction action) {
  return static_cast<std::size_t>(action);
}

struct WorkspaceState {
  int window_x{};
  int window_y{};
  int window_width{1440};
  int window_height{900};
  bool window_position_saved{};
  bool window_maximized{};
  bool show_threads{};
  bool show_backtrace{};
  bool show_stack{};
  bool show_memory_map{};
  bool show_modules{};
  bool show_security{};
  bool show_heap{};
  bool show_scans{true};
  bool applied_dark_theme{true};
  float display_scale{1.0F};
  float user_scale{1.0F};
  float applied_ui_scale{};
  bool theme_dark{true};
  bool theme_sync_pending{};
  std::string font_id{"proggy-vector"};
  std::vector<UiFontChoice> fonts;
  std::array<ImGuiKeyChord, static_cast<std::size_t>(DebugAction::Count)>
      keybindings{default_keybindings()};
  std::array<ImGuiKeyChord, static_cast<std::size_t>(ScriptAction::Count)>
      script_keybindings{default_script_keybindings()};
  std::array<ImGuiKeyChord, static_cast<std::size_t>(NavigationAction::Count)>
      navigation_keybindings{default_navigation_keybindings()};
  std::optional<std::size_t> keybinding_capture;
  int keybinding_capture_frame{-1};
  std::string keybinding_message;
  bool show_keybindings{};
};

} // namespace mydbg::app
