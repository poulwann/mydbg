#pragma once

#include "app/DecompilerController.h"
#include "app/MemoryData.h"
#include "backend/decompiler/DecompilerEngine.h"
#include "backend/lldb/LldbEngine.h"
#include "localization/Localization.h"

#include <TextEditor.h>
#include <imgui.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct SDL_Window;

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

struct MemoryTypeHint {
  std::uint64_t address{};
  std::string label;
  std::string type;
  bool string{};
  std::string module_path;
};

struct DisassemblyGraphView;
struct DisassemblyTextCache;

struct NavigationLocation {
  std::uint64_t address{};
  std::optional<std::uint64_t> decompiler_function{};
  std::optional<std::size_t> decompiler_line{};
  std::optional<std::size_t> decompiler_span{};
};

struct UiState {
  std::array<char, 4096> executable_path{};
  std::array<char, 4096> script_path{};
  std::uint64_t attach_process_id{};
  std::array<char, 256> remote_endpoint{};
  int remote_profile{};
  debugger::SessionIdentity observed_session;
  debugger::SessionStatus session_status;
  debugger::CommandTicket session_clear;
  std::string session_action_message;
  std::optional<std::uint64_t> comment_address;
  std::uint64_t comment_generation{};
  debugger::SessionIdentity comment_session;
  std::array<char, 65537> comment_text{};
  bool comment_editor_requested{};
  debugger::CommandTicket comment_write;
  std::string comment_error;
  bool remote_endpoint_initialized{};
  std::array<char, 256> breakpoint_specification{};
  std::array<char, 128> memory_address{};
  std::array<char, 1024> console_command{};
  std::array<char, 4096> breakpoint_condition{};
  std::array<char, 256> binary_string_filter{};
  std::array<char, 128> value_scan_value{};
  std::array<char, 1024> instruction_patch_text{};
  std::optional<std::uint64_t> instruction_patch_address;
  std::vector<std::uint8_t> instruction_patch_original;
  std::uint64_t instruction_patch_generation{};
  bool instruction_patch_assemble{};
  bool instruction_patch_editor_requested{};
  std::string instruction_patch_error;
  std::string register_edit_name;
  std::array<char, 4096> register_edit_text{};
  std::uint64_t register_edit_revision{};
  bool register_edit_focus{};
  debugger::CommandTicket register_write;
  std::string register_write_name;
  std::string register_edit_error;
  bool memory_edit_mode{};
  std::uint64_t memory_edit_base{};
  std::vector<std::uint8_t> memory_edit_source;
  std::array<std::array<char, 3>, 256> memory_edit_bytes{};
  std::optional<std::size_t> memory_edit_focus;
  std::string memory_edit_error;
  std::uint64_t memory_selection_generation{};
  std::uint64_t memory_selection_base{};
  std::size_t memory_selection_size{};
  std::optional<std::size_t> memory_selection_anchor;
  std::optional<std::size_t> memory_selection_end;
  bool memory_selection_dragging{};
  MemoryByteOrder memory_copy_order{MemoryByteOrder::AsStored};
  std::size_t memory_copy_word_size{4};
  std::vector<MemoryTypeHint> memory_type_hints;
  std::uint64_t memory_hints_serial{};
  std::optional<DecompilerTarget> decompiler_target;
  std::optional<DecompilerTarget> decompiler_context_target;
  std::optional<std::uint64_t> decompiler_context_load_address;
  std::optional<std::size_t> decompiler_selection_anchor;
  std::optional<std::size_t> decompiler_selection_start;
  std::optional<std::size_t> decompiler_selection_end;
  std::optional<std::size_t> decompiler_keyboard_line;
  std::optional<std::size_t> decompiler_keyboard_span;
  std::optional<std::uint64_t> decompiler_keyboard_function;
  std::uint64_t decompiler_keyboard_cursor{};
  std::uint64_t decompiler_target_serial{};
  DecompilerDialog decompiler_dialog{DecompilerDialog::None};
  std::array<char, 256> decompiler_name_text{};
  std::array<char, 1024> decompiler_type_text{};
  std::string decompiler_message;
  SDL_Window *main_window{};
  std::mutex file_dialog_mutex;
  std::optional<std::string> selected_executable;
  std::optional<std::string> selected_script;
  std::string file_dialog_error;
  std::string file_dialog_location;
  bool file_dialog_open{};
  bool script_dialog{};
  std::string python_console_message;
  TextEditor script_editor;
  TextEditor::Breakpoints script_breakpoints;
  std::string script_loaded_path;
  std::string script_file_error;
  bool script_dirty{};
  bool script_editor_initialized{};
  bool script_editor_theme_dark{};
  std::size_t selected_script_frame{};
  std::uint32_t script_execution_line{};
  int window_x{};
  int window_y{};
  int window_width{1440};
  int window_height{900};
  bool window_position_saved{};
  bool window_maximized{};
  std::optional<std::uint32_t> editing_breakpoint;
  std::optional<std::uint64_t> creating_conditional_breakpoint;
  bool condition_editor_requested{};
  std::uint64_t disassembly_cursor{};
  std::uint64_t cursor_generation{};
  std::uint64_t cursor_stop_revision{};
  std::string breakpoint_condition_error;
  std::uint64_t disassembly_scroll_generation{};
  std::uint64_t disassembly_scroll_stop_revision{};
  std::optional<std::uint64_t> disassembly_scroll_target;
  bool disassembly_graph_view{};
  std::optional<bool> disassembly_graph_enabled;
  std::shared_ptr<DisassemblyGraphView> disassembly_graph_state;
  std::shared_ptr<DisassemblyTextCache> disassembly_text_cache;
  std::uint64_t decompiler_scroll_selection{};
  std::array<NavigationLocation, 256> navigation_history{};
  std::optional<NavigationLocation> navigation_source_restore;
  std::size_t navigation_history_size{};
  std::size_t navigation_history_index{};
  bool navigation_follow_requested{};
  int navigation_dispatch_frame{-1};
  bool navigation_control_locked{};
  bool navigation_dialog_requested{};
  bool navigation_dialog_decompiler_view{};
  bool navigation_dialog_open{};
  std::uint64_t navigation_dialog_generation{};
  std::array<char, 64> navigation_address{};
  std::string navigation_address_error;
  std::optional<std::uint64_t> memory_map_address;
  bool scroll_memory_map_to_address{};
  bool show_threads{};
  bool show_backtrace{};
  bool show_stack{};
  bool show_memory_map{};
  bool show_modules{};
  bool show_security{};
  bool show_heap{};
  bool show_scans{true};
  int binary_string_minimum_length{4};
  bool binary_string_include_utf16{true};
  debugger::ValueScanType value_scan_type{debugger::ValueScanType::Dword};
  debugger::ValueScanComparison value_scan_comparison{
      debugger::ValueScanComparison::Exact};
  bool value_scan_unknown{};
  bool value_scan_signed{};
  bool value_scan_writable_only{true};
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
  bool python_window_focused{};
  std::optional<std::size_t> keybinding_capture;
  int keybinding_capture_frame{-1};
  std::string keybinding_message;
  bool show_keybindings{};
  std::optional<std::uint64_t> selected_history_generation;
  std::optional<std::uint64_t> selected_history_stop;
};

} // namespace mydbg::app
