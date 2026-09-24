#include "app/AppMenus.h"
#include "app/AppActions.h"
#include "app/AppState.h"
#include "app/HelpSystem.h"
#include "app/UiSupport.h"
#include "plugins/PluginApi.h"

#include <imgui_internal.h>

#include <algorithm>
#include <cmath>

namespace mydbg::app {

void draw_navigation_dialog(const debugger::SessionSnapshot &snapshot,
                            debugger::LldbEngine &engine, UiState &ui) {
  if (ui.navigation_dialog_requested) {
    ImGui::OpenPopup(l10n::label(l10n::Key::GuiSupportNavigateAddress));
    ui.navigation_dialog_requested = false;
    ui.navigation_dialog_open = true;
  }
  ImGui::SetNextWindowSize(ImVec2(480.0F, 0.0F), ImGuiCond_Appearing);
  if (!ImGui::BeginPopupModal(l10n::label(l10n::Key::GuiSupportNavigateAddress),
                              nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    return;
  }
  const char *origin = l10n::label(ui.navigation_dialog_decompiler_view
                                       ? l10n::Key::WindowDecompiler
                                       : l10n::Key::WindowDisassembly);
  if (!ui.navigation_dialog_open ||
      ui.navigation_dialog_generation != snapshot.generation) {
    ui.navigation_dialog_open = false;
    ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
    ImGui::SetWindowFocus(origin);
    return;
  }
  if (ImGui::IsWindowAppearing()) {
    ImGui::SetKeyboardFocusHere();
  }
  const bool submitted = ImGui::InputText(
      l10n::label(l10n::Key::GuiSupportNavigationAddress),
      ui.navigation_address.data(), ui.navigation_address.size(),
      ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
  ImGui::TextWrapped("%s",
                     l10n::text(l10n::Key::GuiSupportNavigationAddressHint));
  const bool valid_session = app_navigation_session_valid(snapshot, ui);
  if (!valid_session) {
    ImGui::TextColored(
        ImVec4(1.0F, 0.35F, 0.35F, 1.0F), "%s",
        l10n::text(l10n::Key::GuiSupportNavigationStoppedRequired));
  }
  if (!ui.navigation_address_error.empty()) {
    ImGui::TextColored(ImVec4(1.0F, 0.35F, 0.35F, 1.0F), "%s",
                       ui.navigation_address_error.c_str());
  }
  const char *focus_after_close = nullptr;
  ImGui::BeginDisabled(!valid_session);
  const bool go = ImGui::Button(l10n::label(l10n::Key::GuiSupportNavigationGo));
  if (valid_session && (submitted || go)) {
    const AppNavigationResult navigation =
        app_submit_navigation_address(snapshot, engine, ui);
    if (navigation.target != AppNavigationTarget::None) {
      ui_focus_navigation_target(navigation.target);
      const bool code =
          app_navigation_address_is_code(snapshot, navigation.address);
      focus_after_close =
          code ? origin : l10n::label(l10n::Key::WindowMemoryDump);
      ui.navigation_dialog_open = false;
      ImGui::CloseCurrentPopup();
    }
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  if (ImGui::Button(l10n::label(l10n::Key::GuiSupportCancel)) ||
      ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
    ui.navigation_dialog_open = false;
    ui.navigation_address_error.clear();
    focus_after_close = origin;
    ImGui::CloseCurrentPopup();
  }
  ImGui::EndPopup();
  if (focus_after_close != nullptr) {
    ImGui::SetWindowFocus(focus_after_close);
  }
}

void draw_breakpoint_context_actions(const debugger::SessionSnapshot &snapshot,
                                     debugger::LldbEngine &engine, UiState &ui,
                                     std::uint64_t address) {
  const debugger::BreakpointInfo *breakpoint =
      breakpoint_info_at(snapshot, address);
  if (breakpoint != nullptr) {
    if (ImGui::MenuItem(l10n::label(l10n::Key::GuiSupportRemoveBreakpoint),
                        "F2"))
      engine.remove_breakpoint(breakpoint->id);
    if (ImGui::MenuItem(
            l10n::label(l10n::Key::GuiSupportEditConditionalBreakpoint)))
      request_existing_condition_editor(ui, *breakpoint);
    return;
  }
  if (ImGui::MenuItem(l10n::label(l10n::Key::GuiSupportSetBreakpoint), "F2"))
    engine.set_breakpoint(address_specification(address));
  if (ImGui::MenuItem(
          l10n::label(l10n::Key::GuiSupportSetConditionalBreakpoint)))
    request_new_condition_editor(ui, address);
}

void draw_pointer_context_actions(const debugger::SessionSnapshot &snapshot,
                                  debugger::LldbEngine &engine, UiState &ui,
                                  std::uint64_t address) {
  if (ImGui::MenuItem(l10n::label(l10n::Key::GuiSupportFollowDisassembly)))
    follow_disassembly(engine, ui, address);
  if (ImGui::MenuItem(l10n::label(l10n::Key::GuiSupportFollowMemoryDump)))
    follow_memory(engine, ui, address);
  if (ImGui::MenuItem(l10n::label(l10n::Key::GuiSupportShowMemoryMap)))
    show_in_memory_map(ui, address);
  ImGui::Separator();
  draw_breakpoint_context_actions(snapshot, engine, ui, address);
}

void draw_instruction_patch_editor(const debugger::SessionSnapshot &snapshot,
                                   debugger::LldbEngine &engine, UiState &ui) {
  if (ui.instruction_patch_editor_requested) {
    ImGui::OpenPopup(l10n::label(l10n::Key::GuiSupportPatchInstruction));
    ui.instruction_patch_editor_requested = false;
  }
  ImGui::SetNextWindowSize(ImVec2(580.0F, 0.0F), ImGuiCond_Appearing);
  if (!ImGui::BeginPopupModal(
          l10n::label(l10n::Key::GuiSupportPatchInstruction), nullptr,
          ImGuiWindowFlags_AlwaysAutoResize)) {
    return;
  }

  const bool valid_session = app_instruction_patch_session_valid(snapshot, ui);
  ImGui::Text(l10n::text(l10n::Key::GuiSupportPatchAddress),
              ui.instruction_patch_address
                  ? address_specification(*ui.instruction_patch_address).c_str()
                  : "-");
  ImGui::Text(l10n::text(l10n::Key::GuiSupportOriginalBytes),
              bytes_as_hex(ui.instruction_patch_original).c_str());
  const char *label = ui.instruction_patch_assemble
                          ? l10n::label(l10n::Key::GuiSupportIntelInstruction)
                          : l10n::label(l10n::Key::GuiSupportHexBytes);
  const bool submitted = ImGui::InputText(
      label, ui.instruction_patch_text.data(), ui.instruction_patch_text.size(),
      ImGuiInputTextFlags_EnterReturnsTrue);
  if (ui.instruction_patch_assemble) {
    ImGui::TextDisabled("%s",
                        l10n::text(l10n::Key::GuiSupportPatchOverwriteHint));
  } else {
    ImGui::TextDisabled("%s", l10n::text(l10n::Key::GuiSupportHexBytesHint));
  }
  if (!valid_session) {
    ImGui::TextColored(ImVec4(1.0F, 0.35F, 0.35F, 1.0F), "%s",
                       l10n::text(l10n::Key::GuiSupportPatchStoppedRequired));
  }
  if (!ui.instruction_patch_error.empty()) {
    ImGui::TextColored(ImVec4(1.0F, 0.35F, 0.35F, 1.0F), "%s",
                       ui.instruction_patch_error.c_str());
  }

  ImGui::BeginDisabled(!valid_session);
  const bool apply_clicked =
      ImGui::Button(l10n::label(l10n::Key::GuiSupportApply));
  if (submitted || apply_clicked) {
    if (app_apply_instruction_patch(engine, ui)) {
      ImGui::CloseCurrentPopup();
    }
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  if (ImGui::Button(l10n::label(l10n::Key::GuiSupportCancel))) {
    app_close_instruction_patch_editor(ui);
    ImGui::CloseCurrentPopup();
  }
  ImGui::EndPopup();
}

void debug_action_menu_item(const char *label, DebugAction action,
                            const debugger::SessionSnapshot &snapshot,
                            debugger::LldbEngine &engine, const UiState &ui) {
  const std::string shortcut = keybinding_name(ui, action);
  if (!ImGui::MenuItem(label, shortcut.empty() ? nullptr : shortcut.c_str(),
                       false, debug_action_enabled(action, snapshot, ui))) {
    return;
  }
  execute_debug_action(action, snapshot, engine, ui);
}

void draw_keybindings_settings(UiState &ui) {
  if (!ui.show_keybindings) {
    ui.keybinding_capture.reset();
    return;
  }
  if (!ImGui::Begin(l10n::label(l10n::Key::WindowKeybindings),
                    &ui.show_keybindings)) {
    ImGui::End();
    return;
  }
  ImGui::TextWrapped(l10n::text(l10n::Key::GuiSupportBindingFocusHelp),
                     l10n::text(l10n::Key::WindowPythonDebugger));
  ImGui::TextWrapped("%s",
                     l10n::text(l10n::Key::GuiSupportNavigationCaptureHelp));
  if (ImGui::Button(l10n::label(l10n::Key::GuiSupportRestoreDefaults))) {
    ui_restore_keybindings(ui);
  }
  if (!ui.keybinding_message.empty()) {
    ImGui::SameLine();
    ImGui::TextDisabled("%s", ui.keybinding_message.c_str());
  }
  if (ImGui::BeginTable("keybinding-table", 4,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                            ImGuiTableFlags_Resizable |
                            ImGuiTableFlags_ScrollY)) {
    ImGui::TableSetupColumn(l10n::text(l10n::Key::GuiSupportContextColumn));
    ImGui::TableSetupColumn(l10n::text(l10n::Key::GuiSupportCommandColumn));
    ImGui::TableSetupColumn(l10n::text(l10n::Key::GuiSupportBindingColumn));
    ImGui::TableSetupColumn(l10n::text(l10n::Key::GuiSupportDefaultColumn));
    ImGui::TableHeadersRow();
    const auto draw_action = [&](const char *context, const auto &action,
                                 ImGuiKeyChord binding,
                                 std::size_t capture_index) {
      ImGui::PushID(static_cast<int>(capture_index));
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextUnformatted(context);
      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(l10n::text(action.label));
      ImGui::TableSetColumnIndex(2);
      const bool capturing = ui.keybinding_capture == capture_index;
      const char *binding_text =
          capturing      ? l10n::text(l10n::Key::GuiSupportPressKeys)
          : binding == 0 ? l10n::text(l10n::Key::GuiSupportUnbound)
                         : ImGui::GetKeyChordName(binding);
      const std::string current = std::string{binding_text} + "###binding";
      if (ImGui::Button(current.c_str())) {
        ui.keybinding_capture = capture_index;
        ui.keybinding_capture_frame = ImGui::GetFrameCount();
        ui.keybinding_message.clear();
      }
      ImGui::TableSetColumnIndex(3);
      if (action.default_binding == 0) {
        ImGui::TextDisabled("%s", l10n::text(l10n::Key::GuiSupportNoBinding));
      } else {
        ImGui::TextUnformatted(ImGui::GetKeyChordName(action.default_binding));
      }
      ImGui::PopID();
    };
    for (std::size_t index = 0; index < debug_actions.size(); ++index) {
      draw_action(l10n::text(l10n::Key::GuiSupportNativeContext),
                  debug_actions[index], ui.keybindings[index], index);
    }
    for (std::size_t index = 0; index < script_actions.size(); ++index) {
      draw_action(l10n::text(l10n::Key::GuiSupportPythonContext),
                  script_actions[index], ui.script_keybindings[index],
                  debug_actions.size() + index);
    }
    for (std::size_t index = 0; index < navigation_actions.size(); ++index) {
      draw_action(l10n::text(l10n::Key::GuiSupportNavigationContext),
                  navigation_actions[index], ui.navigation_keybindings[index],
                  debug_actions.size() + script_actions.size() + index);
    }
    ImGui::EndTable();
  }

  ui_capture_keybinding(ui);
  ImGui::End();
}

void draw_debugger_menu(const debugger::SessionSnapshot &snapshot,
                        debugger::LldbEngine &engine, UiState &ui,
                        debugger::help::HelpSystem &help, bool control_lease) {
  if (!ImGui::BeginMainMenuBar()) {
    return;
  }
  if (ImGui::BeginMenu(l10n::label(l10n::Key::GuiSupportDebuggerMenu))) {
    const auto action_item = [&](DebugAction action,
                                 const char *label = nullptr) {
      debug_action_menu_item(
          label ? label
                : l10n::label(debug_actions[action_index(action)].label),
          action, snapshot, engine, ui);
    };
    ImGui::BeginDisabled(control_lease);
    action_item(DebugAction::StartContinue,
                l10n::label(can_terminate(snapshot)
                                ? l10n::Key::GuiSupportContinue
                                : l10n::Key::GuiSupportStart));
    action_item(DebugAction::StartMain);
    action_item(DebugAction::StartEntry);
    ImGui::Separator();
    action_item(DebugAction::ToggleBreakpoint);
    action_item(DebugAction::RunToCursor);
    ImGui::Separator();
    action_item(DebugAction::SourceStepInto);
    action_item(DebugAction::SourceStepOver);
    action_item(DebugAction::InstructionStepInto);
    action_item(DebugAction::InstructionStepOver);
    action_item(DebugAction::FinishFunction);
    if (ImGui::BeginMenu(
            l10n::label(l10n::Key::GuiSupportRunUntil),
            debug_action_enabled(DebugAction::NextCall, snapshot, ui))) {
      action_item(DebugAction::NextCall,
                  l10n::label(l10n::Key::GuiSupportNextCall));
      action_item(DebugAction::NextBranch,
                  l10n::label(l10n::Key::GuiSupportNextBranch));
      action_item(DebugAction::NextReturn,
                  l10n::label(l10n::Key::GuiSupportNextReturn));
      action_item(DebugAction::NextSystemCall,
                  l10n::label(l10n::Key::GuiSupportNextSystemCall));
      ImGui::EndMenu();
    }
    ImGui::EndDisabled();
    ImGui::Separator();
    action_item(DebugAction::Pause);
    action_item(DebugAction::Terminate);
    ImGui::EndMenu();
  }
  if (ImGui::BeginMenu(l10n::label(l10n::Key::GuiSupportViewMenu))) {
    for (const auto &panel : ui_panel_settings) {
      ImGui::MenuItem(l10n::label(panel.label), nullptr, &(ui.*panel.visible));
    }
    ImGui::EndMenu();
  }
  if (ImGui::BeginMenu(l10n::label(l10n::Key::GuiSupportSettingsMenu))) {
    if (ImGui::BeginMenu(l10n::label(l10n::Key::GuiSupportThemeMenu))) {
      const auto theme_option = [&ui, &engine](const char *label, bool dark) {
        if (ImGui::MenuItem(label, nullptr, ui.theme_dark == dark)) {
          app_select_theme(engine, ui, dark);
          ImGui::MarkIniSettingsDirty();
        }
      };
      theme_option(l10n::label(l10n::Key::GuiSupportDarkTheme), true);
      theme_option(l10n::label(l10n::Key::GuiSupportLightTheme), false);
      ImGui::EndMenu();
    }
    if (ImGui::BeginMenu(l10n::label(l10n::Key::GuiSupportUiScaleMenu))) {
      const auto scale_option = [&ui](const char *label, float scale) {
        const bool selected = std::abs(ui.user_scale - scale) < 0.01F;
        if (ImGui::MenuItem(label, nullptr, selected)) {
          ui.user_scale = scale;
          ImGui::MarkIniSettingsDirty();
        }
      };
      scale_option(l10n::label(l10n::Key::GuiSupportScaleSeventyFive), 0.75F);
      scale_option(l10n::label(l10n::Key::GuiSupportScaleOneHundred), 1.0F);
      scale_option(l10n::label(l10n::Key::GuiSupportScaleOneHundredTwentyFive),
                   1.25F);
      scale_option(l10n::label(l10n::Key::GuiSupportScaleOneHundredFifty),
                   1.5F);
      scale_option(l10n::label(l10n::Key::GuiSupportScaleOneHundredSeventyFive),
                   1.75F);
      scale_option(l10n::label(l10n::Key::GuiSupportScaleTwoHundred), 2.0F);
      scale_option(l10n::label(l10n::Key::GuiSupportScaleTwoHundredFifty),
                   2.5F);
      scale_option(l10n::label(l10n::Key::GuiSupportScaleThreeHundred), 3.0F);
      ImGui::Separator();
      ImGui::TextDisabled(l10n::text(l10n::Key::GuiSupportScaleSummary),
                          static_cast<double>(ui.display_scale * 100.0F),
                          static_cast<double>(effective_ui_scale(ui) * 100.0F));
      ImGui::EndMenu();
    }
    if (ImGui::BeginMenu(l10n::label(l10n::Key::GuiSupportFontMenu))) {
      for (const UiFontChoice &choice : ui.fonts) {
        if (ImGui::MenuItem(choice.label.c_str(), nullptr,
                            ui.font_id == choice.id)) {
          ui.font_id = choice.id;
          ImGui::GetIO().FontDefault = choice.font;
          ImGui::MarkIniSettingsDirty();
        }
      }
      ImGui::EndMenu();
    }
    if (ImGui::MenuItem(l10n::label(l10n::Key::GuiSupportKeybindingsMenu),
                        nullptr, &ui.show_keybindings)) {
      ui.keybinding_message.clear();
    }
    ImGui::Separator();
    ImGui::TextDisabled(l10n::text(l10n::Key::GuiSupportSettingsSavedIn),
                        ImGui::GetIO().IniFilename);
    ImGui::EndMenu();
  }
  const auto plugin_surfaces =
      debugger::plugins::PluginRegistry::instance().surfaces();
  if (std::any_of(plugin_surfaces.begin(), plugin_surfaces.end(),
                  [](const debugger::plugins::SurfaceRegistration &surface) {
                    return surface.surface == debugger::plugins::Surface::Menu;
                  }) &&
      ImGui::BeginMenu(l10n::label(l10n::Key::GuiSupportPluginsMenu))) {
    for (const auto &surface : plugin_surfaces) {
      if (surface.surface == debugger::plugins::Surface::Menu) {
        surface.callback(snapshot, engine);
      }
    }
    ImGui::EndMenu();
  }
  if (ImGui::BeginMenu(l10n::label(l10n::Key::GuiSupportHelpMenu))) {
    if (ImGui::MenuItem(l10n::label(l10n::Key::WindowDebuggerManual), "F1"))
      help.open();
    if (ImGui::MenuItem(
            l10n::label(l10n::Key::GuiSupportConditionalBreakpointsHelp)))
      help.open("04-breakpoints.md");
    ImGui::EndMenu();
  }
  if (!ImGui::GetIO().WantTextInput &&
      ImGui::Shortcut(ImGuiKey_F1, ImGuiInputFlags_RouteGlobal)) {
    help.open();
  }
  ImGui::EndMainMenuBar();
}

} // namespace mydbg::app
