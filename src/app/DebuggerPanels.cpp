#include "app/AppState.h"

#include "app/AppActions.h"
#include "app/AppMenus.h"
#include "app/DebuggerController.h"
#include "app/DebuggerPanels.h"
#include "app/DisassemblyGraph.h"
#include "app/DisassemblyText.h"
#include "app/DisassemblyTextDrawing.h"
#include "app/UiSupport.h"
#include "localization/Localization.h"
#include <imgui_internal.h>

#include <algorithm>
#include <cstdio>
#include <sstream>
#include <string_view>
#include <utility>

#include <cinttypes>
namespace mydbg::app {

void draw_error_text(const std::string &error) {
  if (!error.empty())
    ImGui::TextColored(ImVec4(1.0F, 0.35F, 0.35F, 1.0F), "%s", error.c_str());
}

namespace {
bool begin_optional_panel(l10n::Key title, bool &visible) {
  if (!visible)
    return false;
  if (ImGui::Begin(l10n::label(title), &visible))
    return true;
  ImGui::End();
  return false;
}

bool begin_detail_table(const char *id, int columns) {
  return ImGui::BeginTable(id, columns,
                           ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                               ImGuiTableFlags_ScrollY |
                               ImGuiTableFlags_Resizable);
}

const char *session_state_text(debugger::SessionState state) {
  switch (state) {
  case debugger::SessionState::Initializing:
    return l10n::text(l10n::Key::GuiPanelsSessionStateInitializing);
  case debugger::SessionState::NoTarget:
    return l10n::text(l10n::Key::GuiPanelsSessionStateNoTarget);
  case debugger::SessionState::TargetLoaded:
    return l10n::text(l10n::Key::GuiPanelsSessionStateTargetLoaded);
  case debugger::SessionState::Launching:
    return l10n::text(l10n::Key::GuiPanelsSessionStateLaunching);
  case debugger::SessionState::Connecting:
    return l10n::text(l10n::Key::GuiPanelsSessionStateConnecting);
  case debugger::SessionState::Running:
    return l10n::text(l10n::Key::GuiPanelsSessionStateRunning);
  case debugger::SessionState::Stopped:
    return l10n::text(l10n::Key::GuiPanelsSessionStateStopped);
  case debugger::SessionState::Exited:
    return l10n::text(l10n::Key::GuiPanelsSessionStateExited);
  case debugger::SessionState::Error:
    return l10n::text(l10n::Key::GuiPanelsSessionStateError);
  case debugger::SessionState::ShuttingDown:
    return l10n::text(l10n::Key::GuiPanelsSessionStateShuttingDown);
  }
  return l10n::text(l10n::Key::GuiPanelsSessionUnknown);
}

const char *session_mode_text(debugger::SessionMode mode) {
  switch (mode) {
  case debugger::SessionMode::Local:
    return l10n::text(l10n::Key::GuiPanelsSessionModeLocal);
  case debugger::SessionMode::Remote:
    return l10n::text(l10n::Key::GuiPanelsSessionModeRemote);
  case debugger::SessionMode::QemuUser:
    return l10n::text(l10n::Key::GuiPanelsSessionModeQemuUser);
  case debugger::SessionMode::QemuSystem:
    return l10n::text(l10n::Key::GuiPanelsSessionModeQemuSystem);
  }
  return l10n::text(l10n::Key::GuiPanelsSessionUnknown);
}

} // namespace

const char *byte_order_text(const std::string &order) {
  if (order == "little") {
    return l10n::text(l10n::Key::GuiPanelsByteOrderLittle);
  }
  if (order == "big") {
    return l10n::text(l10n::Key::GuiPanelsByteOrderBig);
  }
  if (order == "PDP") {
    return l10n::text(l10n::Key::GuiPanelsByteOrderPdp);
  }
  if (order == "invalid") {
    return l10n::text(l10n::Key::GuiPanelsByteOrderInvalid);
  }
  if (order == "unknown") {
    return l10n::text(l10n::Key::GuiPanelsByteOrderUnknown);
  }
  return order.c_str();
}

void draw_session_panel(const debugger::SessionSnapshot &snapshot,
                        debugger::LldbEngine &engine, UiState &ui,
                        bool control_lease) {
  ImGui::Begin(l10n::label(l10n::Key::WindowSession));
  const auto session_input = debugger_sync_session_input(ui);

  ImGui::TextUnformatted(l10n::text(l10n::Key::GuiPanelsExecutable));
  const float browse_width =
      ImGui::CalcTextSize(l10n::text(l10n::Key::GuiPanelsBrowse)).x +
      ImGui::GetStyle().FramePadding.x * 2.0F;
  ImGui::SetNextItemWidth(-(browse_width + ImGui::GetStyle().ItemSpacing.x));
  ImGui::InputText("##elf-executable", ui.executable_path.data(),
                   ui.executable_path.size());
  ImGui::SameLine();
  ImGui::BeginDisabled(session_input.file_dialog_open);
  if (ImGui::Button(session_input.file_dialog_open
                        ? l10n::label(l10n::Key::GuiPanelsSelectingExecutable)
                        : l10n::label(l10n::Key::GuiPanelsBrowse))) {
    show_executable_dialog(ui);
  }
  ImGui::EndDisabled();
  draw_error_text(session_input.file_dialog_error);
  ImGui::SeparatorText(l10n::text(l10n::Key::GuiSessionSavedState));
  if (!snapshot.session.sha256.empty()) {
    ImGui::TextDisabled(l10n::text(l10n::Key::GuiSessionHash),
                        snapshot.session.sha256.c_str());
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("%s", snapshot.session.sha256.c_str());
    ImGui::TextWrapped(
        l10n::text(l10n::Key::GuiSessionCounts),
        ui.session_status.breakpoint_count, ui.session_status.watch_count,
        ui.session_status.edit_count, ui.session_status.comment_count);
    const bool clearable =
        snapshot.state == debugger::SessionState::Stopped ||
        snapshot.state == debugger::SessionState::TargetLoaded ||
        snapshot.state == debugger::SessionState::Exited ||
        snapshot.state == debugger::SessionState::Error;
    ImGui::BeginDisabled(control_lease || !clearable ||
                         ui.session_clear.valid());
    if (ImGui::Button(l10n::label(l10n::Key::GuiSessionClear))) {
      ui.session_action_message.clear();
      ui.session_clear = engine.clear_saved_session(snapshot.session.sha256);
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
      ImGui::SetTooltip("%s", l10n::text(l10n::Key::GuiSessionClearHelp));
    if (ui.session_status.writable && ui.session_status.error.empty())
      ImGui::TextDisabled("%s", l10n::text(l10n::Key::GuiSessionAutosaved));
  } else {
    ImGui::TextDisabled("%s", l10n::text(l10n::Key::GuiSessionUnavailable));
  }
  if (!ui.session_status.error.empty())
    ImGui::TextWrapped(l10n::text(l10n::Key::GuiSessionStorageError),
                       ui.session_status.error.c_str());
  if (!snapshot.session_error.empty())
    ImGui::TextWrapped("%s", snapshot.session_error.c_str());
  if (!ui.session_action_message.empty())
    ImGui::TextWrapped("%s", ui.session_action_message.c_str());
  ImGui::SeparatorText(l10n::text(l10n::Key::GuiPanelsLocalProcess));
  ImGui::BeginDisabled(control_lease);
  if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsLaunchRestart))) {
    engine.launch(ui.executable_path.data());
  }
  if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
    ImGui::SetTooltip("%s", l10n::text(l10n::Key::GuiPanelsLaunchHelp));
  }
  const bool continue_session = can_terminate(snapshot);
  const std::string shortcut = keybinding_name(ui, DebugAction::StartContinue);
  const char *start_text =
      l10n::text(continue_session ? l10n::Key::GuiPanelsContinue
                                  : l10n::Key::GuiPanelsStart);
  const std::string start_label =
      (shortcut.empty() ? std::string{start_text}
                        : l10n::format(l10n::Key::GuiPanelsActionWithShortcut,
                                       start_text, shortcut.c_str())) +
      "###start-continue";
  ImGui::BeginDisabled(!can_start_or_continue(snapshot, ui));
  if (ImGui::Button(start_label.c_str())) {
    start_or_continue(snapshot, engine, ui);
  }
  if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
    ImGui::SetTooltip("%s", continue_session
                                ? l10n::text(l10n::Key::GuiPanelsContinueHelp)
                                : l10n::text(l10n::Key::GuiPanelsStartHelp));
  }
  ImGui::EndDisabled();
  ImGui::EndDisabled();
  ImGui::SameLine();
  ImGui::BeginDisabled(snapshot.state != debugger::SessionState::Running);
  if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsPause))) {
    engine.stop();
  }
  ImGui::EndDisabled();
  ImGui::TextUnformatted(l10n::text(l10n::Key::GuiPanelsProcessId));
  ImGui::SetNextItemWidth(
      -(ImGui::CalcTextSize(l10n::text(l10n::Key::GuiPanelsAttach)).x +
        ImGui::GetStyle().FramePadding.x * 2.0F +
        ImGui::GetStyle().ItemSpacing.x));
  ImGui::InputScalar("##attach-pid", ImGuiDataType_U64, &ui.attach_process_id);
  ImGui::SameLine();
  ImGui::BeginDisabled(control_lease || ui.attach_process_id == 0);
  if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsAttach))) {
    engine.attach(ui.attach_process_id);
  }
  ImGui::EndDisabled();

  ImGui::SeparatorText(l10n::text(l10n::Key::GuiPanelsRemoteProcess));
  const char *remote_profiles[] = {
      l10n::text(l10n::Key::GuiPanelsRemoteProfileServer),
      l10n::text(l10n::Key::GuiPanelsRemoteProfileQemuUser),
      l10n::text(l10n::Key::GuiPanelsRemoteProfileQemuSystem)};
  ImGui::TextUnformatted(l10n::text(l10n::Key::GuiPanelsProfile));
  ImGui::SetNextItemWidth(-1.0F);
  ImGui::Combo("##remote-profile", &ui.remote_profile, remote_profiles,
               static_cast<int>(std::size(remote_profiles)));
  ImGui::TextUnformatted(l10n::text(l10n::Key::GuiPanelsEndpoint));
  ImGui::SetNextItemWidth(-1.0F);
  ImGui::InputText("##remote-endpoint", ui.remote_endpoint.data(),
                   ui.remote_endpoint.size());
  const debugger::SessionMode remote_mode =
      ui.remote_profile == 1
          ? debugger::SessionMode::QemuUser
          : (ui.remote_profile == 2 ? debugger::SessionMode::QemuSystem
                                    : debugger::SessionMode::Remote);
  ImGui::BeginDisabled(control_lease || ui.remote_endpoint[0] == '\0');
  if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsConnect))) {
    engine.connect_remote(debugger::RemoteOptions{
        .executable = ui.executable_path.data(),
        .endpoint = ui.remote_endpoint.data(),
        .mode = remote_mode,
    });
  }
  ImGui::EndDisabled();
  ImGui::PushStyleColor(ImGuiCol_Text,
                        ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
  if (ui.remote_profile == 1) {
    ImGui::TextWrapped("%s", l10n::text(l10n::Key::GuiPanelsQemuUserHelp));
  } else if (ui.remote_profile == 2) {
    ImGui::TextWrapped("%s", l10n::text(l10n::Key::GuiPanelsQemuSystemHelp));
  } else {
    ImGui::TextWrapped("%s",
                       l10n::text(l10n::Key::GuiPanelsRemoteEndpointHelp));
  }
  ImGui::PopStyleColor();

  const bool stopped = snapshot.state == debugger::SessionState::Stopped;
  ImGui::BeginDisabled(control_lease || !stopped);
  if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsStepInto))) {
    engine.step_instruction(false);
  }
  ImGui::SameLine();
  if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsStepOver))) {
    engine.step_instruction(true);
  }
  if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsToggleBreakpoint))) {
    toggle_cursor_breakpoint(snapshot, engine, ui);
  }
  ImGui::SameLine();
  if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsRunToCursorShortcut))) {
    engine.run_to_address(ui.disassembly_cursor);
  }
  ImGui::EndDisabled();
  ImGui::BeginDisabled(!can_terminate(snapshot));
  if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsTerminate))) {
    engine.terminate();
  }
  ImGui::EndDisabled();

  ImGui::Separator();
  ImGui::Text(l10n::text(l10n::Key::GuiPanelsState),
              session_state_text(snapshot.state));
  ImGui::Text(l10n::text(l10n::Key::GuiPanelsMode),
              session_mode_text(snapshot.mode));
  ImGui::Text(l10n::text(l10n::Key::GuiPanelsTarget),
              snapshot.target_path.c_str());
  ImGui::Text(l10n::text(l10n::Key::GuiPanelsTriple),
              snapshot.target_triple.c_str());
  ImGui::Text(l10n::text(l10n::Key::GuiPanelsArchitecture),
              snapshot.architecture.c_str());
  ImGui::Text(l10n::text(l10n::Key::GuiPanelsByteOrder),
              byte_order_text(snapshot.byte_order));
  ImGui::Text(l10n::text(l10n::Key::GuiPanelsAddressSize),
              snapshot.address_byte_size);
  ImGui::Text(l10n::text(l10n::Key::GuiPanelsProcessThreadIds),
              snapshot.process_id, snapshot.thread_id);
  ImGui::Text(l10n::text(l10n::Key::GuiPanelsStopRevision),
              snapshot.stop_revision);
  ImGui::TextWrapped(l10n::text(l10n::Key::GuiPanelsStopReason),
                     snapshot.stop_reason.c_str());
  if (snapshot.crash.crashed) {
    ImGui::SeparatorText(l10n::text(l10n::Key::GuiPanelsCrashTriage));
    ImGui::TextColored(ImVec4(1.0F, 0.35F, 0.35F, 1.0F), "%s",
                       snapshot.crash.summary.c_str());
    ImGui::Text(l10n::text(l10n::Key::GuiPanelsExecutableStack),
                snapshot.crash.stack_executable
                    ? l10n::text(l10n::Key::GuiPanelsYes)
                    : l10n::text(l10n::Key::GuiPanelsNo));
    for (const debugger::CyclicMatch &match : snapshot.crash.cyclic_matches) {
      const std::string source = debugger::cyclic_source_display(match.source);
      if (match.has_address) {
        ImGui::Text(l10n::text(l10n::Key::GuiPanelsCyclicOffsetAddress),
                    source.c_str(), match.address, match.offset,
                    match.bytes.c_str());
      } else {
        ImGui::Text(l10n::text(l10n::Key::GuiPanelsCyclicOffset),
                    source.c_str(), match.offset, match.bytes.c_str());
      }
    }
  }
  if (ImGui::CollapsingHeader(l10n::label(l10n::Key::GuiPanelsStopHistory))) {
    for (auto entry = snapshot.stop_history.rbegin();
         entry != snapshot.stop_history.rend(); ++entry) {
      ImGui::PushID(static_cast<int>(entry->stop_revision));
      const bool selected =
          ui.selected_history_generation == entry->generation &&
          ui.selected_history_stop == entry->stop_revision;
      const std::string label =
          l10n::format(l10n::Key::GuiPanelsStopHistoryEntry,
                       entry->stop_revision, entry->pc,
                       entry->stop_reason.c_str()) +
          "###history-entry";
      if (ImGui::Selectable(label.c_str(), selected)) {
        ui.selected_history_generation = entry->generation;
        ui.selected_history_stop = entry->stop_revision;
      }
      ImGui::PopID();
    }
    const auto *selected = debugger_selected_history(snapshot, ui);
    if (selected != nullptr &&
        ImGui::BeginTable("history-registers", 3,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
      ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsRegisterColumn));
      ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsValueColumn));
      ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsPreviousColumn));
      ImGui::TableHeadersRow();
      for (const debugger::RegisterValue &value : selected->registers) {
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        ImGui::TextUnformatted(value.name.c_str());
        ImGui::TableSetColumnIndex(1);
        ImGui::TextUnformatted(value.value.c_str());
        ImGui::TableSetColumnIndex(2);
        ImGui::TextUnformatted(value.previous_value.c_str());
      }
      ImGui::EndTable();
    }
  }
  draw_error_text(snapshot.error);
  ImGui::End();
}

std::string
pointer_chain_text(const std::vector<debugger::PointerChainEntry> &chain) {
  std::ostringstream output;
  for (const debugger::PointerChainEntry &entry : chain) {
    output << " -> ";
    if (!entry.error.empty()) {
      output << '<' << entry.error << '>';
      break;
    }
    output << "0x" << std::hex << entry.value;
    if (!entry.symbol.empty()) {
      output << " (" << entry.symbol << ')';
    } else if (!entry.mapping.empty()) {
      output << " (" << entry.mapping << ')';
    }
  }
  return output.str();
}

std::string branch_details_text(const debugger::InstructionRow &instruction) {
  std::ostringstream output;
  const l10n::Key status =
      !instruction.branch.available
          ? l10n::Key::GuiPanelsBranchUnknown
          : (instruction.branch.taken ? l10n::Key::GuiPanelsBranchTaken
                                      : l10n::Key::GuiPanelsBranchNotTaken);
  output << l10n::format(l10n::Key::GuiPanelsBranchDetails, l10n::text(status),
                         instruction.branch.explanation.c_str());
  for (const debugger::ResolvedOperandInfo &operand :
       instruction.resolved_operands) {
    if (output.tellp() > 0) {
      output << '\n';
    }
    output << debugger::operand_role_display(operand.role) << ' '
           << operand.expression << " = ";
    if (!operand.error.empty()) {
      output << '<' << operand.error << '>';
    } else if (operand.has_value) {
      output << "0x" << std::hex << operand.value
             << pointer_chain_text(operand.pointer_chain);
    } else {
      output << l10n::text(l10n::Key::GuiPanelsOperandUnavailable);
    }
  }
  return output.str();
}

const char *branch_summary_text(const debugger::InstructionRow &instruction) {
  if (!instruction.branch.conditional) {
    return "";
  }
  if (!instruction.branch.available) {
    return l10n::text(l10n::Key::GuiPanelsBranchUnknown);
  }
  return instruction.branch.taken
             ? l10n::text(l10n::Key::GuiPanelsBranchTaken)
             : l10n::text(l10n::Key::GuiPanelsBranchNotTaken);
}

void draw_comment_editor(const debugger::SessionSnapshot &snapshot,
                         debugger::LldbEngine &engine, UiState &ui,
                         bool control_lease) {
  if (ui.comment_editor_requested) {
    ImGui::OpenPopup(l10n::label(l10n::Key::GuiSessionCommentEditor));
    ui.comment_editor_requested = false;
  }
  if (!ImGui::BeginPopupModal(
          l10n::label(l10n::Key::GuiSessionCommentEditor), nullptr,
          ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings))
    return;
  if (!debugger_validate_comment(snapshot, ui, control_lease)) {
    ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
    return;
  }
  if (debugger_complete_comment(ui)) {
    ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
    return;
  }
  ImGui::Text(l10n::text(l10n::Key::GuiSessionCommentAddress),
              *ui.comment_address);
  ImGui::TextWrapped("%s", l10n::text(l10n::Key::GuiSessionCommentHelp));
  ImGui::BeginDisabled(ui.comment_write.valid());
  ImGui::InputTextMultiline(
      "##session-comment", ui.comment_text.data(), ui.comment_text.size(),
      ImVec2(ImGui::GetFontSize() * 42.0F, ImGui::GetTextLineHeight() * 8.0F),
      ImGuiInputTextFlags_AllowTabInput);
  if (!ui.comment_error.empty())
    ImGui::TextWrapped("%s", ui.comment_error.c_str());
  if (ImGui::Button(l10n::label(l10n::Key::GuiSessionSaveComment)))
    ui.comment_write = engine.set_comment(
        *ui.comment_address, ui.comment_text.data(), ui.comment_generation);
  ImGui::SameLine();
  if (ImGui::Button(l10n::label(l10n::Key::GuiSessionDeleteComment)))
    ui.comment_write =
        engine.set_comment(*ui.comment_address, {}, ui.comment_generation);
  ImGui::SameLine();
  if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsCancel)) ||
      (!ui.comment_write.valid() && ImGui::IsKeyPressed(ImGuiKey_Escape))) {
    ui.comment_address.reset();
    ImGui::CloseCurrentPopup();
  }
  ImGui::EndDisabled();
  ImGui::EndPopup();
}

void draw_instruction_context_actions(
    const debugger::SessionSnapshot &snapshot, debugger::LldbEngine &engine,
    UiState &ui, const debugger::InstructionRow &instruction,
    bool control_lease) {
  ui.disassembly_cursor = instruction.address;
  ImGui::BeginDisabled(control_lease);
  draw_breakpoint_context_actions(snapshot, engine, ui, instruction.address);
  ImGui::EndDisabled();
  ImGui::BeginDisabled(control_lease || ui.session_clear.valid() ||
                       snapshot.state != debugger::SessionState::Stopped ||
                       snapshot.session.epoch.empty() ||
                       !instruction.has_file_address);
  if (ImGui::MenuItem(l10n::label(l10n::Key::GuiSessionEditComment)))
    debugger_request_comment_editor(snapshot, ui, instruction.address,
                                    instruction.user_comment);
  ImGui::EndDisabled();
  ImGui::Separator();
  ImGui::BeginDisabled(control_lease ||
                       snapshot.state != debugger::SessionState::Stopped);
  if (ImGui::MenuItem(
          l10n::label(l10n::Key::GuiPanelsChangeInstructionBytes))) {
    request_instruction_patch_editor(snapshot, ui, instruction, false);
  }
  ImGui::BeginDisabled(!snapshot.supports_intel_syntax);
  if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsAssembleInstruction))) {
    request_instruction_patch_editor(snapshot, ui, instruction, true);
  }
  ImGui::EndDisabled();
  ImGui::EndDisabled();
  ImGui::Separator();
  ImGui::BeginDisabled(control_lease ||
                       snapshot.state != debugger::SessionState::Stopped);
  if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsSetInstructionPointer))) {
    engine.write_register("pc", instruction.address);
  }
  if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsRunToCursor), "F4")) {
    engine.run_to_address(instruction.address);
  }
  ImGui::EndDisabled();
  if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsFollowMemory))) {
    follow_memory(engine, ui, instruction.address);
  }
  if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsShowMemoryMap))) {
    show_in_memory_map(ui, instruction.address);
  }
}

void draw_disassembly_panel(const debugger::SessionSnapshot &snapshot,
                            debugger::LldbEngine &engine, UiState &ui,
                            bool control_lease) {
  ImGui::Begin(l10n::label(l10n::Key::WindowDisassembly));
  dispatch_navigation_shortcuts(snapshot, engine, ui, false, control_lease);
  if (ImGui::Checkbox(l10n::label(l10n::Key::GuiPanelsGraphView),
                      &ui.disassembly_graph_view)) {
    ImGui::MarkIniSettingsDirty();
    if (!ui.disassembly_graph_view) {
      ui.disassembly_graph_state.reset();
    }
  }
  debugger_sync_disassembly_mode(snapshot, engine, ui);
  ImGui::SameLine();
  if (snapshot.supports_intel_syntax) {
    bool intel_syntax = snapshot.intel_syntax;
    ImGui::BeginDisabled(control_lease);
    if (ImGui::Checkbox(l10n::label(l10n::Key::GuiPanelsIntelSyntax),
                        &intel_syntax)) {
      engine.set_intel_syntax(intel_syntax);
    }
    ImGui::EndDisabled();
  } else {
    ImGui::TextDisabled(l10n::text(l10n::Key::GuiPanelsArchitectureSyntax),
                        snapshot.architecture.empty() ? "" : ": ",
                        snapshot.architecture.c_str());
  }
  ImGui::SameLine();
  ImGui::TextDisabled("%s", l10n::text(l10n::Key::GuiPanelsDisassemblyHelp));

  if (ui.disassembly_graph_view) {
    draw_disassembly_graph(snapshot, engine, ui, control_lease);
    ImGui::BeginDisabled(control_lease);
    draw_instruction_patch_editor(snapshot, engine, ui);
    ImGui::EndDisabled();
    ImGui::End();
    return;
  }
  const bool follow_requested =
      std::exchange(ui.navigation_follow_requested, false);
  const auto &io = ImGui::GetIO();
  const bool keyboard_navigation =
      !control_lease && snapshot.state == debugger::SessionState::Stopped &&
      navigation_input_allowed(ui) &&
      ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
      !io.KeyCtrl && !io.KeyShift && !io.KeyAlt && !io.KeySuper;

  if (begin_detail_table("instructions", 5)) {
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsAddressColumn),
                            ImGuiTableColumnFlags_WidthFixed, 150.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsBytesColumn),
                            ImGuiTableColumnFlags_WidthFixed, 220.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsInstructionColumn));
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsCommentColumn));
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsBranchColumn));
    ImGui::TableHeadersRow();
    ImGui::TableSetColumnIndex(3);
    const auto &presentations = disassembly_presentations(
        ui.disassembly_text_cache, snapshot, ImGui::GetContentRegionAvail().x);
    std::optional<std::uint64_t> keyboard_scroll_target;
    auto cursor = debugger_disassembly_cursor(snapshot, ui);
    if (keyboard_navigation && !snapshot.instructions.empty()) {
      const bool up = ImGui::IsKeyPressed(ImGuiKey_UpArrow);
      const bool down = ImGui::IsKeyPressed(ImGuiKey_DownArrow);
      if (up || down) {
        cursor =
            debugger_move_disassembly_cursor(snapshot, ui, cursor, up, down);
        keyboard_scroll_target = cursor->address;
      }
    }
    if (follow_requested && cursor != snapshot.instructions.end()) {
      const auto target = disassembly_navigation_target(
          snapshot, *cursor,
          presentations[static_cast<std::size_t>(
              cursor - snapshot.instructions.begin())]);
      if (target) {
        follow_address(snapshot, engine, ui, *target);
      }
    }
    for (std::size_t row = 0; row < snapshot.instructions.size(); ++row) {
      const auto &instruction = snapshot.instructions[row];
      const auto &presentation = presentations[row];
      const debugger::BreakpointInfo *breakpoint =
          breakpoint_info_at(snapshot, instruction.address);
      ImGui::TableNextRow();
      if (instruction.address == snapshot.pc) {
        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                               ui.theme_dark ? IM_COL32(160, 140, 40, 65)
                                             : IM_COL32(230, 190, 30, 55));
      }
      ImGui::TableSetColumnIndex(0);
      char address_label[64]{};
      std::snprintf(address_label, sizeof(address_label), "%s0x%" PRIx64,
                    breakpoint ? "* " : "  ", instruction.address);
      for (const auto color :
           {ImGuiCol_Header, ImGuiCol_HeaderHovered, ImGuiCol_HeaderActive}) {
        auto tint = ImGui::GetStyleColorVec4(color);
        tint.w *= 0.35F;
        ImGui::PushStyleColor(color, tint);
      }
      if (ImGui::Selectable(
              address_label, ui.disassembly_cursor == instruction.address,
              ImGuiSelectableFlags_SpanAllColumns,
              ImVec2(0.0F, std::max(ImGui::GetTextLineHeight(),
                                    presentation.annotation.size.y))) &&
          !follow_requested) {
        ui.disassembly_cursor = instruction.address;
      }
      ImGui::PopStyleColor(3);
      if (keyboard_scroll_target == instruction.address) {
        ImGui::SetScrollHereY(0.5F);
      }
      if (ui.disassembly_scroll_target == instruction.address &&
          snapshot.instructions.front().address == instruction.address) {
        ImGui::SetScrollHereY(0.5F);
        ui.disassembly_scroll_target.reset();
      }
      if (instruction.address == snapshot.pc &&
          (ui.disassembly_scroll_generation != snapshot.generation ||
           ui.disassembly_scroll_stop_revision != snapshot.stop_revision)) {
        ImGui::SetScrollHereY(0.5F);
        ui.disassembly_scroll_generation = snapshot.generation;
        ui.disassembly_scroll_stop_revision = snapshot.stop_revision;
      }
      if (ImGui::BeginPopupContextItem()) {
        draw_instruction_context_actions(snapshot, engine, ui, instruction,
                                         control_lease);
        ImGui::EndPopup();
      }
      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(presentation.bytes.c_str());
      ImGui::TableSetColumnIndex(2);
      if (const auto target =
              draw_disassembly_text_cell(presentation.instruction, snapshot)) {
        ui.disassembly_cursor = instruction.address;
        follow_address(snapshot, engine, ui, *target);
      }
      ImGui::TableSetColumnIndex(3);
      if (const auto target =
              draw_disassembly_text_cell(presentation.annotation, snapshot)) {
        ui.disassembly_cursor = instruction.address;
        follow_address(snapshot, engine, ui, *target);
      }
      ImGui::TableSetColumnIndex(4);
      if (instruction.address == snapshot.pc) {
        const char *summary = branch_summary_text(instruction);
        ImGui::TextUnformatted(summary);
        if (summary[0] != '\0' && ImGui::IsItemHovered()) {
          const std::string details = branch_details_text(instruction);
          if (!details.empty()) {
            ImGui::SetTooltip("%s", details.c_str());
          }
        }
      }
    }
    ImGui::EndTable();
  }
  ImGui::BeginDisabled(control_lease);
  draw_instruction_patch_editor(snapshot, engine, ui);
  ImGui::EndDisabled();
  ImGui::End();
}

void draw_threads_panel(const debugger::SessionSnapshot &snapshot,
                        debugger::LldbEngine &engine, UiState &ui) {
  if (!begin_optional_panel(l10n::Key::WindowThreads, ui.show_threads))
    return;
  if (begin_detail_table("thread-table", 4)) {
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsIdColumn),
                            ImGuiTableColumnFlags_WidthFixed, 110.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsIndexColumn),
                            ImGuiTableColumnFlags_WidthFixed, 55.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsName));
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsStopReasonColumn));
    ImGui::TableHeadersRow();
    for (const debugger::ThreadInfo &thread : snapshot.threads) {
      ImGui::PushID(static_cast<int>(thread.index));
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      char id[32]{};
      std::snprintf(id, sizeof(id), "0x%" PRIx64, thread.id);
      if (ImGui::Selectable(id, thread.selected,
                            ImGuiSelectableFlags_SpanAllColumns)) {
        engine.select_thread(thread.id);
      }
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("%u", thread.index);
      ImGui::TableSetColumnIndex(2);
      ImGui::TextUnformatted(thread.name.c_str());
      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(thread.stop_reason.c_str());
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
  ImGui::End();
}

void draw_backtrace_panel(const debugger::SessionSnapshot &snapshot,
                          debugger::LldbEngine &engine, UiState &ui) {
  if (!begin_optional_panel(l10n::Key::WindowBacktrace, ui.show_backtrace))
    return;
  if (begin_detail_table("backtrace-table", 4)) {
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsFrameIndexColumn),
                            ImGuiTableColumnFlags_WidthFixed, 35.0F);
    ImGui::TableSetupColumn(
        l10n::label(l10n::Key::GuiPanelsProgramCounterColumn),
        ImGuiTableColumnFlags_WidthFixed, 130.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsFunctionColumn));
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsSourceColumn));
    ImGui::TableHeadersRow();
    for (const debugger::ThreadInfo &thread : snapshot.threads) {
      if (!thread.selected) {
        continue;
      }
      for (const debugger::StackFrameInfo &frame : thread.frames) {
        ImGui::PushID(static_cast<int>(frame.index));
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        char index[24]{};
        std::snprintf(index, sizeof(index), "%u", frame.index);
        if (ImGui::Selectable(index, frame.selected,
                              ImGuiSelectableFlags_SpanAllColumns)) {
          engine.select_frame(thread.id, frame.index);
        }
        ImGui::TableSetColumnIndex(1);
        ImGui::Text("0x%" PRIx64, frame.pc);
        ImGui::TableSetColumnIndex(2);
        ImGui::TextUnformatted(frame.function.c_str());
        ImGui::TableSetColumnIndex(3);
        if (!frame.source_path.empty()) {
          ImGui::Text("%s:%u", frame.source_path.c_str(), frame.source_line);
        } else {
          ImGui::TextUnformatted(frame.module.c_str());
        }
        ImGui::PopID();
      }
    }
    ImGui::EndTable();
  }
  ImGui::End();
}

void draw_stack_panel(const debugger::SessionSnapshot &snapshot,
                      debugger::LldbEngine &engine, UiState &ui) {
  if (!begin_optional_panel(l10n::Key::WindowStackTelescope, ui.show_stack))
    return;
  if (begin_detail_table("stack-table", 3)) {
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsAddressColumn),
                            ImGuiTableColumnFlags_WidthFixed, 135.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsValueColumn),
                            ImGuiTableColumnFlags_WidthFixed, 135.0F);
    ImGui::TableSetupColumn(
        l10n::label(l10n::Key::GuiPanelsPointerChainColumn));
    ImGui::TableHeadersRow();
    for (const debugger::StackEntry &entry : snapshot.stack) {
      ImGui::PushID(static_cast<int>(entry.address ^ (entry.address >> 32U)));
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      char address[32]{};
      std::snprintf(address, sizeof(address), "0x%" PRIx64, entry.address);
      if (ImGui::Selectable(address, false)) {
        follow_memory(engine, ui, entry.address);
      }
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("0x%" PRIx64, entry.value);
      if (ImGui::BeginPopupContextItem("stack-value-context")) {
        draw_pointer_context_actions(snapshot, engine, ui, entry.value);
        ImGui::EndPopup();
      }
      ImGui::TableSetColumnIndex(2);
      ImGui::Text("%s%s", entry.symbol.c_str(),
                  pointer_chain_text(entry.pointer_chain).c_str());
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
  ImGui::End();
}

void draw_heap_panel(const debugger::SessionSnapshot &snapshot,
                     debugger::LldbEngine &engine, UiState &ui) {
  if (!begin_optional_panel(l10n::Key::WindowGlibcHeap, ui.show_heap))
    return;
  if (!snapshot.heap_error.empty()) {
    ImGui::TextColored(ImVec4(1.0F, 0.72F, 0.25F, 1.0F), "%s",
                       snapshot.heap_error.c_str());
  }
  if (begin_detail_table("heap-chunks", 6)) {
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsChunkColumn),
                            ImGuiTableColumnFlags_WidthFixed, 135.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsSizeColumn),
                            ImGuiTableColumnFlags_WidthFixed, 80.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsFlagsColumn),
                            ImGuiTableColumnFlags_WidthFixed, 50.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsStateColumn),
                            ImGuiTableColumnFlags_WidthFixed, 65.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsForwardLinkColumn));
    ImGui::TableSetupColumn(
        l10n::label(l10n::Key::GuiPanelsBackwardLinkColumn));
    ImGui::TableHeadersRow();
    for (const debugger::HeapChunkInfo &chunk : snapshot.heap_chunks) {
      ImGui::PushID(static_cast<int>(chunk.address ^ (chunk.address >> 32U)));
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      char address[32]{};
      std::snprintf(address, sizeof(address), "0x%" PRIx64, chunk.address);
      if (ImGui::Selectable(address, false)) {
        follow_memory(engine, ui, chunk.address);
      }
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("0x%" PRIx64, chunk.size);
      ImGui::TableSetColumnIndex(2);
      ImGui::Text("%c%c%c", (chunk.flags & 1U) != 0 ? 'P' : '-',
                  (chunk.flags & 2U) != 0 ? 'M' : '-',
                  (chunk.flags & 4U) != 0 ? 'A' : '-');
      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(chunk.in_use
                                 ? l10n::text(l10n::Key::GuiPanelsHeapUsed)
                                 : l10n::text(l10n::Key::GuiPanelsHeapFree));
      ImGui::TableSetColumnIndex(4);
      ImGui::Text("0x%" PRIx64, chunk.forward);
      ImGui::TableSetColumnIndex(5);
      ImGui::Text("0x%" PRIx64, chunk.backward);
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
  ImGui::End();
}

void draw_memory_map_panel(const debugger::SessionSnapshot &snapshot,
                           debugger::LldbEngine &engine, UiState &ui) {
  if (!begin_optional_panel(l10n::Key::WindowMemoryMap, ui.show_memory_map))
    return;
  if (begin_detail_table("memory-map-table", 4)) {
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsStart),
                            ImGuiTableColumnFlags_WidthFixed, 135.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsEndColumn),
                            ImGuiTableColumnFlags_WidthFixed, 135.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsPermissionsColumn),
                            ImGuiTableColumnFlags_WidthFixed, 48.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsMappingColumn));
    ImGui::TableHeadersRow();
    for (const debugger::MemoryRegionInfo &region : snapshot.memory_regions) {
      ImGui::PushID(static_cast<int>(region.start ^ (region.start >> 32U)));
      ImGui::TableNextRow();
      const bool selected = ui.memory_map_address &&
                            *ui.memory_map_address >= region.start &&
                            *ui.memory_map_address < region.end;
      if (selected) {
        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                               ImGui::GetColorU32(ImGuiCol_Header));
      }
      ImGui::TableSetColumnIndex(0);
      char start[32]{};
      std::snprintf(start, sizeof(start), "0x%" PRIx64, region.start);
      if (ImGui::Selectable(start, selected,
                            ImGuiSelectableFlags_SpanAllColumns)) {
        debugger_follow_memory_region(engine, ui, region);
      }
      if (selected && ui.scroll_memory_map_to_address) {
        ImGui::SetScrollHereY(0.5F);
        ui.scroll_memory_map_to_address = false;
      }
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("0x%" PRIx64, region.end);
      ImGui::TableSetColumnIndex(2);
      ImGui::Text("%c%c%c", region.readable ? 'r' : '-',
                  region.writable ? 'w' : '-', region.executable ? 'x' : '-');
      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(region.name.c_str());
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
  ImGui::End();
}

void draw_modules_panel(const debugger::SessionSnapshot &snapshot,
                        debugger::LldbEngine &engine, UiState &ui) {
  if (!begin_optional_panel(l10n::Key::WindowModules, ui.show_modules))
    return;
  if (begin_detail_table("module-table", 4)) {
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsBaseColumn),
                            ImGuiTableColumnFlags_WidthFixed, 135.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsEndColumn),
                            ImGuiTableColumnFlags_WidthFixed, 135.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsModuleColumn));
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsBuildIdColumn));
    ImGui::TableHeadersRow();
    for (const debugger::ModuleInfo &module : snapshot.modules) {
      ImGui::PushID(static_cast<int>(module.base ^ (module.base >> 32U)));
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      char base[32]{};
      std::snprintf(base, sizeof(base), "0x%" PRIx64, module.base);
      if (ImGui::Selectable(base, false) && module.base != 0) {
        follow_disassembly(engine, ui, module.base);
      }
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("0x%" PRIx64, module.end);
      ImGui::TableSetColumnIndex(2);
      ImGui::TextUnformatted(module.path.c_str());
      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(module.uuid.c_str());
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
  ImGui::End();
}

void draw_security_panel(const debugger::SessionSnapshot &snapshot,
                         UiState &ui) {
  if (!begin_optional_panel(l10n::Key::WindowElfSecurity, ui.show_security))
    return;
  if (!snapshot.security.available) {
    ImGui::TextDisabled("%s",
                        l10n::text(l10n::Key::GuiPanelsSecurityUnavailable));
  } else {
    ImGui::Text(l10n::text(l10n::Key::GuiPanelsPie),
                snapshot.security.pie
                    ? l10n::text(l10n::Key::GuiPanelsEnabled)
                    : l10n::text(l10n::Key::GuiPanelsDisabled));
    ImGui::Text(l10n::text(l10n::Key::GuiPanelsNx),
                snapshot.security.nx
                    ? l10n::text(l10n::Key::GuiPanelsEnabled)
                    : l10n::text(l10n::Key::GuiPanelsDisabled));
    ImGui::Text(
        l10n::text(l10n::Key::GuiPanelsRelro),
        snapshot.security.full_relro ? l10n::text(l10n::Key::GuiPanelsRelroFull)
        : snapshot.security.relro ? l10n::text(l10n::Key::GuiPanelsRelroPartial)
                                  : l10n::text(l10n::Key::GuiPanelsDisabled));
    ImGui::Text(l10n::text(l10n::Key::GuiPanelsStackCanary),
                snapshot.security.stack_canary
                    ? l10n::text(l10n::Key::GuiPanelsCanaryFound)
                    : l10n::text(l10n::Key::GuiPanelsCanaryNotFound));
    ImGui::Text(l10n::text(l10n::Key::GuiPanelsSymbols),
                snapshot.security.stripped
                    ? l10n::text(l10n::Key::GuiPanelsSymbolsStripped)
                    : l10n::text(l10n::Key::GuiPanelsSymbolsPresent));
  }
  ImGui::End();
}

void draw_register_panel(const debugger::SessionSnapshot &snapshot,
                         debugger::LldbEngine &engine, UiState &ui) {
  ImGui::Begin(l10n::label(l10n::Key::WindowRegisters));
  debugger_complete_register_write(snapshot, ui);
  const bool pending = ui.register_write.valid();
  const bool writable =
      snapshot.state == debugger::SessionState::Stopped && !pending;
  if (!pending && ui.register_edit_revision != snapshot.revision) {
    ui.register_edit_name.clear();
  }
  draw_error_text(ui.register_edit_error);
  ImGui::TextDisabled("%s", l10n::text(l10n::Key::GuiPanelsRegisterEditHelp));
  if (begin_detail_table("registers", 3)) {
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsRegisterColumn),
                            ImGuiTableColumnFlags_WidthFixed, 100.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsValueColumn));
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsPreviousColumn));
    ImGui::TableHeadersRow();
    for (std::size_t index = 0; index < snapshot.registers.size(); ++index) {
      const auto &value = snapshot.registers[index];
      ImGui::PushID(value.name.c_str());
      ImGui::TableNextRow();
      if (value.changed) {
        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                               IM_COL32(110, 75, 20, 180));
      }
      ImGui::TableSetColumnIndex(0);
      const bool editing = ui.register_edit_name == value.name;
      if (ImGui::Selectable(value.name.c_str(), editing,
                            editing ? ImGuiSelectableFlags_None
                                    : ImGuiSelectableFlags_SpanAllColumns) &&
          writable) {
        debugger_begin_register_edit(snapshot, ui, value);
      }
      if (ImGui::BeginPopupContextItem("register-context")) {
        ImGui::BeginDisabled(!writable);
        if (ImGui::MenuItem(
                l10n::label(l10n::Key::GuiPanelsEditRegisterValue))) {
          debugger_begin_register_edit(snapshot, ui, value);
        }
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsClear), "0")) {
          debugger_clear_register(engine, ui, value);
        }
        const bool integer = debugger_register_is_integer(value);
        ImGui::BeginDisabled(!integer);
        const auto mask = debugger_register_mask(value, integer);
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsDecrement), "-1")) {
          ui.register_edit_name.clear();
          debugger_write_register(
              engine, ui, value,
              address_specification((value.numeric_value - 1) & mask));
        }
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsIncrement), "+1")) {
          ui.register_edit_name.clear();
          debugger_write_register(
              engine, ui, value,
              address_specification((value.numeric_value + 1) & mask));
        }
        ImGui::EndDisabled();
        ImGui::EndDisabled();
        ImGui::Separator();
        if (value.has_numeric_value) {
          draw_pointer_context_actions(snapshot, engine, ui,
                                       value.numeric_value);
        } else {
          ImGui::TextDisabled("%s",
                              l10n::text(l10n::Key::GuiPanelsValueNotAddress));
        }
        ImGui::EndPopup();
      }
      ImGui::TableSetColumnIndex(1);
      if (ui.register_edit_name == value.name) {
        ImGui::BeginDisabled(!writable);
        if (ui.register_edit_focus && writable) {
          ImGui::SetKeyboardFocusHere();
          ui.register_edit_focus = false;
        }
        ImGui::SetNextItemWidth(-1.0F);
        const bool submitted =
            ImGui::InputText("##register-value", ui.register_edit_text.data(),
                             ui.register_edit_text.size(),
                             ImGuiInputTextFlags_EnterReturnsTrue |
                                 ImGuiInputTextFlags_AutoSelectAll);
        const bool cancelled =
            ImGui::IsItemActive() && ImGui::IsKeyPressed(ImGuiKey_Escape);
        if (submitted && writable) {
          debugger_write_register(engine, ui, value,
                                  ui.register_edit_text.data());
        } else if (cancelled || (!pending && ImGui::IsItemDeactivated())) {
          ui.register_edit_name.clear();
        }
        ImGui::EndDisabled();
      } else {
        ImGui::Text("%s%s", value.value.c_str(),
                    pointer_chain_text(value.pointer_chain).c_str());
      }
      ImGui::TableSetColumnIndex(2);
      if (value.changed) {
        ImGui::TextColored(ImVec4(1.0F, 0.78F, 0.30F, 1.0F), "%s",
                           value.previous_value.c_str());
      } else {
        ImGui::TextDisabled("%s", value.previous_value.c_str());
      }
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
  ImGui::End();
}

void draw_breakpoints_panel(const debugger::SessionSnapshot &snapshot,
                            debugger::LldbEngine &engine, UiState &ui) {
  ImGui::Begin(l10n::label(l10n::Key::WindowBreakpoints));
  const bool submitted = ImGui::InputTextWithHint(
      "##breakpoint", l10n::text(l10n::Key::GuiPanelsBreakpointAddressHint),
      ui.breakpoint_specification.data(), ui.breakpoint_specification.size(),
      ImGuiInputTextFlags_EnterReturnsTrue);
  ImGui::SameLine();
  if (submitted ||
      ImGui::Button(l10n::label(l10n::Key::GuiPanelsAddBreakpoint))) {
    engine.set_breakpoint(ui.breakpoint_specification.data());
    ui.breakpoint_specification.front() = '\0';
  }

  if (begin_detail_table("breakpoint-list", 6)) {
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsOnColumn),
                            ImGuiTableColumnFlags_WidthFixed, 28.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsIdColumn),
                            ImGuiTableColumnFlags_WidthFixed, 28.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsDescriptionColumn));
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsConditionColumn),
                            ImGuiTableColumnFlags_WidthFixed, 78.0F);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsHitsColumn),
                            ImGuiTableColumnFlags_WidthFixed, 34.0F);
    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 30.0F);
    ImGui::TableHeadersRow();
    for (const debugger::BreakpointInfo &breakpoint : snapshot.breakpoints) {
      ImGui::PushID(static_cast<int>(breakpoint.id));
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      bool enabled = breakpoint.enabled;
      if (ImGui::Checkbox("##enabled", &enabled)) {
        engine.set_breakpoint_enabled(breakpoint.id, enabled);
      }
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("%u", breakpoint.id);
      ImGui::TableSetColumnIndex(2);
      ImGui::TextUnformatted(breakpoint.description.c_str());
      if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::TextUnformatted(breakpoint.description.c_str());
        if (!breakpoint.condition.empty()) {
          ImGui::Text(l10n::text(l10n::Key::GuiPanelsLldbCondition),
                      breakpoint.condition.c_str());
        }
        if (!breakpoint.script_condition.empty()) {
          ImGui::TextWrapped(l10n::text(l10n::Key::GuiPanelsBreakpointScript),
                             breakpoint.script_condition.c_str());
        }
        if (!breakpoint.script_error.empty()) {
          ImGui::TextColored(ImVec4(1.0F, 0.35F, 0.35F, 1.0F),
                             l10n::text(l10n::Key::GuiPanelsLastError),
                             breakpoint.script_error.c_str());
        }
        ImGui::EndTooltip();
      }
      ImGui::TableSetColumnIndex(3);
      if (ImGui::SmallButton(
              breakpoint.script_condition.empty()
                  ? l10n::label(l10n::Key::GuiPanelsAddCondition)
                  : l10n::label(l10n::Key::GuiPanelsEditCondition))) {
        request_existing_condition_editor(ui, breakpoint);
      }
      ImGui::TableSetColumnIndex(4);
      ImGui::Text("%u", breakpoint.hit_count);
      ImGui::TableSetColumnIndex(5);
      if (ImGui::SmallButton(
              l10n::label(l10n::Key::GuiPanelsRemoveBreakpoint))) {
        engine.remove_breakpoint(breakpoint.id);
      }
      ImGui::PopID();
    }
    ImGui::EndTable();
  }

  if (ui.condition_editor_requested) {
    ImGui::OpenPopup(l10n::label(l10n::Key::GuiPanelsConditionalBreakpoint));
    ui.condition_editor_requested = false;
  }
  ImGui::SetNextWindowSize(ImVec2(600.0F, 230.0F), ImGuiCond_Appearing);
  if (ImGui::BeginPopupModal(
          l10n::label(l10n::Key::GuiPanelsConditionalBreakpoint), nullptr,
          ImGuiWindowFlags_NoSavedSettings)) {
    const bool creating = ui.creating_conditional_breakpoint.has_value();
    const std::uint32_t breakpoint_id = ui.editing_breakpoint.value_or(0);
    if (creating) {
      ImGui::Text(l10n::text(l10n::Key::GuiPanelsNewBreakpointAddress),
                  *ui.creating_conditional_breakpoint);
    } else {
      ImGui::Text(l10n::text(l10n::Key::GuiPanelsBreakpointId), breakpoint_id);
    }
    ImGui::InputTextMultiline(
        "##script-condition", ui.breakpoint_condition.data(),
        ui.breakpoint_condition.size(), ImVec2(-1.0F, 130.0F));
    draw_error_text(ui.breakpoint_condition_error);
    if (ImGui::Button(creating ? l10n::label(l10n::Key::GuiPanelsCreate)
                               : l10n::label(l10n::Key::GuiPanelsApply))) {
      if (debugger_apply_condition(engine, ui, creating, breakpoint_id)) {
        ImGui::CloseCurrentPopup();
        close_condition_editor(ui);
      }
    }
    if (!creating) {
      ImGui::SameLine();
      if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsClearCondition))) {
        engine.set_breakpoint_script(breakpoint_id, {});
        ui.breakpoint_condition.front() = '\0';
        ImGui::CloseCurrentPopup();
        close_condition_editor(ui);
      }
    }
    ImGui::SameLine();
    if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsCancel))) {
      ImGui::CloseCurrentPopup();
      close_condition_editor(ui);
    }
    ImGui::EndPopup();
  }
  ImGui::End();
}

void draw_scans_panel(const debugger::SessionSnapshot &snapshot,
                      debugger::LldbEngine &engine, UiState &ui) {
  if (!begin_optional_panel(l10n::Key::WindowScans, ui.show_scans))
    return;
  if (!ImGui::BeginTabBar("scan-tabs")) {
    ImGui::End();
    return;
  }

  if (ImGui::BeginTabItem(l10n::label(l10n::Key::GuiPanelsBinaryStrings))) {
    ImGui::SetNextItemWidth(110.0F);
    ImGui::InputInt(l10n::label(l10n::Key::GuiPanelsMinimumStringLength),
                    &ui.binary_string_minimum_length);
    ui.binary_string_minimum_length =
        std::clamp(ui.binary_string_minimum_length, 1, 4096);
    ImGui::SameLine();
    ImGui::Checkbox(l10n::label(l10n::Key::GuiPanelsIncludeUtf16),
                    &ui.binary_string_include_utf16);
    ImGui::SameLine();
    ImGui::BeginDisabled(snapshot.target_path.empty());
    if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsScanBinary))) {
      engine.scan_binary_strings(
          static_cast<std::uint32_t>(ui.binary_string_minimum_length),
          ui.binary_string_include_utf16);
    }
    ImGui::EndDisabled();
    ImGui::SetNextItemWidth(-1.0F);
    ImGui::InputTextWithHint(
        "##string-filter", l10n::text(l10n::Key::GuiPanelsStringFilterHint),
        ui.binary_string_filter.data(), ui.binary_string_filter.size());
    if (!snapshot.binary_strings_error.empty()) {
      draw_error_text(snapshot.binary_strings_error);
    } else {
      ImGui::Text(l10n::text(l10n::Key::GuiPanelsStringCount),
                  snapshot.binary_string_count);
      if (snapshot.binary_strings_truncated) {
        ImGui::SameLine();
        ImGui::TextDisabled(l10n::text(l10n::Key::GuiPanelsTruncatedResults),
                            snapshot.binary_strings.size());
      }
    }

    if (begin_detail_table("binary-string-results", 4)) {
      ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsAddressColumn),
                              ImGuiTableColumnFlags_WidthFixed, 145.0F);
      ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsFileOffsetColumn),
                              ImGuiTableColumnFlags_WidthFixed, 110.0F);
      ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsEncodingColumn),
                              ImGuiTableColumnFlags_WidthFixed, 80.0F);
      ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsStringColumn));
      ImGui::TableSetupScrollFreeze(0, 1);
      ImGui::TableHeadersRow();
      const std::string_view filter{ui.binary_string_filter.data()};
      for (std::size_t index = 0; index < snapshot.binary_strings.size();
           ++index) {
        const debugger::BinaryStringInfo &result =
            snapshot.binary_strings[index];
        if (!filter.empty() && result.value.find(filter) == std::string::npos) {
          continue;
        }
        ImGui::PushID(static_cast<int>(index));
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        std::string address;
        if (result.has_load_address) {
          address = address_specification(result.load_address);
        } else if (result.has_file_address) {
          address = l10n::format(l10n::Key::GuiPanelsFileAddress,
                                 result.file_address);
        } else {
          address = "--";
        }
        address += "###binary-string-result";
        if (ImGui::Selectable(address.c_str(), false,
                              ImGuiSelectableFlags_SpanAllColumns) &&
            ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) &&
            result.has_load_address &&
            snapshot.state == debugger::SessionState::Stopped) {
          follow_memory(engine, ui, result.load_address);
        }
        if (result.has_load_address && ImGui::BeginPopupContextItem()) {
          ImGui::BeginDisabled(snapshot.state !=
                               debugger::SessionState::Stopped);
          draw_pointer_context_actions(snapshot, engine, ui,
                                       result.load_address);
          ImGui::EndDisabled();
          ImGui::EndPopup();
        }
        ImGui::TableSetColumnIndex(1);
        ImGui::Text("0x%" PRIx64, result.file_offset);
        ImGui::TableSetColumnIndex(2);
        ImGui::TextUnformatted(result.encoding.c_str());
        ImGui::TableSetColumnIndex(3);
        ImGui::TextUnformatted(result.value.c_str());
        ImGui::PopID();
      }
      ImGui::EndTable();
    }
    ImGui::EndTabItem();
  }

  if (ImGui::BeginTabItem(l10n::label(l10n::Key::GuiPanelsValueScanner))) {
    const std::array<const char *, 6> value_type_names{
        l10n::text(l10n::Key::GuiPanelsByteValueType),
        l10n::text(l10n::Key::GuiPanelsTwoByteValueType),
        l10n::text(l10n::Key::GuiPanelsFourByteValueType),
        l10n::text(l10n::Key::GuiPanelsEightByteValueType),
        l10n::text(l10n::Key::GuiPanelsFloatValueType),
        l10n::text(l10n::Key::GuiPanelsDoubleValueType)};
    const float selector_width =
        std::clamp(ImGui::GetContentRegionAvail().x * 0.40F, 240.0F, 360.0F);
    int type_index = static_cast<int>(ui.value_scan_type);
    ImGui::BeginDisabled(snapshot.value_scan_active);
    ImGui::SetNextItemWidth(selector_width);
    if (ImGui::Combo(l10n::label(l10n::Key::GuiPanelsValueType), &type_index,
                     value_type_names.data(),
                     static_cast<int>(value_type_names.size()))) {
      ui.value_scan_type = static_cast<debugger::ValueScanType>(type_index);
    }
    const bool floating_point =
        ui.value_scan_type == debugger::ValueScanType::Float ||
        ui.value_scan_type == debugger::ValueScanType::Double;
    if (floating_point) {
      ui.value_scan_signed = false;
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(floating_point);
    ImGui::Checkbox(l10n::label(l10n::Key::GuiPanelsSignedValues),
                    &ui.value_scan_signed);
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::Checkbox(l10n::label(l10n::Key::GuiPanelsWritableOnly),
                    &ui.value_scan_writable_only);
    ImGui::EndDisabled();

    bool needs_value = true;
    if (!snapshot.value_scan_active) {
      const std::array<const char *, 2> first_scan_names{
          l10n::text(l10n::Key::GuiPanelsExactValue),
          l10n::text(l10n::Key::GuiPanelsUnknownInitialValue)};
      int first_scan = ui.value_scan_unknown ? 1 : 0;
      ImGui::SetNextItemWidth(selector_width);
      if (ImGui::Combo(l10n::label(l10n::Key::GuiPanelsScanType), &first_scan,
                       first_scan_names.data(),
                       static_cast<int>(first_scan_names.size()))) {
        ui.value_scan_unknown = first_scan == 1;
      }
      needs_value = !ui.value_scan_unknown;
    } else {
      const std::array<const char *, 5> next_scan_names{
          l10n::text(l10n::Key::GuiPanelsExactValue),
          l10n::text(l10n::Key::GuiPanelsChangedValue),
          l10n::text(l10n::Key::GuiPanelsUnchangedValue),
          l10n::text(l10n::Key::GuiPanelsIncreasedValue),
          l10n::text(l10n::Key::GuiPanelsDecreasedValue)};
      int comparison = static_cast<int>(ui.value_scan_comparison);
      ImGui::SetNextItemWidth(selector_width);
      if (ImGui::Combo(l10n::label(l10n::Key::GuiPanelsScanType), &comparison,
                       next_scan_names.data(),
                       static_cast<int>(next_scan_names.size()))) {
        ui.value_scan_comparison =
            static_cast<debugger::ValueScanComparison>(comparison);
      }
      needs_value =
          ui.value_scan_comparison == debugger::ValueScanComparison::Exact;
    }

    ImGui::BeginDisabled(!needs_value);
    ImGui::SetNextItemWidth(220.0F);
    const bool submitted = ImGui::InputTextWithHint(
        "##scan-value",
        needs_value ? l10n::text(l10n::Key::GuiPanelsValueColumn)
                    : l10n::text(l10n::Key::GuiPanelsNoScanValueRequired),
        ui.value_scan_value.data(), ui.value_scan_value.size(),
        ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_scan = snapshot.state == debugger::SessionState::Stopped;
    ImGui::BeginDisabled(!can_scan);
    if (!snapshot.value_scan_active) {
      if ((submitted && needs_value) ||
          ImGui::Button(l10n::label(l10n::Key::GuiPanelsFirstScan))) {
        engine.start_value_scan(ui.value_scan_type, ui.value_scan_value.data(),
                                ui.value_scan_unknown, ui.value_scan_signed,
                                ui.value_scan_writable_only);
      }
    } else if ((submitted && needs_value) ||
               ImGui::Button(l10n::label(l10n::Key::GuiPanelsNextScan))) {
      engine.next_value_scan(ui.value_scan_comparison,
                             ui.value_scan_value.data());
    }
    ImGui::EndDisabled();
    if (snapshot.value_scan_active) {
      ImGui::SameLine();
      if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsNewScan))) {
        engine.reset_value_scan();
      }
    }

    if (!snapshot.value_scan_error.empty()) {
      draw_error_text(snapshot.value_scan_error);
    } else if (snapshot.value_scan_active) {
      ImGui::Text(l10n::text(l10n::Key::GuiPanelsScanMatchCount),
                  snapshot.value_scan_match_count);
      if (snapshot.value_scan_truncated) {
        ImGui::SameLine();
        ImGui::TextDisabled(l10n::text(l10n::Key::GuiPanelsTruncatedResults),
                            snapshot.value_scan_results.size());
      }
    } else {
      ImGui::TextDisabled("%s", l10n::text(l10n::Key::GuiPanelsValueScanHelp));
    }

    if (begin_detail_table("value-scan-results", 4)) {
      ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsAddressColumn),
                              ImGuiTableColumnFlags_WidthFixed, 145.0F);
      ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsCurrentColumn),
                              ImGuiTableColumnFlags_WidthFixed, 110.0F);
      ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsPreviousColumn),
                              ImGuiTableColumnFlags_WidthFixed, 110.0F);
      ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsRegionColumn));
      ImGui::TableSetupScrollFreeze(0, 1);
      ImGui::TableHeadersRow();
      ImGuiListClipper clipper;
      clipper.Begin(static_cast<int>(snapshot.value_scan_results.size()));
      while (clipper.Step()) {
        for (int index = clipper.DisplayStart; index < clipper.DisplayEnd;
             ++index) {
          const debugger::ValueScanResult &result =
              snapshot.value_scan_results[static_cast<std::size_t>(index)];
          ImGui::PushID(index);
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          char address[32]{};
          std::snprintf(address, sizeof(address), "0x%" PRIx64, result.address);
          if (ImGui::Selectable(address, false,
                                ImGuiSelectableFlags_SpanAllColumns) &&
              ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
            follow_memory(engine, ui, result.address);
          }
          if (ImGui::BeginPopupContextItem()) {
            ImGui::BeginDisabled(snapshot.state !=
                                 debugger::SessionState::Stopped);
            draw_pointer_context_actions(snapshot, engine, ui, result.address);
            ImGui::EndDisabled();
            ImGui::EndPopup();
          }
          ImGui::TableSetColumnIndex(1);
          ImGui::TextUnformatted(result.current_value.c_str());
          ImGui::TableSetColumnIndex(2);
          ImGui::TextUnformatted(result.previous_value.c_str());
          ImGui::TableSetColumnIndex(3);
          ImGui::TextUnformatted(result.region.c_str());
          ImGui::PopID();
        }
      }
      ImGui::EndTable();
    }
    ImGui::EndTabItem();
  }
  ImGui::EndTabBar();
  ImGui::End();
}

} // namespace mydbg::app
