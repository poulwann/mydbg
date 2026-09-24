#include "app/DecompilerPanels.h"
#include "app/AppActions.h"
#include "app/AppMenus.h"
#include "app/AppState.h"
#include "app/DebuggerPanels.h"
#include "app/DecompilerController.h"
#include "app/UiSupport.h"
#include "localization/Localization.h"

#include <cinttypes>
#include <span>
#include <utility>

namespace mydbg::app {

ImU32 decompiler_token_color(debugger::DecompilerTokenKind kind) {
  switch (kind) {
  case debugger::DecompilerTokenKind::Keyword:
    return IM_COL32(198, 120, 221, 255);
  case debugger::DecompilerTokenKind::Comment:
    return IM_COL32(106, 153, 85, 255);
  case debugger::DecompilerTokenKind::DataType:
    return IM_COL32(78, 201, 176, 255);
  case debugger::DecompilerTokenKind::Function:
    return IM_COL32(220, 220, 170, 255);
  case debugger::DecompilerTokenKind::Parameter:
    return IM_COL32(156, 220, 254, 255);
  case debugger::DecompilerTokenKind::Local:
    return IM_COL32(184, 215, 255, 255);
  case debugger::DecompilerTokenKind::Constant:
    return IM_COL32(181, 206, 168, 255);
  case debugger::DecompilerTokenKind::Global:
    return IM_COL32(235, 186, 120, 255);
  case debugger::DecompilerTokenKind::Plain:
    return ImGui::GetColorU32(ImGuiCol_Text);
  }
  return ImGui::GetColorU32(ImGuiCol_Text);
}

const char *decompiler_target_kind_name(debugger::DecompilerSymbolKind kind) {
  switch (kind) {
  case debugger::DecompilerSymbolKind::Function:
    return l10n::text(l10n::Key::GuiPanelsDecompilerFunction);
  case debugger::DecompilerSymbolKind::Global:
    return l10n::text(l10n::Key::GuiPanelsDecompilerGlobal);
  case debugger::DecompilerSymbolKind::Constant:
    return l10n::text(l10n::Key::GuiPanelsDecompilerConstant);
  case debugger::DecompilerSymbolKind::Local:
    return l10n::text(l10n::Key::GuiPanelsDecompilerLocal);
  case debugger::DecompilerSymbolKind::Parameter:
    return l10n::text(l10n::Key::GuiPanelsDecompilerParameter);
  case debugger::DecompilerSymbolKind::None:
    return l10n::text(l10n::Key::GuiPanelsDecompilerToken);
  }
  return l10n::text(l10n::Key::GuiPanelsDecompilerToken);
}

void draw_decompiler_edit_dialogs(
    debugger::DecompilerEngine &decompiler, UiState &ui,
    const debugger::DecompilerSnapshot &decompiled, bool enabled) {
  if (ui.decompiler_dialog == DecompilerDialog::Rename) {
    ImGui::OpenPopup(l10n::label(l10n::Key::GuiPanelsRenameDecompilerItem));
  } else if (ui.decompiler_dialog == DecompilerDialog::SetType) {
    ImGui::OpenPopup(l10n::label(l10n::Key::GuiPanelsSetDecompilerType));
  }

  for (const bool rename : {true, false}) {
    const auto title = rename ? l10n::Key::GuiPanelsRenameDecompilerItem
                              : l10n::Key::GuiPanelsSetDecompilerType;
    if (!ImGui::BeginPopupModal(l10n::label(title), nullptr,
                                ImGuiWindowFlags_NoSavedSettings))
      continue;
    if (!enabled || !ui.decompiler_target) {
      ui.decompiler_dialog = DecompilerDialog::None;
      ImGui::CloseCurrentPopup();
    }
    const DecompilerTarget *target =
        ui.decompiler_target ? &*ui.decompiler_target : nullptr;
    ImGui::Text(l10n::text(l10n::Key::GuiPanelsDecompilerTarget),
                target ? decompiler_target_kind_name(target->kind)
                       : l10n::text(l10n::Key::GuiPanelsDecompilerToken),
                target ? target->text.c_str() : "");
    if (!rename)
      ImGui::TextDisabled("%s",
                          l10n::text(l10n::Key::GuiPanelsDecompilerTypeHelp));
    const auto text = rename ? std::span<char>{ui.decompiler_name_text}
                             : std::span<char>{ui.decompiler_type_text};
    const bool submitted =
        ImGui::InputText(l10n::label(rename ? l10n::Key::GuiPanelsName
                                            : l10n::Key::GuiPanelsType),
                         text.data(), text.size(),
                         ImGuiInputTextFlags_EnterReturnsTrue |
                             ImGuiInputTextFlags_AutoSelectAll);
    draw_error_text(ui.decompiler_message);
    if ((submitted || ImGui::Button(l10n::label(l10n::Key::GuiPanelsApply))) &&
        enabled && target != nullptr) {
      const bool applied = decompiler_apply_edit(decompiler, ui, decompiled,
                                                 *target, rename, text.data());
      if (applied) {
        ui.decompiler_dialog = DecompilerDialog::None;
        ImGui::CloseCurrentPopup();
      }
    }
    ImGui::SameLine();
    if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsCancel)) ||
        ImGui::IsKeyPressed(ImGuiKey_Escape)) {
      ui.decompiler_dialog = DecompilerDialog::None;
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }
}

void draw_decompiler_panel(
    const debugger::SessionSnapshot &snapshot,
    const std::shared_ptr<const debugger::DecompilerSnapshot> &decompiled,
    debugger::DecompilerEngine &decompiler, debugger::LldbEngine &engine,
    UiState &ui, bool control_lease) {
  ImGui::Begin(l10n::label(l10n::Key::WindowDecompiler));
  decompiler_sync_request(ui, *decompiled);
  const bool content_ready =
      decompiler_content_ready(snapshot, *decompiled, ui, control_lease);
  dispatch_navigation_shortcuts(snapshot, engine, ui, true, control_lease);
  const bool follow_requested =
      std::exchange(ui.navigation_follow_requested, false);
  if (decompiled->loading) {
    ImGui::TextDisabled("%s",
                        l10n::text(l10n::Key::GuiPanelsDecompilerLoading));
  } else if (!decompiled->error.empty()) {
    draw_error_text(decompiled->error);
  } else if (decompiled->lines.empty()) {
    ImGui::TextDisabled("%s", l10n::text(l10n::Key::GuiPanelsDecompilerEmpty));
  } else {
    ImGui::Text(l10n::text(l10n::Key::GuiPanelsDecompilerFunctionAddress),
                decompiled->function_file_address);
  }
  if (!decompiled->notice.empty()) {
    ImGui::SameLine();
    ImGui::TextDisabled("%s", decompiled->notice.c_str());
  }
  if (!ui.decompiler_message.empty()) {
    ImGui::TextDisabled("%s", ui.decompiler_message.c_str());
  }
  ImGui::TextDisabled("%s",
                      l10n::text(l10n::Key::GuiPanelsDecompilerNavigationHelp));

  const auto selected_file = selected_file_address(snapshot, ui);
  const auto selected_line =
      decompiler_closest_line(*decompiled, selected_file);
  decompiler_sync_selection(snapshot, *decompiled, ui, selected_line);
  const auto program_counter_line =
      decompiler_program_counter_line(snapshot, *decompiled);

  ImGui::BeginChild("decompiled-code", ImVec2(0.0F, 0.0F),
                    ImGuiChildFlags_Borders,
                    ImGuiWindowFlags_HorizontalScrollbar);
  const bool decompiler_focused =
      ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
  const auto &io = ImGui::GetIO();
  const bool keyboard_navigation =
      decompiler_focused && !control_lease &&
      snapshot.state == debugger::SessionState::Stopped &&
      !decompiled->loading && decompiled->generation == snapshot.generation &&
      navigation_input_allowed(ui) && !io.KeyCtrl && !io.KeyShift &&
      !io.KeyAlt && !io.KeySuper;
  bool keyboard_scrolled = false;
  std::optional<DecompilerNavigationLink> keyboard_target;
  if (ui.decompiler_keyboard_line) {
    if (keyboard_navigation) {
      const bool up = ImGui::IsKeyPressed(ImGuiKey_UpArrow);
      const bool down = ImGui::IsKeyPressed(ImGuiKey_DownArrow);
      if (up || down) {
        decompiler_move_line(snapshot, *decompiled, ui, up, down);
        keyboard_scrolled = true;
      }
    }
    int direction = 0;
    if (keyboard_navigation) {
      if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow))
        direction = -1;
      if (ImGui::IsKeyPressed(ImGuiKey_RightArrow))
        direction = 1;
    }
    keyboard_target =
        decompiler_update_keyboard_target(snapshot, *decompiled, ui, direction);
  }
  bool navigated = false;
  for (std::size_t index = 0; index < decompiled->lines.size(); ++index) {
    const debugger::DecompiledLine &line = decompiled->lines[index];
    const bool selected = ui.decompiler_keyboard_line == index;
    const bool program_counter =
        program_counter_line && *program_counter_line == index;

    ImGui::PushID(static_cast<int>(index));
    const float line_height = ImGui::GetTextLineHeight();
    const bool line_activated = ImGui::Selectable(
        "##decompiled-line", selected, ImGuiSelectableFlags_AllowDoubleClick,
        ImVec2(0.0F, line_height));
    const ImVec2 item_min = ImGui::GetItemRectMin();
    const ImVec2 item_max = ImGui::GetItemRectMax();
    const bool line_hovered = ImGui::IsItemHovered();
    ImDrawList *draw_list = ImGui::GetWindowDrawList();
    if (program_counter && !selected) {
      draw_list->AddRectFilled(item_min, item_max, IM_COL32(100, 100, 20, 110));
    }
    const bool line_marked = ui.decompiler_selection_start &&
                             ui.decompiler_selection_end &&
                             index >= *ui.decompiler_selection_start &&
                             index <= *ui.decompiler_selection_end;
    if (line_marked) {
      draw_list->AddRectFilled(item_min, item_max, IM_COL32(70, 110, 170, 95));
    }
    DecompilerHover hovered;
    float text_x = item_min.x;
    const float mouse_x = ImGui::GetMousePos().x;
    for (const debugger::DecompilerSpan &span : line.spans) {
      const char *begin = line.text.data() + span.start;
      const char *end = begin + span.length;
      const float span_width = ImGui::CalcTextSize(begin, end).x;
      if (selected && decompiler_focused && keyboard_target &&
          keyboard_target->span == &span) {
        const auto offset = keyboard_target->character;
        const auto end_offset = decompiler_word_end(line.text, offset);
        const float start_x =
            text_x + ImGui::CalcTextSize(begin, line.text.data() + offset).x;
        const float end_x =
            start_x + ImGui::CalcTextSize(line.text.data() + offset,
                                          line.text.data() + end_offset)
                          .x;
        draw_list->AddLine(ImVec2(start_x, item_max.y - 1.0F),
                           ImVec2(end_x, item_max.y - 1.0F),
                           ImGui::GetColorU32(ImGuiCol_Text));
      }
      draw_list->AddText(ImVec2(text_x, item_min.y),
                         decompiler_token_color(span.kind), begin, end);
      if (content_ready && line_hovered && mouse_x >= text_x &&
          mouse_x < text_x + span_width) {
        std::size_t character_index = span.start;
        float character_x = text_x;
        for (std::size_t offset = 0; offset < span.length; ++offset) {
          const char *character_begin = begin + offset;
          const float character_width =
              ImGui::CalcTextSize(character_begin, character_begin + 1).x;
          if (mouse_x < character_x + character_width ||
              offset + 1 == span.length) {
            character_index = span.start + offset;
            break;
          }
          character_x += character_width;
        }
        decompiler_resolve_hover(snapshot, *decompiled, ui, line, span,
                                 character_index, hovered);
      }
      text_x += span_width;
    }
    if (hovered.target) {
      ImGui::SetTooltip(
          l10n::text(l10n::Key::GuiPanelsDecompilerTokenDescription),
          decompiler_target_kind_name(hovered.target->kind),
          hovered.target->text.c_str());
    }
    if (hovered.navigation_address) {
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
      ImGui::SetTooltip("0x%" PRIx64, *hovered.navigation_address);
    }
    if (content_ready && line_hovered) {
      if (line_activated && ImGui::IsMouseReleased(ImGuiMouseButton_Left) &&
          hovered.navigation_address &&
          io.MouseDragMaxDistanceSqr[ImGuiMouseButton_Left] <=
              io.MouseDragThreshold * io.MouseDragThreshold) {
        decompiler_select_source(snapshot, *decompiled, ui, line,
                                 hovered.file_address);
        follow_address(snapshot, engine, ui, *hovered.navigation_address);
        navigated = true;
        decompiler_clear_selection(ui);
      } else if (!hovered.navigation_address &&
                 ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) &&
                 !line.file_addresses.empty()) {
        decompiler_select_source(snapshot, *decompiled, ui, line,
                                 hovered.file_address);
        decompiler_navigate_file(snapshot, *decompiled, engine, ui,
                                 line.file_addresses.front());
        navigated = true;
      } else if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        decompiler_begin_selection(snapshot, *decompiled, ui, line, index,
                                   hovered.file_address);
      } else if (ImGui::IsMouseDragging(ImGuiMouseButton_Left) &&
                 ui.decompiler_selection_anchor) {
        decompiler_extend_selection(ui, index);
      }
    }
    if (content_ready && line_hovered) {
      decompiler_update_context(snapshot, *decompiled, ui, line, hovered);
    }

    if (!navigated && selected &&
        (keyboard_scrolled ||
         (selected_file && ui.decompiler_scroll_selection != *selected_file))) {
      ImGui::SetScrollHereY(0.5F);
      if (selected_file)
        ui.decompiler_scroll_selection = *selected_file;
    }
    if (ImGui::BeginPopupContextItem("decompiler-context")) {
      if (ui.decompiler_selection_start && ui.decompiler_selection_end) {
        if (ImGui::MenuItem(
                l10n::label(l10n::Key::GuiPanelsCopyDecompilerLines),
                "Ctrl+C")) {
          const std::string text = selected_decompiler_text(
              decompiled->lines, *ui.decompiler_selection_start,
              *ui.decompiler_selection_end);
          ImGui::SetClipboardText(text.c_str());
        }
        ImGui::Separator();
      }
      ImGui::BeginDisabled(!content_ready);
      const DecompilerTarget *target = ui.decompiler_context_target
                                           ? &*ui.decompiler_context_target
                                           : nullptr;
      if (target != nullptr &&
          target->kind != debugger::DecompilerSymbolKind::None) {
        ImGui::TextDisabled(
            l10n::text(l10n::Key::GuiPanelsDecompilerTokenDescription),
            decompiler_target_kind_name(target->kind), target->text.c_str());
        ImGui::BeginDisabled(!decompiler_target_renamable(*target));
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsRename), "N")) {
          open_decompiler_dialog(ui, DecompilerDialog::Rename, *target,
                                 target->name);
        }
        ImGui::EndDisabled();
        ImGui::BeginDisabled(!decompiler_target_typable(*target));
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsSetType), "Y")) {
          open_decompiler_dialog(ui, DecompilerDialog::SetType, *target, "");
        }
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsSetPointerType),
                            "P")) {
          open_decompiler_dialog(ui, DecompilerDialog::SetType, *target,
                                 "void *");
        }
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsSetByteArrayType),
                            "[")) {
          open_decompiler_dialog(ui, DecompilerDialog::SetType, *target,
                                 "uint8_t[16]");
        }
        if (ImGui::MenuItem(
                l10n::label(l10n::Key::GuiPanelsConvertStructPointer),
                "Shift+[")) {
          open_decompiler_dialog(ui, DecompilerDialog::SetType, *target,
                                 "struct type *");
        }
        ImGui::EndDisabled();
        ImGui::BeginDisabled(!target->has_reference_file_address);
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsMarkString), "A")) {
          mark_decompiler_string(decompiler, ui, engine, snapshot, *decompiled,
                                 *target);
        }
        ImGui::EndDisabled();
        ImGui::Separator();
      }
      const std::optional<std::uint64_t> context_load_address =
          ui.decompiler_context_load_address;
      if (!context_load_address) {
        ImGui::TextDisabled(
            "%s", l10n::text(l10n::Key::GuiPanelsCursorAddressUnavailable));
      } else {
        const std::uint64_t load_address = *context_load_address;
        ImGui::BeginDisabled(snapshot.session.epoch.empty());
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiSessionEditComment))) {
          decompiler_request_comment(snapshot, *decompiled, ui, load_address);
        }
        ImGui::EndDisabled();
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsShowDisassembly))) {
          decompiler_select_source(
              snapshot, *decompiled, ui, line,
              ui.decompiler_context_target &&
                      ui.decompiler_context_target->has_cursor_file_address
                  ? std::optional{ui.decompiler_context_target
                                      ->cursor_file_address}
                  : std::nullopt);
          follow_disassembly(engine, ui, load_address);
          navigated = true;
        }
        ImGui::BeginDisabled(control_lease);
        draw_breakpoint_context_actions(snapshot, engine, ui, load_address);
        ImGui::EndDisabled();
        ImGui::Separator();
        ImGui::BeginDisabled(control_lease ||
                             snapshot.state != debugger::SessionState::Stopped);
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsRunToCursor),
                            "F4")) {
          ui.disassembly_cursor = load_address;
          engine.run_to_address(load_address);
        }
        ImGui::EndDisabled();
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsFollowMemory)))
          follow_memory(engine, ui, load_address);
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsShowMemoryMap)))
          show_in_memory_map(ui, load_address);
      }
      ImGui::EndDisabled();
      ImGui::EndPopup();
    }
    ImGui::PopID();
  }
  if (follow_requested && !navigated && keyboard_target &&
      ui.decompiler_keyboard_line) {
    decompiler_select_source(
        snapshot, *decompiled, ui,
        decompiled->lines[*ui.decompiler_keyboard_line],
        keyboard_target->span->has_file_address
            ? std::optional{keyboard_target->span->file_address}
            : std::nullopt);
    follow_address(snapshot, engine, ui, keyboard_target->address);
  }
  if (decompiler_focused && !ImGui::GetIO().WantTextInput &&
      ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C) &&
      ui.decompiler_selection_start && ui.decompiler_selection_end) {
    const std::string text = selected_decompiler_text(
        decompiled->lines, *ui.decompiler_selection_start,
        *ui.decompiler_selection_end);
    ImGui::SetClipboardText(text.c_str());
  }
  if (content_ready && decompiler_focused && !ImGui::GetIO().WantTextInput &&
      ui.decompiler_target) {
    const DecompilerTarget &target = *ui.decompiler_target;
    if (ImGui::IsKeyPressed(ImGuiKey_N) &&
        decompiler_target_renamable(target)) {
      open_decompiler_dialog(ui, DecompilerDialog::Rename, target, target.name);
    } else if (ImGui::IsKeyPressed(ImGuiKey_Y) &&
               decompiler_target_typable(target)) {
      open_decompiler_dialog(ui, DecompilerDialog::SetType, target, "");
    } else if (ImGui::IsKeyPressed(ImGuiKey_A) &&
               target.has_reference_file_address) {
      mark_decompiler_string(decompiler, ui, engine, snapshot, *decompiled,
                             target);
    } else if (ImGui::IsKeyPressed(ImGuiKey_P) &&
               decompiler_target_typable(target)) {
      open_decompiler_dialog(ui, DecompilerDialog::SetType, target, "void *");
    } else if (ImGui::IsKeyPressed(ImGuiKey_LeftBracket) &&
               decompiler_target_typable(target)) {
      open_decompiler_dialog(ui, DecompilerDialog::SetType, target,
                             ImGui::GetIO().KeyShift
                                 ? std::string_view{"struct type *"}
                                 : std::string_view{"uint8_t[16]"});
    }
  }
  draw_decompiler_edit_dialogs(decompiler, ui, *decompiled, content_ready);
  ImGui::EndChild();
  ImGui::End();
}

} // namespace mydbg::app
