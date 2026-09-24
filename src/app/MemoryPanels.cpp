#include "app/MemoryPanels.h"
#include "app/AppActions.h"
#include "app/AppMenus.h"
#include "app/AppState.h"
#include "app/DebuggerController.h"
#include "app/DebuggerPanels.h"
#include "app/DisassemblyText.h"
#include "app/MemoryData.h"
#include "app/MemoryInspection.h"
#include "app/UiSupport.h"
#include "localization/Localization.h"

#include <imgui_internal.h>

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <limits>
#include <utility>

namespace mydbg::app {

namespace {
std::string memory_string_at(const debugger::SessionSnapshot &snapshot,
                             std::uint64_t address) {
  auto text = memory_inspection_string_at(snapshot, address);
  if (!text) {
    return l10n::text(l10n::Key::GuiPanelsOutsideCurrentDump);
  }
  return text->empty()
             ? std::string{l10n::text(l10n::Key::GuiPanelsEmptyString)}
             : std::move(*text);
}
} // namespace

void draw_typed_memory_hints(const debugger::SessionSnapshot &snapshot,
                             UiState &ui) {
  const auto dump_end = debugger_memory_visible_hint_end(snapshot, ui);
  if (!dump_end) {
    return;
  }
  if (!ImGui::CollapsingHeader(
          l10n::label(l10n::Key::GuiPanelsTypedDecompilerView),
          ImGuiTreeNodeFlags_DefaultOpen)) {
    return;
  }
  for (const MemoryTypeHint &hint : ui.memory_type_hints) {
    if (hint.address < snapshot.memory_base || hint.address >= *dump_end) {
      continue;
    }
    ImGui::PushID(static_cast<int>(hint.address));
    if (hint.string) {
      ImGui::BulletText(l10n::text(l10n::Key::GuiPanelsTypedString),
                        hint.address, hint.label.c_str(),
                        memory_string_at(snapshot, hint.address).c_str());
    } else {
      ImGui::BulletText(l10n::text(l10n::Key::GuiPanelsTypedValue),
                        hint.address, hint.label.c_str(), hint.type.c_str());
      const auto fields = parse_inline_struct_fields(
          hint.type,
          snapshot.address_byte_size == 0 ? 8U : snapshot.address_byte_size);
      if (!fields.empty()) {
        std::uint64_t field_address = hint.address;
        ImGui::Indent();
        for (const ParsedField &field : fields) {
          const auto value =
              read_memory_unsigned(snapshot, field_address, field.width);
          if (value) {
            ImGui::Text("+0x%04" PRIx64 " %-24s %-16s = 0x%" PRIx64,
                        field_address - hint.address, field.type.c_str(),
                        field.name.c_str(), *value);
          } else {
            ImGui::TextDisabled(
                l10n::text(l10n::Key::GuiPanelsFieldOutsideDump),
                field_address - hint.address, field.type.c_str(),
                field.name.c_str());
          }
          field_address += field.width;
        }
        ImGui::Unindent();
      } else if (const std::size_t width = primitive_type_width(
                     hint.type, snapshot.address_byte_size == 0
                                    ? 8U
                                    : snapshot.address_byte_size);
                 width != 0) {
        if (const auto value =
                read_memory_unsigned(snapshot, hint.address, width)) {
          ImGui::Indent();
          ImGui::Text(l10n::text(l10n::Key::GuiPanelsMemoryValue), *value);
          ImGui::Unindent();
        }
      }
    }
    ImGui::PopID();
  }
}

void draw_memory_panel(const debugger::SessionSnapshot &snapshot,
                       debugger::LldbEngine &engine, UiState &ui) {
  ImGui::Begin(l10n::label(l10n::Key::WindowMemoryDump));
  const bool controls_locked = (ImGui::GetCurrentContext()->CurrentItemFlags &
                                ImGuiItemFlags_Disabled) != 0;
  const bool dump_changed = debugger_sync_memory_selection(snapshot, ui);
  // The final motion and release can arrive in the same frame. Consume that
  // position before ending the selection gesture.
  const bool selection_released = ImGui::IsMouseReleased(ImGuiMouseButton_Left);
  if (controls_locked ||
      (!ImGui::IsMouseDown(ImGuiMouseButton_Left) && !selection_released)) {
    ui.memory_selection_dragging = false;
  }
  const auto copy_bytes = [&](MemoryCopyFormat format, MemoryByteOrder order,
                              std::size_t word_size) {
    if (debugger_memory_has_selection(snapshot, ui)) {
      if (const auto text = format_memory_bytes(
              debugger_memory_selected_bytes(snapshot, ui), format, order,
              word_size, snapshot.byte_order)) {
        ImGui::SetClipboardText(text->c_str());
      }
    }
  };
  const bool edit_mode_at_frame_start = ui.memory_edit_mode;
  const bool submitted = ImGui::InputTextWithHint(
      "##memory-address", l10n::text(l10n::Key::GuiPanelsMemoryAddressHint),
      ui.memory_address.data(), ui.memory_address.size(),
      ImGuiInputTextFlags_EnterReturnsTrue);
  ImGui::SameLine();
  if (submitted || ImGui::Button(l10n::label(l10n::Key::GuiPanelsGo))) {
    engine.execute_command(std::string{"dump "} + ui.memory_address.data());
  }
  ImGui::SameLine();
  ImGui::BeginDisabled(controls_locked ||
                       snapshot.state != debugger::SessionState::Stopped);
  if (ImGui::Button(l10n::label(l10n::Key::GuiPanelsStack))) {
    follow_memory(engine, ui, snapshot.sp);
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  const bool can_edit = !controls_locked &&
                        snapshot.state == debugger::SessionState::Stopped &&
                        !snapshot.memory.empty();
  if (!can_edit) {
    ui.memory_edit_mode = false;
    ui.memory_edit_focus.reset();
  }
  const auto draw_edit_mode_action = [&] {
    if (ImGui::MenuItem(
            ui.memory_edit_mode
                ? l10n::label(l10n::Key::GuiPanelsLeaveMemoryEditMode)
                : l10n::label(l10n::Key::GuiPanelsEnterMemoryEditMode),
            nullptr, false, can_edit)) {
      ui.memory_edit_mode = !ui.memory_edit_mode;
      if (!ui.memory_edit_mode) {
        ui.memory_edit_focus.reset();
      }
    }
  };
  ImGui::BeginDisabled(!can_edit);
  if (ImGui::Checkbox(l10n::label(l10n::Key::GuiPanelsEdit),
                      &ui.memory_edit_mode) &&
      !ui.memory_edit_mode) {
    ui.memory_edit_focus.reset();
  }
  ImGui::EndDisabled();
  if (ImGui::IsItemHovered()) {
    ImGui::SetTooltip("%s", l10n::text(l10n::Key::GuiPanelsMemoryEditHelp));
  }
  ImGui::SameLine();
  ImGui::TextDisabled(l10n::text(l10n::Key::GuiPanelsTrackedPatches),
                      snapshot.patches.size());

  const std::size_t editable_count =
      std::min(ui.memory_edit_bytes.size(), snapshot.memory.size());
  debugger_sync_memory_editor(snapshot, ui, dump_changed, editable_count);
  draw_error_text(ui.memory_edit_error);
  draw_typed_memory_hints(snapshot, ui);
  ImGui::PushStyleColor(ImGuiCol_Text,
                        ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
  ImGui::TextWrapped("%s", l10n::text(l10n::Key::GuiPanelsMemorySelectionHelp));
  ImGui::PopStyleColor();
  if (ui.memory_edit_mode && editable_count < snapshot.memory.size()) {
    ImGui::TextDisabled(l10n::text(l10n::Key::GuiPanelsMemoryEditLimit),
                        editable_count);
  }
  if (debugger_memory_has_selection(snapshot, ui)) {
    ImGui::Text(l10n::text(l10n::Key::GuiPanelsMemorySelection),
                snapshot.memory_base + debugger_memory_selection_start(ui),
                snapshot.memory_base + debugger_memory_selection_end(ui),
                debugger_memory_selection_end(ui) -
                    debugger_memory_selection_start(ui) + 1);
  } else {
    ImGui::Dummy(ImVec2(0.0F, ImGui::GetTextLineHeight()));
  }

  bool open_byte_context = false;
  bool memory_focused =
      ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
  std::optional<std::size_t> drag_offset;
  float drag_distance = std::numeric_limits<float>::max();
  const auto interact_with_byte = [&](std::size_t offset, bool editing) {
    const bool hovered =
        ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem);
    if (!controls_locked && hovered &&
        ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
      debugger_select_memory_byte(snapshot, ui, offset, ImGui::GetIO().KeyShift,
                                  editing);
    }
    if (!controls_locked && hovered &&
        ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
      debugger_select_memory_context(snapshot, ui, offset);
      open_byte_context = true;
    }
    if (ui.memory_selection_dragging && ImGui::IsItemVisible()) {
      const ImVec2 mouse = ImGui::GetIO().MousePos;
      const ImVec2 minimum = ImGui::GetItemRectMin();
      const ImVec2 maximum = ImGui::GetItemRectMax();
      const float dx =
          std::max({minimum.x - mouse.x, 0.0F, mouse.x - maximum.x});
      const float dy =
          std::max({minimum.y - mouse.y, 0.0F, mouse.y - maximum.y});
      const float distance = dx * dx + dy * dy;
      if (distance < drag_distance) {
        drag_distance = distance;
        drag_offset = offset;
      }
    }
  };
  const auto byte_selected = [&](std::size_t offset) {
    return debugger_memory_has_selection(snapshot, ui) &&
           offset >= debugger_memory_selection_start(ui) &&
           offset <= debugger_memory_selection_end(ui);
  };
  const auto draw_byte = [&](std::size_t offset, const char *text,
                             ImVec2 size) {
    const ImVec2 position = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("##select-byte", size,
                           ImGuiButtonFlags_MouseButtonLeft |
                               ImGuiButtonFlags_MouseButtonRight);
    interact_with_byte(offset, false);
    ImDrawList *draw = ImGui::GetWindowDrawList();
    if (byte_selected(offset)) {
      draw->AddRectFilled(position,
                          ImVec2(position.x + size.x, position.y + size.y),
                          ImGui::GetColorU32(ImGuiCol_TextSelectedBg));
    }
    draw->AddText(position, ImGui::GetColorU32(ImGuiCol_Text), text);
  };

  constexpr std::size_t bytes_per_row = 16;
  constexpr int column_count = static_cast<int>(bytes_per_row) + 2;
  const ImGuiStyle &style = ImGui::GetStyle();
  const float compact_cell_padding_x =
      std::max(1.0F, style.CellPadding.x * 0.25F);
  const float compact_cell_padding_y =
      std::max(1.0F, style.CellPadding.y * 0.5F);
  const float compact_frame_padding_x =
      std::max(2.0F, style.FramePadding.x * 0.5F);
  const float compact_frame_padding_y =
      std::max(1.0F, style.FramePadding.y * 0.5F);
  const float byte_editor_width =
      ImGui::CalcTextSize("FF").x + compact_frame_padding_x * 2.0F + 1.0F;
  const float byte_column_width =
      byte_editor_width + compact_cell_padding_x * 2.0F;
  const float address_column_width =
      ImGui::CalcTextSize("0x0000000000000000").x +
      compact_cell_padding_x * 2.0F;
  const float ascii_column_width =
      ImGui::CalcTextSize("................").x + compact_cell_padding_x * 2.0F;
  ImGui::PushStyleVar(ImGuiStyleVar_CellPadding,
                      ImVec2(compact_cell_padding_x, compact_cell_padding_y));
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
                      ImVec2(compact_frame_padding_x, compact_frame_padding_y));
  bool memory_editor_hovered = false;
  if (ImGui::BeginTable("memory-hex", column_count,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                            ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY |
                            ImGuiTableFlags_SizingFixedFit)) {
    ImGui::TableSetupScrollFreeze(1, 1);
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsAddressColumn),
                            ImGuiTableColumnFlags_WidthFixed,
                            address_column_width);
    for (std::size_t index = 0; index < bytes_per_row; ++index) {
      char heading[3]{};
      std::snprintf(heading, sizeof(heading), "%02zX", index);
      ImGui::TableSetupColumn(heading, ImGuiTableColumnFlags_WidthFixed,
                              byte_column_width);
    }
    ImGui::TableSetupColumn(l10n::label(l10n::Key::GuiPanelsAsciiColumn),
                            ImGuiTableColumnFlags_WidthFixed,
                            ascii_column_width);
    ImGui::TableHeadersRow();

    for (std::size_t offset = 0; offset < snapshot.memory.size();
         offset += bytes_per_row) {
      ImGui::PushID(static_cast<int>(offset));
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      const std::uint64_t row_address = snapshot.memory_base + offset;
      ImGui::Text("0x%" PRIx64, row_address);
      if (ImGui::BeginPopupContextItem("memory-address-context")) {
        draw_edit_mode_action();
        ImGui::Separator();
        draw_breakpoint_context_actions(snapshot, engine, ui, row_address);
        ImGui::Separator();
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsUseDumpAddress))) {
          follow_memory(engine, ui, row_address);
        }
        if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsShowMemoryMap))) {
          show_in_memory_map(ui, row_address);
        }
        ImGui::EndPopup();
      }

      const std::size_t count =
          std::min(bytes_per_row, snapshot.memory.size() - offset);
      for (std::size_t index = 0; index < bytes_per_row; ++index) {
        ImGui::TableSetColumnIndex(static_cast<int>(index) + 1);
        if (index >= count) {
          continue;
        }
        const std::size_t byte_offset = offset + index;
        const std::uint64_t byte_address = snapshot.memory_base + byte_offset;
        const bool patched =
            debugger_memory_byte_is_patched(snapshot, byte_address);
        if (patched) {
          ImGui::PushStyleColor(ImGuiCol_Text,
                                ImVec4(1.0F, 0.68F, 0.20F, 1.0F));
        }
        ImGui::PushID(static_cast<int>(index));
        if (ui.memory_edit_mode && byte_offset < editable_count) {
          if (byte_selected(byte_offset)) {
            ImGui::TableSetBgColor(ImGuiTableBgTarget_CellBg,
                                   ImGui::GetColorU32(ImGuiCol_TextSelectedBg));
          }
          if (ui.memory_edit_focus == byte_offset) {
            ImGui::SetKeyboardFocusHere();
            ui.memory_edit_focus.reset();
          }
          ImGui::SetNextItemWidth(byte_editor_width);
          const bool byte_submitted = ImGui::InputText(
              "##byte", ui.memory_edit_bytes[byte_offset].data(),
              ui.memory_edit_bytes[byte_offset].size(),
              ImGuiInputTextFlags_CharsHexadecimal |
                  ImGuiInputTextFlags_AutoSelectAll |
                  ImGuiInputTextFlags_EnterReturnsTrue);
          interact_with_byte(byte_offset, true);
          if (byte_submitted || ImGui::IsItemDeactivatedAfterEdit()) {
            debugger_patch_memory_byte(snapshot, engine, ui, byte_offset,
                                       byte_address);
          }
        } else {
          char text[3]{};
          std::snprintf(
              text, sizeof(text), "%02X",
              static_cast<unsigned int>(snapshot.memory[byte_offset]));
          draw_byte(byte_offset, text,
                    ImVec2(byte_editor_width, ImGui::GetTextLineHeight()));
        }
        if (can_edit && byte_offset < editable_count &&
            ImGui::IsItemHovered() &&
            ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
          ui.memory_edit_mode = true;
          ui.memory_edit_focus = byte_offset;
          ui.memory_selection_dragging = false;
        }
        if (patched) {
          ImGui::PopStyleColor();
        }
        ImGui::PopID();
      }

      ImGui::TableSetColumnIndex(column_count - 1);
      ImGui::PushID("ascii");
      for (std::size_t index = 0; index < count; ++index) {
        if (index != 0) {
          ImGui::SameLine(0.0F, 0.0F);
        }
        ImGui::PushID(static_cast<int>(index));
        const unsigned char value = snapshot.memory[offset + index];
        const char text[] = {
            value >= 0x20U && value <= 0x7eU ? static_cast<char>(value) : '.',
            '\0'};
        draw_byte(
            offset + index, text,
            ImVec2(ImGui::CalcTextSize("F").x, ImGui::GetTextLineHeight()));
        ImGui::PopID();
      }
      ImGui::PopID();
      ImGui::PopID(); // Row scope; ASCII has its own byte IDs.
    }
    memory_editor_hovered =
        ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem);
    memory_focused =
        memory_focused ||
        ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
    if (ui.memory_selection_dragging && memory_editor_hovered) {
      if (drag_offset) {
        ui.memory_selection_end = *drag_offset;
      }
      if (!selection_released) {
        const ImRect visible = ImGui::GetCurrentWindow()->InnerClipRect;
        const float edge = ImGui::GetTextLineHeightWithSpacing();
        const float mouse_y = ImGui::GetIO().MousePos.y;
        const float speed = edge * 20.0F * ImGui::GetIO().DeltaTime;
        if (mouse_y < visible.Min.y + edge) {
          ImGui::SetScrollY(std::max(0.0F, ImGui::GetScrollY() - speed));
        } else if (mouse_y > visible.Max.y - edge) {
          ImGui::SetScrollY(ImGui::GetScrollY() + speed);
        }
      }
    }
    ImGui::EndTable();
  }
  if (selection_released) {
    ui.memory_selection_dragging = false;
  }
  ImGui::PopStyleVar(2);
  if (memory_focused && !controls_locked && !ui.keybinding_capture &&
      !ImGui::GetIO().WantTextInput && ImGui::GetActiveID() == 0 &&
      !ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId |
                                       ImGuiPopupFlags_AnyPopupLevel) &&
      ImGui::GetIO().KeyCtrl) {
    if (ImGui::IsKeyPressed(ImGuiKey_A) && !snapshot.memory.empty()) {
      ui.memory_selection_anchor = 0;
      ui.memory_selection_end = snapshot.memory.size() - 1;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_C)) {
      copy_bytes(MemoryCopyFormat::Hex, MemoryByteOrder::AsStored, 1);
    }
  }
  if (open_byte_context) {
    ImGui::OpenPopup("memory-selection-context");
  }
  if (ImGui::BeginPopup("memory-selection-context")) {
    if (!debugger_memory_has_selection(snapshot, ui) || dump_changed) {
      ImGui::CloseCurrentPopup();
    } else {
      const std::size_t first = debugger_memory_selection_start(ui);
      const std::size_t count = debugger_memory_selection_end(ui) - first + 1;
      ImGui::Text(l10n::text(l10n::Key::GuiPanelsMemorySelection),
                  snapshot.memory_base + first,
                  snapshot.memory_base + debugger_memory_selection_end(ui),
                  count);
      const auto [pointer_width, full_pointer, known_byte_order, pointer] =
          debugger_memory_pointer(snapshot, first);
      if (pointer) {
        ImGui::Text(l10n::text(l10n::Key::GuiPanelsMemoryPointer),
                    snapshot.memory_base + first, *pointer,
                    snapshot.address_byte_size);
      } else {
        ImGui::TextDisabled(
            "%s", l10n::text(l10n::Key::GuiPanelsMemoryPointerUnavailable));
      }
      if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsSelectPointer),
                          nullptr, false, full_pointer)) {
        ui.memory_selection_anchor = first;
        ui.memory_selection_end = first + pointer_width - 1;
      }
      const bool pointer_navigable =
          pointer && navigable_address(snapshot, *pointer);
      ImGui::BeginDisabled(controls_locked ||
                           snapshot.state != debugger::SessionState::Stopped ||
                           !pointer_navigable);
      if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsFollowPointer))) {
        follow_address(snapshot, engine, ui, *pointer);
        const bool code_destination =
            debugger_memory_address_is_code(snapshot, *pointer);
        if (code_destination) {
          ImGui::SetWindowCollapsed(l10n::label(l10n::Key::WindowDisassembly),
                                    false);
          ImGui::SetWindowFocus(l10n::label(l10n::Key::WindowDisassembly));
        }
      }
      if (ImGui::MenuItem(
              l10n::label(l10n::Key::GuiPanelsFollowPointerDisassembly))) {
        follow_disassembly(engine, ui, *pointer);
        ImGui::SetWindowCollapsed(l10n::label(l10n::Key::WindowDisassembly),
                                  false);
        ImGui::SetWindowFocus(l10n::label(l10n::Key::WindowDisassembly));
      }
      if (ImGui::MenuItem(
              l10n::label(l10n::Key::GuiPanelsFollowPointerMemory))) {
        follow_memory(engine, ui, *pointer);
        ImGui::SetWindowCollapsed(l10n::label(l10n::Key::WindowMemoryDump),
                                  false);
        ImGui::SetWindowFocus(l10n::label(l10n::Key::WindowMemoryDump));
      }
      ImGui::EndDisabled();
      if (pointer && !pointer_navigable) {
        ImGui::TextDisabled(
            "%s", l10n::text(l10n::Key::GuiPanelsMemoryPointerNotNavigable));
      }
      ImGui::Separator();
      if (ImGui::MenuItem(l10n::label(l10n::Key::GuiPanelsCopyHexBytes),
                          "Ctrl+C")) {
        copy_bytes(MemoryCopyFormat::Hex, MemoryByteOrder::AsStored, 1);
      }
      if (ImGui::BeginMenu(l10n::label(l10n::Key::GuiPanelsMemoryCopyAs))) {
        ImGui::TextUnformatted(l10n::text(l10n::Key::GuiPanelsMemoryCopyOrder));
        const auto order_option = [&](l10n::Key label, MemoryByteOrder order) {
          if (ImGui::RadioButton(l10n::label(label),
                                 ui.memory_copy_order == order)) {
            ui.memory_copy_order = order;
          }
        };
        order_option(l10n::Key::GuiPanelsMemoryAsStored,
                     MemoryByteOrder::AsStored);
        order_option(l10n::Key::GuiPanelsMemoryLittleEndian,
                     MemoryByteOrder::LittleEndian);
        order_option(l10n::Key::GuiPanelsMemoryBigEndian,
                     MemoryByteOrder::BigEndian);
        ImGui::Separator();
        ImGui::TextUnformatted(l10n::text(l10n::Key::GuiPanelsMemoryWordSize));
        ImGui::BeginDisabled(ui.memory_copy_order == MemoryByteOrder::AsStored);
        const auto word_option = [&](l10n::Key label, std::size_t width) {
          if (ImGui::RadioButton(l10n::label(label),
                                 ui.memory_copy_word_size == width)) {
            ui.memory_copy_word_size = width;
          }
        };
        word_option(l10n::Key::GuiPanelsMemoryWord16, 2);
        word_option(l10n::Key::GuiPanelsMemoryWord32, 4);
        word_option(l10n::Key::GuiPanelsMemoryWord64, 8);
        ImGui::EndDisabled();
        ImGui::Text(l10n::text(l10n::Key::GuiPanelsByteOrder),
                    byte_order_text(snapshot.byte_order));
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
                               ImGui::GetFontSize() * 32.0F);
        ImGui::TextUnformatted(
            l10n::text(l10n::Key::GuiPanelsMemoryCopyOrderHelp));
        const bool can_copy = can_format_memory_bytes(
            count, ui.memory_copy_order, ui.memory_copy_word_size,
            snapshot.byte_order);
        if (!can_copy) {
          ImGui::TextDisabled(
              "%s",
              l10n::text(known_byte_order
                             ? l10n::Key::GuiPanelsMemoryCopyPartialWord
                             : l10n::Key::GuiPanelsMemoryCopyUnknownEndian));
        }
        ImGui::PopTextWrapPos();
        ImGui::Separator();
        ImGui::BeginDisabled(!can_copy);
        const auto copy_option = [&](l10n::Key label, MemoryCopyFormat format) {
          if (ImGui::MenuItem(l10n::label(label))) {
            copy_bytes(format, ui.memory_copy_order, ui.memory_copy_word_size);
          }
        };
        copy_option(l10n::Key::GuiPanelsMemoryHex, MemoryCopyFormat::Hex);
        copy_option(l10n::Key::GuiPanelsMemoryEscaped,
                    MemoryCopyFormat::Escaped);
        copy_option(l10n::Key::GuiPanelsMemoryCArray, MemoryCopyFormat::CArray);
        copy_option(l10n::Key::GuiPanelsMemoryPython,
                    MemoryCopyFormat::PythonBytearray);
        copy_option(l10n::Key::GuiPanelsMemoryJavaScript,
                    MemoryCopyFormat::JavaScriptUint8Array);
        copy_option(l10n::Key::GuiPanelsMemoryRust,
                    MemoryCopyFormat::RustArray);
        ImGui::EndDisabled();
        ImGui::EndMenu();
      }
      const auto integer_option = [&](l10n::Key label, MemoryByteOrder order) {
        if (ImGui::MenuItem(l10n::label(label), nullptr, false, count <= 8)) {
          if (const auto text = format_memory_integer(
                  debugger_memory_selected_bytes(snapshot, ui), order)) {
            ImGui::SetClipboardText(text->c_str());
          }
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
          ImGui::SetTooltip("%s",
                            l10n::text(l10n::Key::GuiPanelsMemoryIntegerHelp));
        }
      };
      integer_option(l10n::Key::GuiPanelsMemoryIntegerLE,
                     MemoryByteOrder::LittleEndian);
      integer_option(l10n::Key::GuiPanelsMemoryIntegerBE,
                     MemoryByteOrder::BigEndian);
      ImGui::Separator();
      draw_edit_mode_action();
    }
    ImGui::EndPopup();
  }
  const bool cancel_edit_with_escape =
      edit_mode_at_frame_start && ImGui::IsKeyPressed(ImGuiKey_Escape);
  const bool cancel_edit_with_outside_click =
      edit_mode_at_frame_start &&
      ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !memory_editor_hovered;
  if (cancel_edit_with_escape || cancel_edit_with_outside_click) {
    ui.memory_edit_mode = false;
    ui.memory_edit_focus.reset();
  }
  if (ImGui::BeginPopupContextWindow("memory-window-context",
                                     ImGuiPopupFlags_NoOpenOverItems)) {
    draw_edit_mode_action();
    ImGui::EndPopup();
  }
  ImGui::End();
}

} // namespace mydbg::app
