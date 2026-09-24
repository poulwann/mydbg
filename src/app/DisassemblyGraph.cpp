#include "app/DisassemblyGraph.h"
#include "app/AppActions.h"
#include "app/AppState.h"
#include "app/DebuggerPanels.h"
#include "app/DisassemblyGraphLayout.h"
#include "app/DisassemblyTextDrawing.h"
#include "app/UiSupport.h"
#include "localization/Localization.h"

#include <algorithm>
#include <cinttypes>
#include <cmath>
#include <limits>
#include <utility>

namespace mydbg::app {
namespace {

constexpr std::size_t no_block = std::numeric_limits<std::size_t>::max();
using EdgeKind = debugger::DisassemblyGraphEdge::Kind;

bool contains(ImVec2 point, ImVec2 position, ImVec2 size) {
  return point.x >= position.x && point.x < position.x + size.x &&
         point.y >= position.y && point.y < position.y + size.y;
}

} // namespace

struct DisassemblyGraphView {
  DisassemblyGraphLayout layout;
  ImVec2 pan;
  float zoom{1.0F};
  bool positioned{};
  bool background_drag{};
  std::uint64_t generation{};
  std::uint64_t stop_revision{};
  std::optional<std::uint64_t> observed_cursor;
  std::optional<std::uint64_t> pending_center;
  std::optional<std::uint64_t> popup_address;
};

namespace {

bool center_address(DisassemblyGraphView &view, std::uint64_t address,
                    ImVec2 canvas_size) {
  const auto found = view.layout.rows.find(address);
  if (found == view.layout.rows.end()) {
    return false;
  }
  const auto [block, row] = found->second;
  const auto &layout = view.layout.blocks[block];
  const ImVec2 point(layout.position.x + layout.size.x * 0.5F,
                     layout.position.y + view.layout.header_height +
                         layout.rows[row].offset +
                         layout.rows[row].height * 0.5F);
  view.pan = ImVec2(canvas_size.x * 0.5F - point.x * view.zoom,
                    canvas_size.y * 0.5F - point.y * view.zoom);
  view.positioned = true;
  return true;
}

ImU32 edge_color(EdgeKind kind) {
  const auto &background = ImGui::GetStyleColorVec4(ImGuiCol_WindowBg);
  const bool dark = background.x + background.y + background.z < 1.5F;
  switch (kind) {
  case EdgeKind::Taken:
    return dark ? IM_COL32(104, 211, 135, 255) : IM_COL32(20, 119, 55, 255);
  case EdgeKind::Fallthrough:
    return dark ? IM_COL32(240, 137, 117, 255) : IM_COL32(183, 61, 38, 255);
  case EdgeKind::Jump:
    return ImGui::GetColorU32(ImGuiCol_SliderGrabActive);
  }
  return ImGui::GetColorU32(ImGuiCol_Text);
}

} // namespace

void draw_disassembly_graph(const debugger::SessionSnapshot &snapshot,
                            debugger::LldbEngine &engine, UiState &ui,
                            bool control_lease) {
  const bool follow_requested =
      std::exchange(ui.navigation_follow_requested, false);
  const auto &graph = snapshot.disassembly_graph;
  if (!graph) {
    if (snapshot.state == debugger::SessionState::Stopped) {
      ImGui::TextDisabled("%s",
                          snapshot.instructions.empty()
                              ? l10n::text(l10n::Key::GuiGraphNoInstructions)
                              : l10n::text(l10n::Key::GuiGraphLoading));
    } else if (snapshot.state == debugger::SessionState::Running ||
               snapshot.state == debugger::SessionState::Launching ||
               snapshot.state == debugger::SessionState::Connecting) {
      ImGui::TextDisabled("%s", l10n::text(l10n::Key::GuiGraphPauseToInspect));
    } else if (snapshot.target_path.empty()) {
      ImGui::TextDisabled("%s", l10n::text(l10n::Key::GuiGraphLoadTarget));
    } else {
      ImGui::TextDisabled("%s", l10n::text(l10n::Key::GuiGraphStartOrAttach));
    }
    return;
  }
  if (!graph->status.empty()) {
    ImGui::TextWrapped("%s", graph->status.c_str());
  }
  if (graph->blocks.empty()) {
    if (graph->status.empty()) {
      ImGui::TextDisabled("%s", l10n::text(l10n::Key::GuiGraphNoBasicBlocks));
    }
    return;
  }
  if (!ui.disassembly_graph_state) {
    ui.disassembly_graph_state = std::make_shared<DisassemblyGraphView>();
    ui.disassembly_graph_state->generation = snapshot.generation;
    ui.disassembly_graph_state->stop_revision = snapshot.stop_revision;
  }
  auto &view = *ui.disassembly_graph_state;
  if (view.layout.graph != graph || view.layout.font != ImGui::GetFont() ||
      view.layout.font_size != ImGui::GetFontSize() ||
      view.layout.architecture != snapshot.architecture) {
    if (!view.pending_center) {
      view.pending_center = ui.disassembly_cursor;
    }
    disassembly_graph_build_layout(view.layout, graph, snapshot.architecture,
                                   ImGui::GetFont(), ImGui::GetFontSize());
  }
  if (!view.observed_cursor || *view.observed_cursor != ui.disassembly_cursor) {
    view.pending_center = ui.disassembly_cursor;
    view.observed_cursor = ui.disassembly_cursor;
  }
  if (view.generation != snapshot.generation ||
      view.stop_revision != snapshot.stop_revision) {
    view.generation = snapshot.generation;
    view.stop_revision = snapshot.stop_revision;
    view.pending_center = snapshot.pc;
  }
  if (ui.disassembly_scroll_target &&
      view.layout.rows.contains(*ui.disassembly_scroll_target)) {
    view.pending_center = *ui.disassembly_scroll_target;
    ui.disassembly_scroll_target.reset();
  }
  const auto &keyboard_io = ImGui::GetIO();
  if (!control_lease && snapshot.state == debugger::SessionState::Stopped &&
      navigation_input_allowed(ui) &&
      ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
      !keyboard_io.KeyCtrl && !keyboard_io.KeyShift && !keyboard_io.KeyAlt &&
      !keyboard_io.KeySuper) {
    const bool up = ImGui::IsKeyPressed(ImGuiKey_UpArrow);
    const bool down = ImGui::IsKeyPressed(ImGuiKey_DownArrow);
    if (up || down) {
      const auto next = disassembly_graph_adjacent_address(
          *graph, ui.disassembly_cursor, up, down);
      if (next) {
        ui.disassembly_cursor = *next;
        view.observed_cursor = *next;
        view.pending_center = *next;
      }
    }
  }
  if (follow_requested) {
    const auto selected = view.layout.rows.find(ui.disassembly_cursor);
    if (selected != view.layout.rows.end()) {
      const auto [block, row] = selected->second;
      const auto &instruction = graph->blocks[block].instructions[row];
      const auto target = disassembly_navigation_target(
          snapshot, instruction, view.layout.blocks[block].rows[row].text);
      if (target && follow_address(snapshot, engine, ui, *target) &&
          ui.disassembly_cursor == *target) {
        view.pending_center = *target;
        view.observed_cursor = *target;
      }
    }
  }

  const bool fit = ImGui::Button(l10n::label(l10n::Key::GuiGraphFit));
  ImGui::SameLine();
  const bool reset_zoom =
      ImGui::Button(l10n::label(l10n::Key::GuiGraphResetZoom));
  ImGui::SameLine();
  if (ImGui::Button(l10n::label(l10n::Key::GuiGraphSelection))) {
    view.pending_center = ui.disassembly_cursor;
    if (!view.layout.rows.contains(ui.disassembly_cursor)) {
      follow_disassembly(engine, ui, ui.disassembly_cursor);
    }
  }
  ImGui::SameLine();
  ImGui::BeginDisabled(snapshot.pc == 0);
  if (ImGui::Button(l10n::label(l10n::Key::GuiGraphProgramCounter))) {
    view.pending_center = snapshot.pc;
    follow_disassembly(engine, ui, snapshot.pc);
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  ImGui::TextDisabled("%.0f%%", view.zoom * 100.0F);
  ImGui::SameLine();
  ImGui::TextDisabled("%s", l10n::text(l10n::Key::GuiGraphHelpMarker));
  if (ImGui::IsItemHovered()) {
    ImGui::SetTooltip("%s", l10n::text(l10n::Key::GuiGraphControlsHelp));
  }
  ImGui::Text(l10n::text(l10n::Key::GuiGraphBlockCount),
              graph->name.empty() ? l10n::text(l10n::Key::GuiGraphDefaultName)
                                  : graph->name.c_str(),
              graph->blocks.size());

  if (!ImGui::BeginChild(
          "assembly-graph-canvas", ImVec2(0.0F, 0.0F), ImGuiChildFlags_Borders,
          ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
    ImGui::EndChild();
    return;
  }
  const ImVec2 origin = ImGui::GetCursorScreenPos();
  const ImVec2 available = ImGui::GetContentRegionAvail();
  const ImVec2 size(std::max(available.x, 1.0F), std::max(available.y, 1.0F));
  ImGui::InvisibleButton("graph", size,
                         ImGuiButtonFlags_MouseButtonLeft |
                             ImGuiButtonFlags_MouseButtonMiddle);
  const bool hovered = ImGui::IsItemHovered();
  const bool active = ImGui::IsItemActive();
  const ImGuiIO &io = ImGui::GetIO();
  if (reset_zoom) {
    const ImVec2 center((size.x * 0.5F - view.pan.x) / view.zoom,
                        (size.y * 0.5F - view.pan.y) / view.zoom);
    view.zoom = 1.0F;
    view.pan = ImVec2(size.x * 0.5F - center.x, size.y * 0.5F - center.y);
  }
  if (fit) {
    const float margin = view.layout.padding * 3.0F;
    view.zoom =
        std::clamp(std::min(std::max(1.0F, size.x - margin * 2.0F) /
                                std::max(1.0F, view.layout.bounds_max.x -
                                                   view.layout.bounds_min.x),
                            std::max(1.0F, size.y - margin * 2.0F) /
                                std::max(1.0F, view.layout.bounds_max.y -
                                                   view.layout.bounds_min.y)),
                   0.1F, 1.0F);
    view.pan = ImVec2(
        size.x * 0.5F - (view.layout.bounds_min.x + view.layout.bounds_max.x) *
                            0.5F * view.zoom,
        size.y * 0.5F - (view.layout.bounds_min.y + view.layout.bounds_max.y) *
                            0.5F * view.zoom);
    view.positioned = true;
    view.pending_center.reset();
  }
  if (view.pending_center && center_address(view, *view.pending_center, size)) {
    view.pending_center.reset();
  }
  if (!view.positioned) {
    if (!center_address(view, snapshot.pc, size)) {
      const auto &first = view.layout.blocks.front();
      view.pan = ImVec2(
          size.x * 0.5F - (first.position.x + first.size.x * 0.5F) * view.zoom,
          view.layout.padding * 2.0F - first.position.y * view.zoom);
    }
    view.positioned = true;
  }
  if (hovered && io.MouseWheel != 0.0F) {
    const ImVec2 anchor(io.MousePos.x - origin.x, io.MousePos.y - origin.y);
    const ImVec2 world((anchor.x - view.pan.x) / view.zoom,
                       (anchor.y - view.pan.y) / view.zoom);
    view.zoom =
        std::clamp(view.zoom * std::pow(1.15F, io.MouseWheel), 0.1F, 2.5F);
    view.pan =
        ImVec2(anchor.x - world.x * view.zoom, anchor.y - world.y * view.zoom);
  }

  const auto screen = [&](ImVec2 point) {
    return ImVec2(origin.x + view.pan.x + point.x * view.zoom,
                  origin.y + view.pan.y + point.y * view.zoom);
  };
  const ImVec2 mouse((io.MousePos.x - origin.x - view.pan.x) / view.zoom,
                     (io.MousePos.y - origin.y - view.pan.y) / view.zoom);
  std::size_t hovered_block = no_block;
  std::size_t hovered_row = no_block;
  std::size_t hovered_edge = no_block;
  if (hovered) {
    for (std::size_t i = 0; i < view.layout.blocks.size(); ++i) {
      const auto &block = view.layout.blocks[i];
      if (!contains(mouse, block.position, block.size)) {
        continue;
      }
      hovered_block = i;
      const float row_y =
          mouse.y - block.position.y - view.layout.header_height;
      if (row_y >= 0.0F) {
        const auto row =
            std::lower_bound(block.rows.begin(), block.rows.end(), row_y,
                             [](const GraphRowLayout &layout, float y) {
                               return layout.offset + layout.height <= y;
                             });
        if (row != block.rows.end()) {
          hovered_row = static_cast<std::size_t>(row - block.rows.begin());
        }
      }
      break;
    }
    if (hovered_block == no_block) {
      for (std::size_t i = 0; i < view.layout.edges.size(); ++i) {
        const auto &edge = view.layout.edges[i];
        if (edge.target == no_block &&
            contains(mouse, edge.label_position, edge.label_size)) {
          hovered_edge = i;
          break;
        }
      }
    }
  }
  const auto hovered_target = [&]() -> std::optional<std::uint64_t> {
    if (hovered_row == no_block) {
      return std::nullopt;
    }
    const auto &block = view.layout.blocks[hovered_block];
    const auto &row = block.rows[hovered_row];
    const auto start = screen(block.position);
    const auto end = screen(ImVec2(block.position.x + block.size.x,
                                   block.position.y + block.size.y));
    auto *draw = ImGui::GetWindowDrawList();
    const auto window_min = draw->GetClipRectMin();
    const auto window_max = draw->GetClipRectMax();
    const ImVec2 clip_min(std::max({start.x, origin.x, window_min.x}),
                          std::max({start.y, origin.y, window_min.y}));
    const ImVec2 clip_max(std::min({end.x, origin.x + size.x, window_max.x}),
                          std::min({end.y, origin.y + size.y, window_max.y}));
    const float y =
        start.y + (view.layout.header_height + row.offset) * view.zoom;
    if (const auto target = hit_disassembly_text(
            row.text.instruction, view.layout.font, view.layout.font_size,
            ImVec2(start.x + (view.layout.padding * 3.0F +
                              view.layout.address_width) *
                                 view.zoom,
                   y + (view.layout.row_height - view.layout.font_size) * 0.5F *
                           view.zoom),
            io.MousePos, clip_min, clip_max, view.zoom)) {
      return navigable_address(snapshot, *target) ? target : std::nullopt;
    }
    const auto target = hit_disassembly_text(
        row.text.annotation, view.layout.font, view.layout.font_size,
        ImVec2(start.x + view.layout.padding * 1.8F * view.zoom,
               y + view.layout.row_height * view.zoom),
        io.MousePos, clip_min, clip_max, view.zoom);
    return target && navigable_address(snapshot, *target) ? target
                                                          : std::nullopt;
  }();
  if (hovered_target) {
    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
  }
  if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
    view.background_drag =
        hovered_block == no_block && hovered_edge == no_block;
    if (hovered_row != no_block) {
      ui.disassembly_cursor =
          graph->blocks[hovered_block].instructions[hovered_row].address;
    }
    if (hovered_target &&
        follow_address(snapshot, engine, ui, *hovered_target)) {
      if (ui.disassembly_cursor == *hovered_target) {
        view.pending_center = *hovered_target;
        view.observed_cursor = *hovered_target;
      }
    } else if (hovered_row != no_block) {
      ui.disassembly_cursor =
          graph->blocks[hovered_block].instructions[hovered_row].address;
      view.observed_cursor = ui.disassembly_cursor;
      view.pending_center.reset();
    } else if (hovered_edge != no_block) {
      const auto &layout = view.layout.edges[hovered_edge];
      const auto &edge = graph->blocks[layout.source].edges[layout.edge];
      const auto &source = graph->blocks[layout.source].instructions;
      if (!source.empty()) {
        ui.disassembly_cursor = source.back().address;
      }
      if (edge.target && follow_address(snapshot, engine, ui, *edge.target)) {
        view.pending_center = *edge.target;
        view.observed_cursor = *edge.target;
      }
    }
  }
  if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
    view.background_drag = false;
  }
  if (active && (ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.0F) ||
                 (view.background_drag &&
                  ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0F)))) {
    view.pan.x += io.MouseDelta.x;
    view.pan.y += io.MouseDelta.y;
    ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeAll);
  }
  if (hovered_row != no_block &&
      ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
    view.popup_address =
        graph->blocks[hovered_block].instructions[hovered_row].address;
    ui.disassembly_cursor = *view.popup_address;
    view.observed_cursor = ui.disassembly_cursor;
    ImGui::OpenPopup("graph-instruction-actions");
  }

  auto *draw = ImGui::GetWindowDrawList();
  draw->PushClipRect(origin, ImVec2(origin.x + size.x, origin.y + size.y),
                     true);
  const float text_size = view.layout.font_size * view.zoom;
  const ImU32 text_color = ImGui::GetColorU32(ImGuiCol_Text);
  const ImU32 muted_color = ImGui::GetColorU32(ImGuiCol_TextDisabled);
  const ImU32 background = ImGui::GetColorU32(ImGuiCol_WindowBg);
  draw->AddRectFilled(origin, ImVec2(origin.x + size.x, origin.y + size.y),
                      background);
  for (std::size_t i = 0; i < view.layout.edges.size(); ++i) {
    const auto &layout = view.layout.edges[i];
    const auto &edge = graph->blocks[layout.source].edges[layout.edge];
    const ImU32 color = edge_color(edge.kind);
    std::array<ImVec2, 6> points;
    for (int p = 0; p < layout.point_count; ++p) {
      points[p] = screen(layout.points[p]);
    }
    draw->AddPolyline(points.data(), layout.point_count, color,
                      std::max(1.0F, 1.5F * view.zoom));
    const auto tip = points[layout.point_count - 1];
    const float arrow =
        std::max(3.0F, view.layout.font_size * 0.35F * view.zoom);
    draw->AddTriangleFilled(tip, ImVec2(tip.x - arrow, tip.y - arrow * 1.6F),
                            ImVec2(tip.x + arrow, tip.y - arrow * 1.6F), color);
    const auto label = screen(layout.label_position);
    draw->AddRectFilled(
        ImVec2(label.x - 2.0F, label.y - 1.0F),
        ImVec2(label.x + layout.label_size.x * view.zoom + 2.0F,
               label.y + layout.label_size.y * view.zoom + 1.0F),
        i == hovered_edge ? ImGui::GetColorU32(ImGuiCol_Header) : background);
    draw->AddText(view.layout.font, text_size, label, color,
                  layout.label.c_str());
  }
  for (std::size_t i = 0; i < view.layout.blocks.size(); ++i) {
    const auto &block = view.layout.blocks[i];
    const auto start = screen(block.position);
    const auto end = screen(ImVec2(block.position.x + block.size.x,
                                   block.position.y + block.size.y));
    if (end.x < origin.x || end.y < origin.y || start.x > origin.x + size.x ||
        start.y > origin.y + size.y) {
      continue;
    }
    const float rounding = ImGui::GetStyle().FrameRounding * view.zoom;
    draw->AddRectFilled(start, end, ImGui::GetColorU32(ImGuiCol_FrameBg),
                        rounding);
    const float header_end = start.y + view.layout.header_height * view.zoom;
    draw->AddRectFilled(start, ImVec2(end.x, header_end),
                        ImGui::GetColorU32(ImGuiCol_Header), rounding);
    draw->AddRect(start, end, ImGui::GetColorU32(ImGuiCol_Border), rounding);
    draw->PushClipRect(
        ImVec2(std::max(start.x, origin.x), std::max(start.y, origin.y)),
        ImVec2(std::min(end.x, origin.x + size.x),
               std::min(end.y, origin.y + size.y)),
        true);
    draw->AddText(view.layout.font, text_size,
                  ImVec2(start.x + view.layout.padding * view.zoom,
                         start.y + view.layout.padding * 0.5F * view.zoom),
                  text_color, block.title.c_str());
    for (std::size_t r = 0; r < block.rows.size(); ++r) {
      const auto &instruction = graph->blocks[i].instructions[r];
      const auto &row = block.rows[r];
      const float y = header_end + row.offset * view.zoom;
      const float row_end = y + row.height * view.zoom;
      if (row_end < origin.y || y > origin.y + size.y) {
        continue;
      }
      if (instruction.address == ui.disassembly_cursor) {
        draw->AddRectFilled(ImVec2(start.x, y), ImVec2(end.x, row_end),
                            ImGui::GetColorU32(ImGuiCol_HeaderActive, 0.35F));
      } else if (i == hovered_block && r == hovered_row) {
        draw->AddRectFilled(ImVec2(start.x, y), ImVec2(end.x, row_end),
                            ImGui::GetColorU32(ImGuiCol_HeaderHovered, 0.35F));
      }
      const float marker_x = start.x + view.layout.padding * 0.7F * view.zoom;
      const float marker_y = y + view.layout.row_height * 0.5F * view.zoom;
      if (instruction.address == snapshot.pc) {
        const float width = view.layout.padding * 0.45F * view.zoom;
        draw->AddRect(ImVec2(start.x + 1.0F, y), ImVec2(end.x - 1.0F, row_end),
                      ImGui::GetColorU32(ImGuiCol_NavCursor), 0.0F,
                      std::max(1.0F, view.zoom));
        draw->AddTriangleFilled(ImVec2(marker_x + width, marker_y),
                                ImVec2(marker_x - width, marker_y - width),
                                ImVec2(marker_x - width, marker_y + width),
                                ImGui::GetColorU32(ImGuiCol_NavCursor));
      }
      const auto *breakpoint =
          breakpoint_info_at(snapshot, instruction.address);
      if (breakpoint != nullptr) {
        const float radius = view.layout.padding * 0.3F * view.zoom;
        const ImVec2 marker(marker_x, y + radius + 1.0F);
        if (breakpoint->enabled) {
          draw->AddCircleFilled(marker, radius,
                                edge_color(EdgeKind::Fallthrough));
        } else {
          draw->AddCircle(marker, radius, edge_color(EdgeKind::Fallthrough));
        }
      }
      const float text_y =
          y +
          (view.layout.row_height - view.layout.font_size) * 0.5F * view.zoom;
      draw->AddText(
          view.layout.font, text_size,
          ImVec2(start.x + view.layout.padding * 1.8F * view.zoom, text_y),
          muted_color, row.address.c_str());
      draw_disassembly_text(draw, row.text.instruction, view.layout.font,
                            view.layout.font_size,
                            ImVec2(start.x + (view.layout.padding * 3.0F +
                                              view.layout.address_width) *
                                                 view.zoom,
                                   text_y),
                            view.zoom);
      draw_disassembly_text(
          draw, row.text.annotation, view.layout.font, view.layout.font_size,
          ImVec2(start.x + view.layout.padding * 1.8F * view.zoom,
                 y + view.layout.row_height * view.zoom),
          view.zoom);
    }
    draw->PopClipRect();
  }
  draw->PopClipRect();

  if (hovered_row != no_block && !active &&
      !ImGui::IsPopupOpen("graph-instruction-actions")) {
    const auto &instruction =
        graph->blocks[hovered_block].instructions[hovered_row];
    const auto &row = view.layout.blocks[hovered_block].rows[hovered_row];
    ImGui::BeginTooltip();
    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 90.0F);
    ImGui::Text("%s  %s", row.address.c_str(),
                row.text.instruction.text.c_str());
    if (hovered_target)
      ImGui::Text("0x%" PRIx64, *hovered_target);
    ImGui::Text(l10n::text(l10n::Key::GuiGraphInstructionBytes),
                row.text.bytes.c_str());
    if (!row.text.annotation.text.empty()) {
      ImGui::TextUnformatted(row.text.annotation.text.c_str());
    }
    if (instruction.address == snapshot.pc) {
      const auto live = std::find_if(
          snapshot.instructions.begin(), snapshot.instructions.end(),
          [&snapshot](const debugger::InstructionRow &candidate) {
            return candidate.address == snapshot.pc;
          });
      if (live != snapshot.instructions.end() && live->branch.conditional) {
        ImGui::Text(l10n::text(l10n::Key::GuiGraphBranchOutcome),
                    live->branch.available
                        ? (live->branch.taken
                               ? l10n::text(l10n::Key::GuiGraphBranchTaken)
                               : l10n::text(l10n::Key::GuiGraphBranchNotTaken))
                        : l10n::text(l10n::Key::GuiGraphBranchUnknown));
        ImGui::TextUnformatted(live->branch.explanation.c_str());
      }
    }
    ImGui::PopTextWrapPos();
    ImGui::EndTooltip();
  } else if (hovered_edge != no_block && !active) {
    const auto &layout = view.layout.edges[hovered_edge];
    const auto &edge = graph->blocks[layout.source].edges[layout.edge];
    if (edge.target && navigable_address(snapshot, *edge.target)) {
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
      ImGui::SetTooltip(l10n::text(l10n::Key::GuiGraphFollowExternalTarget),
                        *edge.target);
    } else {
      ImGui::SetTooltip("%s", l10n::text(l10n::Key::GuiGraphUnavailableTarget));
    }
  }
  if (ImGui::BeginPopup("graph-instruction-actions")) {
    const auto row = view.popup_address
                         ? view.layout.rows.find(*view.popup_address)
                         : view.layout.rows.end();
    if (row != view.layout.rows.end()) {
      const auto [block, index] = row->second;
      draw_instruction_context_actions(snapshot, engine, ui,
                                       graph->blocks[block].instructions[index],
                                       control_lease);
    } else {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }
  ImGui::EndChild();
}

} // namespace mydbg::app
