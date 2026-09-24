#include "app/DisassemblyGraphLayout.h"
#include "app/DisassemblyTextDrawing.h"
#include "localization/Localization.h"

#include <imgui_internal.h>

#include <algorithm>
#include <cfloat>
#include <cinttypes>
#include <cmath>
#include <cstdio>

namespace mydbg::app {
namespace {

constexpr std::size_t no_block = std::numeric_limits<std::size_t>::max();
using EdgeKind = debugger::DisassemblyGraphEdge::Kind;

const char *edge_name(EdgeKind kind) {
  switch (kind) {
  case EdgeKind::Taken:
    return l10n::text(l10n::Key::GuiGraphEdgeTaken);
  case EdgeKind::Fallthrough:
    return l10n::text(l10n::Key::GuiGraphEdgeFallthrough);
  case EdgeKind::Jump:
    return l10n::text(l10n::Key::GuiGraphEdgeJump);
  }
  return l10n::text(l10n::Key::GuiGraphEdgeJump);
}

ImVec2 graph_text_size(ImFont *font, float font_size, const char *text) {
  auto size = font->CalcTextSizeA(font_size, FLT_MAX, -1.0F, text);
  // Preserve ImGui::CalcTextSize width rounding without an active context.
  size.x = ImCeilFast(size.x);
  return size;
}

} // namespace

void disassembly_graph_build_layout(
    DisassemblyGraphLayout &view,
    const std::shared_ptr<const debugger::DisassemblyGraph> &graph,
    std::string_view architecture, ImFont *font, float font_size) {
  view.graph = graph;
  view.font = font;
  view.font_size = font_size;
  view.architecture = architecture;
  view.padding = view.font_size * 0.65F;
  view.row_height = std::ceil(view.font_size * 1.4F);
  view.header_height = view.row_height + view.padding;
  view.address_width = 0.0F;
  view.blocks.clear();
  view.edges.clear();
  view.rows.clear();
  view.blocks.resize(graph->blocks.size());
  std::unordered_map<std::uint64_t, std::size_t> addresses;
  addresses.reserve(graph->blocks.size());
  for (std::size_t i = 0; i < graph->blocks.size(); ++i) {
    const auto &block = graph->blocks[i];
    auto &layout = view.blocks[i];
    addresses.emplace(block.address, i);
    char address[32]{};
    std::snprintf(address, sizeof(address), "0x%" PRIx64, block.address);
    layout.title = address;
    layout.rows.reserve(block.instructions.size());
    for (std::size_t row = 0; row < block.instructions.size(); ++row) {
      const auto &instruction = block.instructions[row];
      std::snprintf(address, sizeof(address), "0x%" PRIx64,
                    instruction.address);
      GraphRowLayout text;
      text.address = address;
      text.text = make_disassembly_presentation(instruction, architecture);
      measure_disassembly_text(text.text.instruction, view.font,
                               view.font_size);
      measure_disassembly_text(text.text.annotation, view.font, view.font_size);
      view.address_width =
          std::max(view.address_width,
                   graph_text_size(view.font, view.font_size, address).x);
      layout.rows.push_back(std::move(text));
      view.rows.emplace(instruction.address, std::pair{i, row});
    }
  }

  const float column_gap = view.font_size * 4.0F;
  const float layer_gap = view.font_size * 6.0F;
  std::vector<std::vector<std::size_t>> outgoing(view.blocks.size());
  std::vector<std::vector<std::size_t>> incoming(view.blocks.size());
  for (std::size_t i = 0; i < graph->blocks.size(); ++i) {
    auto &block = view.blocks[i];
    float text_width{};
    for (const auto &row : block.rows) {
      text_width = std::max({text_width, row.text.instruction.size.x,
                             row.text.annotation.size.x});
    }
    block.size.x = std::max(view.font_size * 25.0F,
                            view.address_width + view.padding * 5.0F +
                                std::min(text_width, view.font_size * 52.0F));
    float row_offset{};
    for (auto &row : block.rows) {
      row.offset = row_offset;
      row.height = view.row_height;
      if (!row.text.annotation.text.empty()) {
        measure_disassembly_text(row.text.annotation, view.font, view.font_size,
                                 block.size.x - view.padding * 3.6F);
        row.height += row.text.annotation.size.y + view.font_size * 0.45F;
      }
      row_offset += row.height;
    }
    block.size.y = view.header_height + view.padding + row_offset;
    for (std::size_t e = 0; e < graph->blocks[i].edges.size(); ++e) {
      const auto &edge = graph->blocks[i].edges[e];
      GraphEdgeLayout layout;
      layout.source = i;
      layout.edge = e;
      if (edge.target) {
        const auto target = addresses.find(*edge.target);
        if (target != addresses.end()) {
          layout.target = target->second;
          incoming[target->second].push_back(view.edges.size());
        }
      }
      outgoing[i].push_back(view.edges.size());
      view.edges.push_back(std::move(layout));
    }
  }

  // Remove DFS back edges for layering, but retain and route them as loop arcs.
  // An explicit stack keeps large functions from consuming the C++ call stack.
  std::vector<unsigned char> color(view.blocks.size());
  std::vector<std::pair<std::size_t, std::size_t>> stack;
  std::vector<std::size_t> finish;
  finish.reserve(view.blocks.size());
  for (std::size_t root = 0; root < view.blocks.size(); ++root) {
    if (color[root] != 0) {
      continue;
    }
    color[root] = 1;
    stack.emplace_back(root, 0);
    while (!stack.empty()) {
      auto &[node, next] = stack.back();
      if (next == outgoing[node].size()) {
        color[node] = 2;
        finish.push_back(node);
        stack.pop_back();
        continue;
      }
      auto &edge = view.edges[outgoing[node][next++]];
      if (edge.target == no_block) {
        continue;
      }
      if (color[edge.target] == 1) {
        edge.back = true;
      } else if (color[edge.target] == 0) {
        color[edge.target] = 1;
        stack.emplace_back(edge.target, 0);
      }
    }
  }
  std::size_t layer_count{1};
  for (auto node = finish.rbegin(); node != finish.rend(); ++node) {
    for (const auto index : outgoing[*node]) {
      const auto &edge = view.edges[index];
      if (edge.target != no_block && !edge.back) {
        auto &target = view.blocks[edge.target];
        target.layer = std::max(target.layer, view.blocks[*node].layer + 1);
        layer_count = std::max(layer_count, target.layer + 1);
      }
    }
  }
  std::vector<std::vector<std::size_t>> layers(layer_count);
  for (std::size_t i = 0; i < view.blocks.size(); ++i) {
    layers[view.blocks[i].layer].push_back(i);
  }
  std::vector<float> layer_top(layer_count);
  std::vector<float> layer_bottom(layer_count);
  float top{};
  float graph_left{};
  float graph_right{};
  for (std::size_t rank = 0; rank < layer_count; ++rank) {
    auto &layer = layers[rank];
    // Predecessor barycenters keep siblings together and put joins below them.
    for (const auto node : layer) {
      float sum{};
      std::size_t count{};
      for (const auto index : incoming[node]) {
        const auto &edge = view.edges[index];
        if (!edge.back) {
          sum += view.blocks[edge.source].order;
          ++count;
        }
      }
      view.blocks[node].order = count == 0 ? static_cast<float>(node)
                                           : sum / static_cast<float>(count);
    }
    std::stable_sort(
        layer.begin(), layer.end(), [&view](auto left, auto right) {
          return view.blocks[left].order < view.blocks[right].order;
        });
    float width = layer.empty() ? 0.0F : -column_gap;
    float height{};
    for (const auto node : layer) {
      width += view.blocks[node].size.x + column_gap;
      height = std::max(height, view.blocks[node].size.y);
    }
    float left = -width * 0.5F;
    layer_top[rank] = top;
    layer_bottom[rank] = top + height;
    for (const auto node : layer) {
      auto &block = view.blocks[node];
      block.position = ImVec2(left, top);
      block.order = left + block.size.x * 0.5F;
      left += block.size.x + column_gap;
    }
    graph_left = std::min(graph_left, -width * 0.5F);
    graph_right = std::max(graph_right, width * 0.5F);
    top += height + layer_gap;
  }

  view.bounds_min = ImVec2(graph_left, -layer_gap * 0.5F);
  view.bounds_max = ImVec2(graph_right, top - layer_gap * 0.5F);
  std::size_t outer_lane{};
  for (auto &layout : view.edges) {
    const auto &source = view.blocks[layout.source];
    const auto &edge = graph->blocks[layout.source].edges[layout.edge];
    const float port = static_cast<float>(layout.edge + 1) /
                       static_cast<float>(outgoing[layout.source].size() + 1);
    const ImVec2 start(source.position.x + source.size.x * port,
                       source.position.y + source.size.y);
    const float exit_y =
        layer_bottom[source.layer] + layer_gap * (0.38F + 0.12F * port);
    layout.label = edge_name(edge.kind);
    if (layout.target == no_block) {
      if (edge.target) {
        layout.label = l10n::format(l10n::Key::GuiGraphExternalEdge,
                                    edge_name(edge.kind), *edge.target);
      } else {
        layout.label = l10n::format(l10n::Key::GuiGraphUnresolvedEdge,
                                    edge_name(edge.kind));
      }
      // Separate unresolved/external labels vertically for multi-way exits.
      const float end_y =
          exit_y + static_cast<float>(layout.edge) * view.row_height;
      layout.points[0] = start;
      layout.points[1] = ImVec2(start.x, end_y);
      layout.point_count = 2;
      layout.label_position = ImVec2(start.x + view.padding * 0.5F, end_y);
    } else {
      const auto &target = view.blocks[layout.target];
      const ImVec2 end(target.position.x + target.size.x * 0.5F,
                       target.position.y);
      if (!layout.back && target.layer == source.layer + 1) {
        layout.points = {start, ImVec2(start.x, exit_y), ImVec2(end.x, exit_y),
                         end};
        layout.point_count = 4;
      } else {
        // All long/loop edges use outside lanes, never a vertical path through
        // intervening cards. Horizontal legs stay in the inter-layer gutters.
        const float lane = column_gap * 0.5F +
                           static_cast<float>(outer_lane++ % 12) * view.padding;
        const bool left = start.x < 0.0F;
        const float outside = left ? graph_left - lane : graph_right + lane;
        const float enter_y = layer_top[target.layer] - layer_gap * 0.25F;
        layout.points = {start,
                         ImVec2(start.x, exit_y),
                         ImVec2(outside, exit_y),
                         ImVec2(outside, enter_y),
                         ImVec2(end.x, enter_y),
                         end};
        layout.point_count = 6;
        if (layout.back) {
          layout.label =
              l10n::format(l10n::Key::GuiGraphLoopEdge, edge_name(edge.kind));
        }
      }
      layout.label_position =
          ImVec2(start.x + view.padding * 0.5F, start.y + view.padding * 0.3F);
    }
    layout.label_size =
        graph_text_size(view.font, view.font_size, layout.label.c_str());
    for (int i = 0; i < layout.point_count; ++i) {
      view.bounds_min.x = std::min(view.bounds_min.x, layout.points[i].x);
      view.bounds_min.y = std::min(view.bounds_min.y, layout.points[i].y);
      view.bounds_max.x = std::max(view.bounds_max.x, layout.points[i].x);
      view.bounds_max.y = std::max(view.bounds_max.y, layout.points[i].y);
    }
    view.bounds_max.x = std::max(view.bounds_max.x,
                                 layout.label_position.x + layout.label_size.x);
    view.bounds_max.y = std::max(view.bounds_max.y,
                                 layout.label_position.y + layout.label_size.y);
  }
}

std::optional<std::uint64_t>
disassembly_graph_adjacent_address(const debugger::DisassemblyGraph &graph,
                                   std::uint64_t cursor, bool up, bool down) {
  std::optional<std::uint64_t> next;
  for (const auto &block : graph.blocks) {
    for (const auto &row : block.instructions) {
      if ((up && row.address < cursor && (!next || row.address > *next)) ||
          (down && row.address > cursor && (!next || row.address < *next))) {
        next = row.address;
      }
    }
  }
  return next;
}

} // namespace mydbg::app
