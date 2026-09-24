#pragma once

#include "app/DisassemblyText.h"

#include <array>
#include <limits>
#include <unordered_map>
#include <utility>

namespace mydbg::app {

struct GraphRowLayout {
  std::string address;
  DisassemblyPresentation text;
  float offset{};
  float height{};
};

struct GraphBlockLayout {
  ImVec2 position;
  ImVec2 size;
  std::string title;
  std::vector<GraphRowLayout> rows;
  std::size_t layer{};
  float order{};
};

struct GraphEdgeLayout {
  std::size_t source{};
  std::size_t edge{};
  std::size_t target{std::numeric_limits<std::size_t>::max()};
  bool back{};
  std::array<ImVec2, 6> points{};
  int point_count{};
  std::string label;
  ImVec2 label_position;
  ImVec2 label_size;
};

struct DisassemblyGraphLayout {
  std::shared_ptr<const debugger::DisassemblyGraph> graph;
  ImFont *font{};
  float font_size{};
  std::string architecture;
  float padding{};
  float row_height{};
  float header_height{};
  float address_width{};
  std::vector<GraphBlockLayout> blocks;
  std::vector<GraphEdgeLayout> edges;
  std::unordered_map<std::uint64_t, std::pair<std::size_t, std::size_t>> rows;
  ImVec2 bounds_min;
  ImVec2 bounds_max;
};

void disassembly_graph_build_layout(
    DisassemblyGraphLayout &view,
    const std::shared_ptr<const debugger::DisassemblyGraph> &graph,
    std::string_view architecture, ImFont *font, float font_size);
std::optional<std::uint64_t>
disassembly_graph_adjacent_address(const debugger::DisassemblyGraph &graph,
                                   std::uint64_t cursor, bool up, bool down);

} // namespace mydbg::app
