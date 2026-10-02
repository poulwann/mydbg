#include "app/RopPanel.h"
#include "app/AppActions.h"
#include "app/AppState.h"
#include "app/RopState.h"
#include "app/UiSupport.h"
#include "backend/DebuggerTypes.h"
#include "backend/lldb/LldbEngine.h"
#include "localization/Localization.h"
#include "scripting/PythonRuntime.h"
#include "scripting/RopTrace.h"

#include <imgui.h>

#include <algorithm>
#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mydbg::app {
namespace {

using namespace debugger::scripting;
constexpr std::size_t no_selection = std::numeric_limits<std::size_t>::max();

struct SourceStamp {
  std::uint64_t fingerprint{};
  std::uint64_t generation{};
  std::uint64_t stop_revision{};
  std::uint64_t thread_id{};
  std::uint64_t pc{};
  std::uint64_t sp{};
};

// Snapshot revisions also change for navigation and console output. Only hash
// source state that affects this simulation, not the revision itself.
SourceStamp source_stamp(const debugger::SessionSnapshot &snapshot) {
  std::uint64_t hash = 14695981039346656037ULL;
  const auto byte = [&](std::uint8_t value) {
    hash = (hash ^ value) * 1099511628211ULL;
  };
  const auto number = [&](std::uint64_t value) {
    for (unsigned shift = 0; shift != 64; shift += 8)
      byte(static_cast<std::uint8_t>(value >> shift));
  };
  const auto text = [&](std::string_view value) {
    number(value.size());
    for (unsigned char character : value)
      byte(character);
  };
  number(snapshot.generation);
  number(snapshot.stop_revision);
  number(snapshot.process_id);
  number(snapshot.thread_id);
  number(snapshot.pc);
  number(snapshot.sp);
  number(snapshot.address_byte_size);
  text(snapshot.session.sha256);
  text(snapshot.session.epoch);
  text(snapshot.architecture);
  number(snapshot.registers.size());
  for (const auto &reg : snapshot.registers) {
    text(reg.name);
    number(reg.has_numeric_value);
    if (reg.has_numeric_value)
      number(reg.numeric_value);
    else
      text(reg.value);
  }
  number(snapshot.patches.size());
  for (const auto &patch : snapshot.patches) {
    number(patch.address);
    number(patch.original.size());
    for (auto value : patch.original)
      byte(value);
    number(patch.replacement.size());
    for (auto value : patch.replacement)
      byte(value);
  }
  return {hash,
          snapshot.generation,
          snapshot.stop_revision,
          snapshot.thread_id,
          snapshot.pc,
          snapshot.sp};
}

bool busy(RopJobStatus status) {
  return status == RopJobStatus::Queued || status == RopJobStatus::Running ||
         status == RopJobStatus::Cancelling;
}

const char *job_label(RopJobStatus status) {
  switch (status) {
  case RopJobStatus::Idle:
    return l10n::text(l10n::Key::GuiRopIdle);
  case RopJobStatus::Queued:
    return l10n::text(l10n::Key::GuiRopQueued);
  case RopJobStatus::Running:
    return l10n::text(l10n::Key::GuiRopRunning);
  case RopJobStatus::Cancelling:
    return l10n::text(l10n::Key::GuiRopCancelling);
  case RopJobStatus::Succeeded:
    return l10n::text(l10n::Key::GuiRopRecorded);
  case RopJobStatus::Failed:
    return l10n::text(l10n::Key::GuiRopFailed);
  case RopJobStatus::Cancelled:
    return l10n::text(l10n::Key::GuiRopCancelled);
  }
  return "";
}

struct EffectRow {
  const RopMemoryAccess *access{};
};

struct StepRow {
  std::size_t node{};
  const RopInstruction *instruction{};
  std::string text;
  std::string sp;
  std::string annotation;
  std::vector<EffectRow> effects;
  std::string register_effects;
  std::string memory_effects;
  float offset{};
  float height{};
};

struct NodeBox {
  std::size_t first_step{};
  std::size_t step_count{};
  std::string title;
  std::string subtitle;
  std::string edge;
  ImVec2 position;
  ImVec2 size;
};

struct SlotRow {
  const RopStackSlot *slot{};
  bool return_target{};
  bool data{};
  std::size_t first_cursor{no_selection};
  std::uint64_t value{};
  bool readable{};
  bool changed{};
  std::uint8_t known_bytes{};
};

struct RegisterRow {
  std::string name;
  std::uint64_t value{};
  std::optional<std::uint64_t> before;
};

bool contains(ImVec2 point, ImVec2 position, ImVec2 size) {
  return point.x >= position.x && point.y >= position.y &&
         point.x < position.x + size.x && point.y < position.y + size.y;
}

bool covers(std::uint64_t address, std::uint64_t start, std::size_t size) {
  return address >= start && address - start < size;
}

} // namespace




struct RopView {
  std::uint64_t trace_job{};
  std::shared_ptr<const RopTrace> trace;
  std::uint64_t observed_revision{std::numeric_limits<std::uint64_t>::max()};
  SourceStamp observed_source;
  SourceStamp trace_source;
  SourceStamp request_source;
  std::uint64_t request_job{};
  bool request_stale{};
  bool stale{true};
  std::string input_error;
  std::vector<StepRow> steps;
  std::vector<NodeBox> nodes;
  std::vector<SlotRow> slots;
  std::vector<RegisterRow> registers;
  std::size_t cursor{};
  std::size_t reconstructed_cursor{no_selection};
  std::size_t selected_node{no_selection};
  std::size_t selected_slot{no_selection};
  std::size_t selected_effect{};
  const RopMemoryAccess *formatted_effect{};
  std::string effect_before;
  std::string effect_after;
  std::uint64_t simulated_pc{};
  std::uint64_t simulated_sp{};
  ImFont *font{};
  float font_size{};
  float padding{};
  float line_height{};
  float header_height{};
  ImVec2 bounds;
  ImVec2 pan;
  float zoom{1.0F};
  bool background_drag{};
  bool fit_requested{true};
  bool center_requested{};
  bool reveal_requested{};
  std::uint64_t synced_trace_job{};
  std::size_t synced_cursor{no_selection};
  std::uint64_t synced_address{};
};

namespace {

std::string format_register_effects(const RopInstruction &instruction) {
  if (!instruction.completed || instruction.register_changes.empty())
    return {};
  std::string summary;
  const std::size_t limit = 3;
  const std::size_t count =
      std::min(limit, instruction.register_changes.size());
  for (std::size_t index = 0; index < count; ++index) {
    const auto &change = instruction.register_changes[index];
    if (!summary.empty())
      summary += ", ";
    summary += change.name;
  }
  if (instruction.register_changes.size() > limit)
    summary += l10n::format(l10n::Key::GuiRopMoreEffects,
                            instruction.register_changes.size() - limit);
  return l10n::format(l10n::Key::GuiRopRegisterEffects, summary.c_str());
}

std::string format_memory_effects(const RopInstruction &instruction) {
  if (!instruction.completed || instruction.memory_accesses.empty())
    return {};
  std::string summary;
  const std::size_t limit = 2;
  const std::size_t count = std::min(limit, instruction.memory_accesses.size());
  for (std::size_t index = 0; index < count; ++index) {
    const auto &access = instruction.memory_accesses[index];
    if (!summary.empty())
      summary += ", ";
    summary += l10n::format(access.write ? l10n::Key::GuiRopMemorySummaryWrite
                                         : l10n::Key::GuiRopMemorySummaryRead,
                            access.address, access.before.size(),
                            access.stack ? l10n::text(l10n::Key::GuiRopStackRegion)
                                         : "");
  }
  if (instruction.memory_accesses.size() > limit)
    summary += l10n::format(l10n::Key::GuiRopMoreEffects,
                            instruction.memory_accesses.size() - limit);
  return l10n::format(l10n::Key::GuiRopMemoryEffectsSummary,
                      summary.c_str());
}
void select_cursor(RopView &view, std::size_t cursor, bool center = true) {
  view.cursor = std::min(cursor, view.steps.size());
  view.selected_node = view.cursor != 0
                           ? view.steps[view.cursor - 1].node
                           : (view.nodes.empty() ? no_selection : 0);
  view.center_requested = false;
  view.reveal_requested = center;
}
std::optional<std::uint64_t> selected_live_address(const RopView &view) {
  if (!view.trace || view.nodes.empty())
    return std::nullopt;
  if (view.cursor != 0 && view.cursor - 1 < view.steps.size())
    return view.steps[view.cursor - 1].instruction->address;
  return view.trace->nodes.front().entry_address;
}

bool sync_live_view(const debugger::SessionSnapshot &snapshot,
                    debugger::LldbEngine &engine, UiState &ui,
                    std::uint64_t address) {
  const auto region = std::find_if(
      snapshot.memory_regions.begin(), snapshot.memory_regions.end(),
      [address](const auto &entry) {
        return address >= entry.start && address < entry.end;
      });
  if (region == snapshot.memory_regions.end())
    return false;
  if (!region->executable) {
    follow_memory(engine, ui.memory, address);
    return true;
  }
  ui.navigation.disassembly_cursor = address;
  ui.navigation.disassembly_scroll_target = address;
  ui.navigation.source_restore.reset();
  ui.decompiler.scroll_selection = std::numeric_limits<std::uint64_t>::max();
  ui.decompiler.keyboard_line.reset();
  ui.decompiler.keyboard_span.reset();
  ui.decompiler.keyboard_cursor = address;
  engine.read_instructions(address);
  return true;
}

std::string fit_text(ImFont &font, float font_size, std::string_view text,
                     float width) {
  if (text.empty() || width <= 0)
    return {};
  if (font.CalcTextSizeA(font_size, 1e6F, 0, text.data(),
                         text.data() + text.size())
          .x <= width)
    return std::string(text);
  static constexpr std::string_view ellipsis = "...";
  const float ellipsis_width =
      font.CalcTextSizeA(font_size, 1e6F, 0, ellipsis.data(),
                         ellipsis.data() + ellipsis.size())
          .x;
  if (ellipsis_width >= width)
    return {};
  std::string clipped;
  clipped.reserve(text.size());
  for (char ch : text) {
    clipped.push_back(ch);
    if (font.CalcTextSizeA(font_size, 1e6F, 0, clipped.c_str()).x +
            ellipsis_width >
        width) {
      clipped.pop_back();
      break;
    }
  }
  while (!clipped.empty() && clipped.back() == ' ')
    clipped.pop_back();
  clipped += ellipsis;
  return clipped;
}


void build_trace_rows(RopView &view) {
  view.steps.clear();
  view.nodes.clear();
  view.slots.clear();
  view.registers.clear();
  view.formatted_effect = nullptr;
  view.selected_slot = no_selection;
  view.font = nullptr;
  view.reconstructed_cursor = no_selection;
  const auto &trace = *view.trace;
  for (const auto &reg : trace.initial_registers)
    view.registers.push_back({reg.name, reg.value, std::nullopt});
  view.nodes.reserve(trace.nodes.size());
  std::size_t step_count = 0;
  for (const auto &node : trace.nodes)
    step_count += node.instructions.size();
  view.steps.reserve(step_count);
  for (std::size_t index = 0; index < trace.nodes.size(); ++index) {
    const auto &node = trace.nodes[index];
    NodeBox box;
    box.first_step = view.steps.size();
    box.step_count = node.instructions.size();
    box.title = node.stack_slot
                    ? l10n::format(l10n::Key::GuiRopReturnNode, index + 1,
                                   *node.stack_slot, node.entry_address)
                    : l10n::format(l10n::Key::GuiRopFlowNode, index + 1,
                                   node.entry_address);
    box.subtitle = l10n::format(l10n::Key::GuiRopEntrySp, node.entry_sp);
    if (index + 1 < trace.nodes.size()) {
      const auto &next = trace.nodes[index + 1];
      box.edge =
          next.stack_slot
              ? l10n::format(l10n::Key::GuiRopReturnEdge, *next.stack_slot)
              : (node.instructions.empty()
                     ? l10n::text(l10n::Key::GuiRopControlFlow)
                     : node.instructions.back().flow);
    }
    for (const auto &instruction : node.instructions) {
      StepRow row;
      row.node = index;
      row.instruction = &instruction;
      row.text = l10n::format(l10n::Key::GuiRopInstructionLine,
                              instruction.address, instruction.text.c_str());
      row.sp = l10n::format(l10n::Key::GuiRopSpTransition,
                            instruction.sp_before, instruction.sp_after);
      row.register_effects = format_register_effects(instruction);
      row.memory_effects = format_memory_effects(instruction);
      if (!instruction.completed)
        row.annotation = l10n::text(l10n::Key::GuiRopNotExecuted);
      std::size_t stack_accesses = 0;
      for (const auto &access : instruction.memory_accesses) {
        row.effects.push_back({&access});
        if (!access.stack)
          continue;
        if (++stack_accesses > 3)
          continue;
        if (!row.annotation.empty())
          row.annotation += "; ";
        const auto key = access.write ? l10n::Key::GuiRopStackWrite
                         : instruction.flow == "return" &&
                                 access.address == instruction.sp_before
                             ? l10n::Key::GuiRopReturnRead
                             : l10n::Key::GuiRopDataRead;
        row.annotation +=
            l10n::format(key, access.address, access.before.size());
      }
      if (stack_accesses > 3)
        row.annotation += l10n::format(l10n::Key::GuiRopMoreStackAccesses,
                                       stack_accesses - 3);
      view.steps.push_back(std::move(row));
    }
    view.nodes.push_back(std::move(box));
  }
  view.slots.reserve(trace.stack_slots.size());
  for (const auto &slot : trace.stack_slots) {
    SlotRow row;
    row.slot = &slot;
    view.slots.push_back(row);
  }
  std::sort(view.slots.begin(), view.slots.end(),
            [](const SlotRow &left, const SlotRow &right) {
              return left.slot->address < right.slot->address;
            });
  const auto slot_at = [&](std::uint64_t address) {
    return std::lower_bound(view.slots.begin(), view.slots.end(), address,
                            [](const SlotRow &row, std::uint64_t value) {
                              return row.slot->address < value;
                            });
  };
  for (std::size_t index = 0; index < trace.nodes.size(); ++index) {
    if (!trace.nodes[index].stack_slot)
      continue;
    const auto address = *trace.nodes[index].stack_slot;
    const auto row = slot_at(address);
    if (row != view.slots.end() && row->slot->address == address) {
      row->return_target = true;
      row->first_cursor =
          std::min(row->first_cursor, view.nodes[index].first_step);
    }
  }
  for (std::size_t index = 0; index < view.steps.size(); ++index) {
    const auto &instruction = *view.steps[index].instruction;
    if (!instruction.completed)
      continue;
    for (const auto &access : instruction.memory_accesses) {
      if (!access.stack || access.write || access.before.empty())
        continue;
      auto row = slot_at(access.address);
      if (row != view.slots.begin() &&
          covers(access.address, (row - 1)->slot->address, trace.pointer_size))
        --row;
      for (;
           row != view.slots.end() &&
           (covers(row->slot->address, access.address, access.before.size()) ||
            covers(access.address, row->slot->address, trace.pointer_size));
           ++row) {
        if (instruction.flow != "return" ||
            access.address != instruction.sp_before)
          row->data = true;
        row->first_cursor = std::min(row->first_cursor, index + 1);
      }
    }
  }
  select_cursor(view, 0);
}

void reconstruct_state(RopView &view) {
  if (view.reconstructed_cursor == view.cursor)
    return;
  const auto &trace = *view.trace;
  view.selected_effect = 0;
  view.formatted_effect = nullptr;
  const auto complete_word =
      static_cast<std::uint8_t>((1U << std::min(trace.pointer_size, 8U)) - 1U);
  for (auto &row : view.slots) {
    row.value = row.slot->value;
    row.readable = row.slot->readable;
    row.changed = false;
    row.known_bytes = row.readable ? complete_word : 0;
  }
  for (std::size_t index = 0; index < view.registers.size(); ++index) {
    view.registers[index].value = trace.initial_registers[index].value;
    view.registers[index].before.reset();
  }
  view.simulated_pc =
      trace.nodes.empty() ? trace.source_pc : trace.nodes.front().entry_address;
  view.simulated_sp =
      trace.nodes.empty() ? trace.source_sp : trace.nodes.front().entry_sp;
  for (std::size_t index = 0; index < view.cursor; ++index) {
    const auto &instruction = *view.steps[index].instruction;
    if (!instruction.completed)
      continue;
    view.simulated_pc = instruction.next_address;
    view.simulated_sp = instruction.sp_after;
    for (const auto &change : instruction.register_changes) {
      const auto found = std::find_if(
          view.registers.begin(), view.registers.end(),
          [&](const RegisterRow &reg) { return reg.name == change.name; });
      if (found != view.registers.end()) {
        found->value = change.after;
        if (index + 1 == view.cursor)
          found->before = change.before;
      }
    }
    for (const auto &access : instruction.memory_accesses) {
      if (!access.write || access.after.empty())
        continue;
      const auto overlap_start = access.address >= trace.pointer_size
                                     ? access.address - trace.pointer_size + 1
                                     : 0;
      auto slot =
          std::lower_bound(view.slots.begin(), view.slots.end(), overlap_start,
                           [](const SlotRow &row, std::uint64_t address) {
                             return row.slot->address < address;
                           });
      const auto last_byte = access.address + access.after.size() - 1;
      for (; slot != view.slots.end() && slot->slot->address <= last_byte;
           ++slot) {
        for (std::uint32_t offset = 0;
             offset < trace.pointer_size && offset < 8; ++offset) {
          const auto address = slot->slot->address + offset;
          if (!covers(address, access.address, access.after.size()))
            continue;
          const unsigned shift = offset * 8;
          slot->value =
              (slot->value & ~(std::uint64_t{0xff} << shift)) |
              (static_cast<std::uint64_t>(access.after[static_cast<std::size_t>(
                   address - access.address)])
               << shift);
          slot->known_bytes |= static_cast<std::uint8_t>(1U << offset);
          slot->changed = true;
        }
        slot->readable = slot->known_bytes == complete_word;
      }
    }
  }
  view.reconstructed_cursor = view.cursor;
}

void build_layout(RopView &view) {
  view.font = ImGui::GetFont();
  view.font_size = ImGui::GetFontSize();
  view.padding = view.font_size * 0.65F;
  view.line_height = view.font_size * 1.3F;
  view.header_height = view.line_height * 2 + view.padding * 2;
  const auto width = [&](const std::string &text) {
    return ImGui::CalcTextSize(text.c_str()).x;
  };
  float node_width = view.font_size * 34;
  float edge_width = 0;
  for (auto &node : view.nodes) {
    node_width =
        std::max({node_width, width(node.title), width(node.subtitle)});
    edge_width = std::max(edge_width, width(node.edge));
    float offset = 0;
    for (std::size_t index = node.first_step;
         index < node.first_step + node.step_count; ++index) {
      auto &row = view.steps[index];
      row.offset = offset;
      std::size_t lines = 2;
      if (!row.annotation.empty())
        ++lines;
      if (!row.register_effects.empty())
        ++lines;
      if (!row.memory_effects.empty())
        ++lines;
      row.height = view.line_height * static_cast<float>(lines) + view.padding;
      offset += row.height;
      node_width = std::max(
          {node_width, width(row.text), width(row.sp), width(row.annotation)});
    }
    node.size.y = view.header_height + std::max(offset, view.line_height);
  }
  node_width =
      std::clamp(node_width + view.padding * 2, view.font_size * 34,
                 view.font_size * 62);
  const float gap_x =
      std::max(view.font_size * 8, edge_width + view.padding * 2);
  const float gap_y = view.font_size * 5;
  float y = 0;
  view.bounds = ImVec2(0, 0);
  const std::size_t columns = std::min<std::size_t>(3, view.nodes.size());
  for (std::size_t first = 0; first < view.nodes.size(); first += columns) {
    float row_height = 0;
    const bool reverse = (first / columns) % 2 != 0;
    for (std::size_t offset = 0;
         offset < columns && first + offset < view.nodes.size(); ++offset) {
      auto &node = view.nodes[first + offset];
      const std::size_t column = reverse ? columns - offset - 1 : offset;
      node.position =
          ImVec2(static_cast<float>(column) * (node_width + gap_x), y);
      node.size.x = node_width;
      row_height = std::max(row_height, node.size.y);
      view.bounds.x = std::max(view.bounds.x, node.position.x + node.size.x);
      view.bounds.y = std::max(view.bounds.y, y + node.size.y);
    }
    y += row_height + gap_y;
  }
}

void synchronize(RopView &view, const debugger::SessionSnapshot &snapshot,
                 const RopTraceSnapshot &job) {
  if (view.observed_revision != snapshot.revision) {
    view.observed_revision = snapshot.revision;
    view.observed_source = source_stamp(snapshot);
  }
  const bool stopped = snapshot.state == debugger::SessionState::Stopped;
  if (view.trace && (!stopped || view.trace_source.fingerprint !=
                                     view.observed_source.fingerprint))
    view.stale = true;
  if (view.request_job && (!stopped || view.request_source.fingerprint !=
                                           view.observed_source.fingerprint))
    view.request_stale = true;
  if (!job.trace || job.trace == view.trace)
    return;
  view.trace = job.trace;
  view.trace_job = job.job_id;
  const auto &trace = *view.trace;
  const auto &source = view.request_source;
  const bool from_request =
      job.job_id == view.request_job && view.request_job != 0;
  view.trace_source = source;
  view.stale = !from_request || view.request_stale || !stopped ||
               source.fingerprint != view.observed_source.fingerprint ||
               trace.generation != source.generation ||
               trace.stop_revision != source.stop_revision ||
               trace.thread_id != source.thread_id ||
               trace.source_pc != source.pc || trace.source_sp != source.sp;
  build_trace_rows(view);
}

void draw_graph(RopView &view) {
  if (view.font != ImGui::GetFont() || view.font_size != ImGui::GetFontSize())
    build_layout(view);
  if (ImGui::Button(l10n::label(l10n::Key::GuiRopFit)))
    view.fit_requested = true;
  ImGui::SameLine();
  if (ImGui::Button(l10n::label(l10n::Key::GuiRopCenter)))
    view.center_requested = true;
  ImGui::SameLine();
  if (ImGui::Button(l10n::label(l10n::Key::GuiRopActualSize))) {
    view.zoom = 1;
    view.center_requested = true;
  }
  ImGui::SameLine();
  ImGui::TextDisabled("%.0f%%", view.zoom * 100);
  ImGui::SameLine();
  ImGui::TextDisabled("(?)");
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", l10n::text(l10n::Key::GuiRopGraphHelp));
  if (!ImGui::BeginChild("rop-canvas", ImVec2(0, 0), ImGuiChildFlags_Borders,
                         ImGuiWindowFlags_NoScrollbar |
                             ImGuiWindowFlags_NoScrollWithMouse)) {
    ImGui::EndChild();
    return;
  }
  const ImVec2 origin = ImGui::GetCursorScreenPos();
  const ImVec2 available = ImGui::GetContentRegionAvail();
  const ImVec2 size(std::max(available.x, 1.0F), std::max(available.y, 1.0F));
  ImGui::InvisibleButton("rop-graph", size,
                         ImGuiButtonFlags_MouseButtonLeft |
                             ImGuiButtonFlags_MouseButtonMiddle);
  const bool hovered = ImGui::IsItemHovered();
  const bool active = ImGui::IsItemActive();
  const auto &io = ImGui::GetIO();
  if (view.fit_requested) {
    view.zoom =
        std::clamp(std::min((size.x - 24) / std::max(view.bounds.x, 1.0F),
                            (size.y - 24) / std::max(view.bounds.y, 1.0F)),
                   0.02F, 1.0F);
    view.pan = ImVec2((size.x - view.bounds.x * view.zoom) / 2,
                      (size.y - view.bounds.y * view.zoom) / 2);
    view.fit_requested = false;
    view.center_requested = false;
    view.reveal_requested = false;
  }
  if (view.reveal_requested && view.selected_node < view.nodes.size()) {
    const auto &node = view.nodes[view.selected_node];
    const ImVec2 start(view.pan.x + node.position.x * view.zoom,
                       view.pan.y + node.position.y * view.zoom);
    const ImVec2 end(start.x + node.size.x * view.zoom,
                     start.y + node.size.y * view.zoom);
    view.center_requested = view.center_requested || start.x < 0 ||
                            start.y < 0 || end.x > size.x || end.y > size.y;
    view.reveal_requested = false;
  }
  if (view.center_requested && view.selected_node < view.nodes.size()) {
    const auto &node = view.nodes[view.selected_node];
    float row_y = view.header_height / 2;
    if (view.cursor && view.steps[view.cursor - 1].node == view.selected_node)
      row_y = view.header_height + view.steps[view.cursor - 1].offset +
              view.steps[view.cursor - 1].height / 2;
    view.pan =
        ImVec2(size.x / 2 - (node.position.x + node.size.x / 2) * view.zoom,
               size.y / 2 - (node.position.y + row_y) * view.zoom);
    view.center_requested = false;
  }
  if (hovered && io.MouseWheel != 0) {
    const ImVec2 anchor(io.MousePos.x - origin.x, io.MousePos.y - origin.y);
    const ImVec2 world((anchor.x - view.pan.x) / view.zoom,
                       (anchor.y - view.pan.y) / view.zoom);
    view.zoom =
        std::clamp(view.zoom * std::pow(1.15F, io.MouseWheel), 0.02F, 2.5F);
    view.pan =
        ImVec2(anchor.x - world.x * view.zoom, anchor.y - world.y * view.zoom);
  }
  const ImVec2 mouse((io.MousePos.x - origin.x - view.pan.x) / view.zoom,
                     (io.MousePos.y - origin.y - view.pan.y) / view.zoom);
  std::size_t hovered_node = no_selection;
  std::size_t hovered_step = no_selection;
  if (hovered) {
    for (std::size_t index = 0; index < view.nodes.size(); ++index) {
      const auto &node = view.nodes[index];
      if (!contains(mouse, node.position, node.size))
        continue;
      hovered_node = index;
      const float y = mouse.y - node.position.y - view.header_height;
      for (std::size_t step = node.first_step;
           step < node.first_step + node.step_count; ++step) {
        if (y >= view.steps[step].offset &&
            y < view.steps[step].offset + view.steps[step].height) {
          hovered_step = step;
          break;
        }
      }
      break;
    }
  }
  if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
    view.background_drag = hovered_node == no_selection;
    if (hovered_step != no_selection)
      select_cursor(view, hovered_step + 1, false);
    else if (hovered_node != no_selection) {
      select_cursor(view, view.nodes[hovered_node].first_step, false);
      view.selected_node = hovered_node;
    }
  }
  if (!ImGui::IsMouseDown(ImGuiMouseButton_Left))
    view.background_drag = false;
  if (active && (ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0) ||
                 (view.background_drag &&
                  ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0)))) {
    view.pan.x += io.MouseDelta.x;
    view.pan.y += io.MouseDelta.y;
    ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeAll);
  }
  const auto screen = [&](ImVec2 point) {
    return ImVec2(origin.x + view.pan.x + point.x * view.zoom,
                  origin.y + view.pan.y + point.y * view.zoom);
  };
  auto *draw = ImGui::GetWindowDrawList();
  draw->PushClipRect(origin, ImVec2(origin.x + size.x, origin.y + size.y),
                     true);
  const ImU32 text = ImGui::GetColorU32(ImGuiCol_Text);
  const ImU32 muted = ImGui::GetColorU32(ImGuiCol_TextDisabled);
  const ImU32 accent = ImGui::GetColorU32(ImGuiCol_SliderGrabActive);
  const float text_size = view.font_size * view.zoom;
  const auto fit_line = [&](std::string_view value, float width) {
    return fit_text(*view.font, text_size, value, width);
  };
  for (std::size_t index = 1; index < view.nodes.size(); ++index) {
    const auto &from = view.nodes[index - 1];
    const auto &to = view.nodes[index];
    const bool same_row = from.position.y == to.position.y;
    const bool right = to.position.x > from.position.x;
    ImVec2 start = same_row
                       ? ImVec2(from.position.x + (right ? from.size.x : 0),
                                from.position.y + view.header_height / 2)
                       : ImVec2(from.position.x + from.size.x / 2,
                                from.position.y + from.size.y);
    ImVec2 end = same_row
                     ? ImVec2(to.position.x + (right ? 0 : to.size.x),
                              to.position.y + view.header_height / 2)
                     : ImVec2(to.position.x + to.size.x / 2, to.position.y);
    start = screen(start);
    end = screen(end);
    const ImU32 color = view.trace->nodes[index].stack_slot ? accent : muted;
    draw->AddLine(start, end, color, std::max(1.0F, 2 * view.zoom));
    const float arrow = std::max(3.0F, 7 * view.zoom);
    const ImVec2 direction =
        same_row ? ImVec2(right ? 1.0F : -1.0F, 0) : ImVec2(0, 1);
    draw->AddTriangleFilled(
        end,
        ImVec2(end.x - direction.x * arrow - direction.y * arrow / 2,
               end.y - direction.y * arrow + direction.x * arrow / 2),
        ImVec2(end.x - direction.x * arrow + direction.y * arrow / 2,
               end.y - direction.y * arrow - direction.x * arrow / 2),
        color);
    const auto &label = from.edge;
    const ImVec2 label_size =
        view.font->CalcTextSizeA(text_size, 1e6F, 0, label.c_str());
    const ImVec2 midpoint((start.x + end.x) / 2, (start.y + end.y) / 2);
    const ImVec2 label_position =
        same_row ? ImVec2(midpoint.x - label_size.x / 2,
                          midpoint.y - label_size.y - 3)
                 : ImVec2(midpoint.x + 5, midpoint.y - label_size.y / 2);
    draw->AddText(view.font, text_size, label_position, color, label.c_str());
  }
  for (std::size_t index = 0; index < view.nodes.size(); ++index) {
    const auto &node = view.nodes[index];
    const ImVec2 start = screen(node.position);
    const ImVec2 end = screen(
        ImVec2(node.position.x + node.size.x, node.position.y + node.size.y));
    if (end.x < origin.x || end.y < origin.y || start.x > origin.x + size.x ||
        start.y > origin.y + size.y)
      continue;
    draw->AddRectFilled(start, end, ImGui::GetColorU32(ImGuiCol_ChildBg),
                        4 * view.zoom);
    draw->AddRect(start, end,
                  index == view.selected_node
                      ? accent
                      : ImGui::GetColorU32(ImGuiCol_Border),
                  4 * view.zoom, index == view.selected_node ? 2.0F : 1.0F);
    draw->PushClipRect(start, end, true);
    draw->AddRectFilled(start,
                        ImVec2(end.x, start.y + view.header_height * view.zoom),
                        ImGui::GetColorU32(ImGuiCol_Header));
    const float x = start.x + view.padding * view.zoom;
    const float text_width = std::max(1.0F, (node.size.x - view.padding * 2) *
                                                view.zoom);
    const auto title = fit_line(node.title, text_width);
    const auto subtitle = fit_line(node.subtitle, text_width);
    draw->AddText(view.font, text_size,
                  ImVec2(x, start.y + view.padding * view.zoom), text,
                  title.c_str());
    draw->AddText(
        view.font, text_size,
        ImVec2(x, start.y + (view.padding + view.line_height) * view.zoom),
        muted, subtitle.c_str());
    for (std::size_t step = node.first_step;
         step < node.first_step + node.step_count; ++step) {
      const auto &row = view.steps[step];
      const float y = start.y + (view.header_height + row.offset) * view.zoom;
      if (y + row.height * view.zoom < origin.y || y > origin.y + size.y)
        continue;
      if (view.cursor == step + 1 || hovered_step == step)
        draw->AddRectFilled(ImVec2(start.x, y),
                            ImVec2(end.x, y + row.height * view.zoom),
                            ImGui::GetColorU32(view.cursor == step + 1
                                                   ? ImGuiCol_HeaderActive
                                                   : ImGuiCol_HeaderHovered));
      const auto instruction_text = fit_line(row.text, text_width);
      const auto sp_text = fit_line(row.sp, text_width);
      draw->AddText(
          view.font, text_size, ImVec2(x, y + view.padding * 0.35F * view.zoom),
          row.instruction->completed ? text : muted, instruction_text.c_str());
      draw->AddText(
          view.font, text_size,
          ImVec2(x, y + (view.line_height + view.padding * 0.35F) * view.zoom),
          muted, sp_text.c_str());
      float line = 2;
      if (!row.annotation.empty()) {
        const auto annotation = fit_line(row.annotation, text_width);
        draw->AddText(
            view.font, text_size,
            ImVec2(x, y + (view.line_height * line + view.padding * 0.35F) *
                              view.zoom),
            muted, annotation.c_str());
        line += 1;
      }
      if (!row.register_effects.empty()) {
        const auto register_effects =
            fit_line(row.register_effects, text_width);
        draw->AddText(
            view.font, text_size,
            ImVec2(x, y + (view.line_height * line + view.padding * 0.35F) *
                              view.zoom),
            accent, register_effects.c_str());
        line += 1;
      }
      if (!row.memory_effects.empty()) {
        const auto memory_effects = fit_line(row.memory_effects, text_width);
        draw->AddText(
            view.font, text_size,
            ImVec2(x, y + (view.line_height * line + view.padding * 0.35F) *
                              view.zoom),
            muted, memory_effects.c_str());
      }
    }
    draw->PopClipRect();
  }
  draw->PopClipRect();
  if (hovered_step != no_selection &&
      !ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
    const auto &row = view.steps[hovered_step];
    ImGui::BeginTooltip();
    ImGui::TextUnformatted(row.text.c_str());
    ImGui::TextUnformatted(row.sp.c_str());
    if (!row.annotation.empty())
      ImGui::TextUnformatted(row.annotation.c_str());
    if (!row.register_effects.empty())
      ImGui::TextUnformatted(row.register_effects.c_str());
    if (!row.memory_effects.empty())
      ImGui::TextUnformatted(row.memory_effects.c_str());
    ImGui::EndTooltip();
  }
  ImGui::EndChild();
}

void draw_inspectors(RopView &view, const debugger::SessionSnapshot &snapshot,
                     debugger::LldbEngine &engine, UiState &ui,
                     bool live_follow) {
  reconstruct_state(view);
  ImGui::Text(l10n::text(l10n::Key::GuiRopSimulatedState), view.simulated_pc,
              view.simulated_sp);
  const StepRow *step = view.cursor ? &view.steps[view.cursor - 1] : nullptr;
  if (step) {
    ImGui::TextWrapped("%s", step->text.c_str());
    ImGui::TextUnformatted(step->sp.c_str());
    if (!step->instruction->completed)
      ImGui::TextWrapped("%s", l10n::text(l10n::Key::GuiRopNotExecuted));
  } else {
    ImGui::TextWrapped("%s", l10n::text(l10n::Key::GuiRopInitialState));
  }
  ImGui::BeginDisabled(!live_follow || view.nodes.empty());
  if (ImGui::Button(l10n::label(l10n::Key::GuiRopFollowInstruction)))
    follow_address(snapshot, engine, ui,
                   step ? step->instruction->address : view.simulated_pc);
  ImGui::EndDisabled();
  if (ImGui::BeginTabBar("rop-inspectors")) {
    if (ImGui::BeginTabItem(l10n::label(l10n::Key::GuiRopRegisters))) {
      if (ImGui::BeginTable("rop-registers", 3,
                            ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                                ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupColumn(l10n::text(l10n::Key::GuiRopRegister));
        ImGui::TableSetupColumn(l10n::text(l10n::Key::GuiRopValue));
        ImGui::TableSetupColumn(l10n::text(l10n::Key::GuiRopPreviousValue));
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        for (const auto &reg : view.registers) {
          ImGui::TableNextRow();
          ImGui::TableNextColumn();
          ImGui::TextUnformatted(reg.name.c_str());
          ImGui::TableNextColumn();
          if (reg.before)
            ImGui::PushStyleColor(
                ImGuiCol_Text,
                ImGui::GetStyleColorVec4(ImGuiCol_SliderGrabActive));
          ImGui::Text("0x%" PRIx64, reg.value);
          if (reg.before)
            ImGui::PopStyleColor();
          ImGui::TableNextColumn();
          if (reg.before)
            ImGui::Text("0x%" PRIx64, *reg.before);
        }
        ImGui::EndTable();
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem(l10n::label(l10n::Key::GuiRopStack))) {
      ImGui::TextWrapped("%s", l10n::text(l10n::Key::GuiRopStackHelp));
      ImGui::BeginDisabled(!live_follow ||
                           view.selected_slot >= view.slots.size());
      if (ImGui::Button(l10n::label(l10n::Key::GuiRopFollowSlot))) {
        follow_memory(engine, ui.memory,
                      view.slots[view.selected_slot].slot->address);
        ui_focus_navigation_target(AppNavigationTarget::Memory);
      }
      ImGui::EndDisabled();
      if (ImGui::BeginTable("rop-stack", 3,
                            ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                                ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupColumn(l10n::text(l10n::Key::GuiRopAddress));
        ImGui::TableSetupColumn(l10n::text(l10n::Key::GuiRopValue));
        ImGui::TableSetupColumn(l10n::text(l10n::Key::GuiRopRole));
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(view.slots.size()));
        while (clipper.Step()) {
          for (int index = clipper.DisplayStart; index < clipper.DisplayEnd;
               ++index) {
            const auto &row = view.slots[static_cast<std::size_t>(index)];
            ImGui::PushID(index);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char address[32];
            std::snprintf(address, sizeof(address), "0x%" PRIx64,
                          row.slot->address);
            if (ImGui::Selectable(address,
                                  view.selected_slot ==
                                      static_cast<std::size_t>(index),
                                  ImGuiSelectableFlags_SpanAllColumns)) {
              view.selected_slot = static_cast<std::size_t>(index);
              if (row.first_cursor != no_selection) {
                select_cursor(view, row.first_cursor);
                for (std::size_t node = 0; node < view.nodes.size(); ++node) {
                  if (view.trace->nodes[node].stack_slot == row.slot->address &&
                      view.nodes[node].first_step == row.first_cursor) {
                    view.selected_node = node;
                    break;
                  }
                }
              }
            }
            ImGui::TableNextColumn();
            if (row.readable)
              ImGui::Text("0x%" PRIx64 "%s", row.value,
                          row.changed ? " *" : "");
            else
              ImGui::TextDisabled("%s",
                                  l10n::text(l10n::Key::GuiRopUnreadable));
            ImGui::TableNextColumn();
            const auto key = row.return_target
                                 ? (row.data ? l10n::Key::GuiRopReturnAndData
                                             : l10n::Key::GuiRopReturnTarget)
                                 : (row.data ? l10n::Key::GuiRopData
                                             : l10n::Key::GuiRopUnconsumed);
            ImGui::TextUnformatted(l10n::text(key));
            ImGui::PopID();
          }
        }
        ImGui::EndTable();
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem(l10n::label(l10n::Key::GuiRopMemoryEffects))) {
      ImGui::TextWrapped("%s", l10n::text(l10n::Key::GuiRopMemoryHelp));
      if (!step || step->effects.empty()) {
        ImGui::TextWrapped("%s", l10n::text(l10n::Key::GuiRopNoMemoryEffects));
      } else {
        const float list_height =
            std::max(ImGui::GetTextLineHeightWithSpacing() * 3,
                     ImGui::GetContentRegionAvail().y * 0.4F);
        if (ImGui::BeginChild("rop-effects", ImVec2(0, list_height),
                              ImGuiChildFlags_Borders)) {
          ImGuiListClipper clipper;
          clipper.Begin(static_cast<int>(step->effects.size()));
          while (clipper.Step()) {
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd;
                 ++index) {
              const auto &access =
                  *step->effects[static_cast<std::size_t>(index)].access;
              char label[192];
              std::snprintf(
                  label, sizeof(label),
                  l10n::text(l10n::Key::GuiRopMemoryAccess),
                  l10n::text(access.write ? l10n::Key::GuiRopWrite
                                          : l10n::Key::GuiRopRead),
                  access.address, access.before.size(),
                  access.stack ? l10n::text(l10n::Key::GuiRopStackRegion) : "");
              ImGui::PushID(index);
              if (ImGui::Selectable(label, view.selected_effect ==
                                               static_cast<std::size_t>(index)))
                view.selected_effect = static_cast<std::size_t>(index);
              ImGui::PopID();
            }
          }
        }
        ImGui::EndChild();
        const auto &access = *step->effects[std::min(view.selected_effect,
                                                     step->effects.size() - 1)]
                                  .access;
        if (view.formatted_effect != &access) {
          view.effect_before = bytes_as_hex(access.before);
          view.effect_after = bytes_as_hex(access.after);
          view.formatted_effect = &access;
        }
        ImGui::BeginDisabled(!live_follow);
        if (ImGui::SmallButton(l10n::label(l10n::Key::GuiRopFollowMemory))) {
          follow_memory(engine, ui.memory, access.address);
          ui_focus_navigation_target(AppNavigationTarget::Memory);
        }
        ImGui::EndDisabled();
        if (ImGui::BeginChild("rop-effect-bytes")) {
          ImGui::TextWrapped(l10n::text(l10n::Key::GuiRopBeforeBytes),
                             view.effect_before.c_str());
          if (access.write)
            ImGui::TextWrapped(l10n::text(l10n::Key::GuiRopAfterBytes),
                               view.effect_after.c_str());
        }
        ImGui::EndChild();
      }
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }
}

} // namespace

void open_rop_at(UiState &ui, std::uint64_t address) {
  ui.workspace.show_rop = true;
  std::snprintf(ui.rop.address.data(), ui.rop.address.size(), "0x%" PRIx64,
                address);
  ui.rop.focus_requested = true;
}

void draw_rop_panel(const debugger::SessionSnapshot &snapshot,
                    debugger::LldbEngine &engine,
                    debugger::scripting::PythonRuntime &runtime, UiState &ui,
                    bool control_lease) {
  auto &state = ui.rop;
  state.window_focused = false;
  if (!state.view)
    state.view = std::make_shared<RopView>();
  auto &view = *state.view;
  auto job = runtime.rop_snapshot();
  synchronize(view, snapshot, job);
  if (!ui.workspace.show_rop)
    return;
  if (std::exchange(state.focus_requested, false))
    ImGui::SetNextWindowFocus();
  ImGui::SetNextWindowSize(ImVec2(1100, 760), ImGuiCond_FirstUseEver);
  const bool visible =
      ImGui::Begin(l10n::label(l10n::Key::WindowRop), &ui.workspace.show_rop);
  state.window_focused =
      ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
  if (!visible) {
    ImGui::End();
    return;
  }
  ImGui::TextWrapped("%s", l10n::text(l10n::Key::GuiRopSimulationNotice));
  ImGui::SetNextItemWidth(ImGui::GetFontSize() * 19);
  ImGui::InputTextWithHint(l10n::label(l10n::Key::GuiRopStackAddress),
                           l10n::text(l10n::Key::GuiRopAddressHint),
                           state.address.data(), state.address.size());
  ImGui::SameLine();
  const bool stopped = snapshot.state == debugger::SessionState::Stopped;
  ImGui::BeginDisabled(!stopped || control_lease || busy(job.status));
  if (ImGui::Button(l10n::label(l10n::Key::GuiRopUseSp)))
    std::snprintf(state.address.data(), state.address.size(), "0x%" PRIx64,
                  snapshot.sp);
  ImGui::SameLine();
  if (ImGui::Button(l10n::label(l10n::Key::GuiRopAnalyze))) {
    std::string_view input(state.address.data());
    while (!input.empty() && input.front() == ' ')
      input.remove_prefix(1);
    while (!input.empty() && input.back() == ' ')
      input.remove_suffix(1);
    const auto address =
        input == "$sp"
            ? std::optional<std::uint64_t>(snapshot.sp)
            : parse_value(input.starts_with("0x") || input.starts_with("0X")
                              ? std::string(input)
                              : "0x" + std::string(input));
    if (!address) {
      view.input_error = l10n::text(l10n::Key::GuiRopInvalidAddress);
    } else {
      RopTraceRequest request;
      request.stack_address = *address;
      request.stack_bytes =
          static_cast<std::uint32_t>(std::clamp(state.stack_bytes, 8, 65536));
      request.max_instructions = static_cast<std::uint32_t>(
          std::clamp(state.max_instructions, 1, 4096));
      request.max_nodes =
          static_cast<std::uint32_t>(std::clamp(state.max_nodes, 1, 512));
      request.timeout_seconds = std::clamp(state.timeout_seconds, 0.1F, 30.0F);
      if (runtime.trace_rop(request)) {
        job = runtime.rop_snapshot();
        view.request_source = source_stamp(snapshot);
        view.request_job = job.job_id;
        view.request_stale = false;
        view.input_error.clear();
      } else {
        view.input_error = l10n::text(l10n::Key::GuiRopWorkerBusy);
      }
    }
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  ImGui::BeginDisabled(!busy(job.status) ||
                       job.status == RopJobStatus::Cancelling);
  if (ImGui::Button(l10n::label(l10n::Key::GuiRopCancel)))
    runtime.cancel_rop();
  ImGui::EndDisabled();
  ImGui::SameLine();
  ImGui::TextUnformatted(job_label(job.status));
  if (ImGui::CollapsingHeader(l10n::label(l10n::Key::GuiRopLimits))) {
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 10);
    ImGui::InputInt(l10n::label(l10n::Key::GuiRopStackBytes),
                    &state.stack_bytes);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 10);
    ImGui::InputInt(l10n::label(l10n::Key::GuiRopInstructionLimit),
                    &state.max_instructions);
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 10);
    ImGui::InputInt(l10n::label(l10n::Key::GuiRopNodeLimit), &state.max_nodes);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 10);
    ImGui::InputFloat(l10n::label(l10n::Key::GuiRopTimeout),
                      &state.timeout_seconds, 0.5F, 1.0F, "%.1f");
    state.stack_bytes = std::clamp(state.stack_bytes, 8, 65536);
    state.max_instructions = std::clamp(state.max_instructions, 1, 4096);
    state.max_nodes = std::clamp(state.max_nodes, 1, 512);
    state.timeout_seconds = std::isfinite(state.timeout_seconds)
                                ? std::clamp(state.timeout_seconds, 0.1F, 30.0F)
                                : 5.0F;
  }
  if (!view.input_error.empty())
    ImGui::TextWrapped("%s", view.input_error.c_str());
  if (!job.error.empty())
    ImGui::TextWrapped("%s", job.error.c_str());
  if (!view.trace) {
    ImGui::TextWrapped("%s", l10n::text(stopped ? l10n::Key::GuiRopEmpty
                                                : l10n::Key::GuiRopStopFirst));
    ImGui::End();
    return;
  }
  ImGui::Separator();
  if (job.job_id != view.trace_job)
    ImGui::TextWrapped("%s", l10n::text(l10n::Key::GuiRopPreviousTrace));
  ImGui::TextWrapped("%s", l10n::text(view.stale ? l10n::Key::GuiRopStale
                                                 : l10n::Key::GuiRopFresh));
  ImGui::Text(l10n::text(l10n::Key::GuiRopTraceSource),
              view.trace->stack_address, view.trace->thread_id,
              view.trace->stop_revision, view.trace->architecture.c_str());
  ImGui::TextWrapped(l10n::text(l10n::Key::GuiRopTerminal),
                     view.trace->status.c_str(), view.trace->message.c_str());
  if (view.nodes.empty()) {
    ImGui::TextWrapped("%s", l10n::text(l10n::Key::GuiRopNoNodes));
    ImGui::End();
    return;
  }
  const bool live_follow =
      !view.stale && !control_lease && !busy(job.status) && stopped;
  ImGui::BeginDisabled(view.cursor == 0);
  if (ImGui::Button(l10n::label(l10n::Key::GuiRopReset)))
    select_cursor(view, 0);
  ImGui::SameLine();
  if (ImGui::Button(l10n::label(l10n::Key::GuiRopPrevious)))
    select_cursor(view, view.cursor - 1);
  ImGui::EndDisabled();
  ImGui::SameLine();
  ImGui::BeginDisabled(view.cursor >= view.steps.size());
  if (ImGui::Button(l10n::label(l10n::Key::GuiRopNext)))
    select_cursor(view, view.cursor + 1);
  ImGui::EndDisabled();
  ImGui::SameLine();
  const auto next_gadget = std::find_if(
      view.nodes.begin(), view.nodes.end(), [&](const NodeBox &node) {
        const std::size_t index =
            static_cast<std::size_t>(&node - view.nodes.data());
        return index > view.selected_node && node.first_step >= view.cursor &&
               view.trace->nodes[index].stack_slot.has_value();
      });
  ImGui::BeginDisabled(next_gadget == view.nodes.end());
  if (ImGui::Button(l10n::label(l10n::Key::GuiRopNextGadget))) {
    select_cursor(view, next_gadget->first_step);
    view.selected_node =
        static_cast<std::size_t>(next_gadget - view.nodes.begin());
  }
  ImGui::EndDisabled();
  ImGui::SameLine();
  ImGui::Text(l10n::text(l10n::Key::GuiRopStepCount), view.cursor,
              view.steps.size(), view.nodes.size());
  ImGui::SameLine();
  ImGui::Checkbox(l10n::label(l10n::Key::GuiRopSyncLiveViews),
                  &state.sync_live_views);
  if (ImGui::IsItemHovered())
    ImGui::SetTooltip("%s", l10n::text(l10n::Key::GuiRopSyncLiveViewsHelp));
  int cursor = static_cast<int>(view.cursor);
  ImGui::SetNextItemWidth(-1);
  if (ImGui::SliderInt("##rop-timeline", &cursor, 0,
                       static_cast<int>(view.steps.size()), "%d"))
    select_cursor(view, static_cast<std::size_t>(cursor));
  if (state.window_focused && !ImGui::GetIO().WantTextInput &&
      !ImGui::GetIO().KeyCtrl && !ImGui::GetIO().KeyAlt &&
      !ImGui::GetIO().KeySuper) {
    if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow) && view.cursor)
      select_cursor(view, view.cursor - 1);
    if (ImGui::IsKeyPressed(ImGuiKey_RightArrow) &&
        view.cursor < view.steps.size())
      select_cursor(view, view.cursor + 1);
  }
  if (state.sync_live_views && live_follow) {
    const auto address = selected_live_address(view);
    if (address && (view.synced_trace_job != view.trace_job ||
                    view.synced_cursor != view.cursor ||
                    view.synced_address != *address) &&
        sync_live_view(snapshot, engine, ui, *address)) {
      view.synced_trace_job = view.trace_job;
      view.synced_cursor = view.cursor;
      view.synced_address = *address;
    }
  } else {
    view.synced_trace_job = 0;
    view.synced_cursor = no_selection;
  }
  if (ImGui::BeginTable("rop-workspace", 2,
                        ImGuiTableFlags_Resizable |
                            ImGuiTableFlags_BordersInnerV)) {
    ImGui::TableSetupColumn("##graph", ImGuiTableColumnFlags_WidthStretch,
                            0.64F);
    ImGui::TableSetupColumn("##inspectors", ImGuiTableColumnFlags_WidthStretch,
                            0.36F);
    ImGui::TableNextRow();
    ImGui::TableNextColumn();
    if (ImGui::BeginChild("rop-graph-pane", ImVec2(0, 0)))
      draw_graph(view);
    ImGui::EndChild();
    ImGui::TableNextColumn();
    if (ImGui::BeginChild("rop-inspector-pane", ImVec2(0, 0)))
      draw_inspectors(view, snapshot, engine, ui, live_follow);
    ImGui::EndChild();
    ImGui::EndTable();
  }
  ImGui::End();
}

} // namespace mydbg::app
