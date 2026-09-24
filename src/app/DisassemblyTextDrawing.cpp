#include "app/DisassemblyTextDrawing.h"

#include <imgui_internal.h>

#include <algorithm>
#include <cfloat>
#include <cinttypes>
#include <cmath>
#include <limits>

namespace mydbg::app {
namespace {

using Kind = DisassemblyTokenKind;

ImU32 token_color(Kind kind) {
  const auto &background = ImGui::GetStyleColorVec4(ImGuiCol_WindowBg);
  const bool dark = background.x + background.y + background.z < 1.5F;
  // Match the decompiler's keyword/parameter/constant/global palette families.
  ImU32 color{};
  switch (kind) {
  case Kind::Mnemonic:
    color = dark ? IM_COL32(198, 120, 221, 255) : IM_COL32(116, 42, 145, 255);
    break;
  case Kind::ControlFlow:
    color = dark ? IM_COL32(240, 137, 117, 255) : IM_COL32(166, 45, 28, 255);
    break;
  case Kind::Register:
    color = dark ? IM_COL32(156, 220, 254, 255) : IM_COL32(0, 88, 138, 255);
    break;
  case Kind::Number:
    color = dark ? IM_COL32(181, 206, 168, 255) : IM_COL32(64, 103, 38, 255);
    break;
  case Kind::Punctuation:
  case Kind::Type:
    color = dark ? IM_COL32(78, 201, 176, 255) : IM_COL32(0, 103, 84, 255);
    break;
  case Kind::Symbol:
    color = dark ? IM_COL32(235, 186, 120, 255) : IM_COL32(132, 77, 8, 255);
    break;
  case Kind::String:
    color = dark ? IM_COL32(206, 145, 120, 255) : IM_COL32(153, 62, 31, 255);
    break;
  case Kind::Comment:
    color = dark ? IM_COL32(137, 169, 120, 255) : IM_COL32(67, 105, 46, 255);
    break;
  case Kind::Runtime:
    color = dark ? IM_COL32(220, 220, 170, 255) : IM_COL32(116, 89, 0, 255);
    break;
  case Kind::Plain:
    return ImGui::GetColorU32(ImGuiCol_Text);
  }
  return ImGui::GetColorU32(ImGui::ColorConvertU32ToFloat4(color));
}

template <typename T>
bool same_debug_value(const std::shared_ptr<const T> &left,
                      const std::shared_ptr<const T> &right) {
  return left == right || (left && right && *left == *right);
}

bool same_debug_scope(
    const std::shared_ptr<const debugger::DebugScopeInfo> &left,
    const std::shared_ptr<const debugger::DebugScopeInfo> &right) {
  return left == right ||
         (left && right && same_debug_value(left->function, right->function) &&
          left->declarations == right->declarations &&
          left->inline_name == right->inline_name &&
          left->inline_call_site == right->inline_call_site &&
          same_debug_scope(left->parent, right->parent));
}

struct PresentationSource {
  std::string mnemonic;
  std::string operands;
  std::string comment;
  std::string user_comment;
  debugger::InstructionFlowKind flow{};
  std::optional<std::uint64_t> flow_target;
  std::vector<std::uint8_t> bytes;
  std::vector<debugger::InstructionReference> references;
  std::shared_ptr<const debugger::DebugSourceLocation> source;
  std::shared_ptr<const debugger::DebugScopeInfo> debug_scope;
  bool begins_source{};
  bool begins_function{};
  bool begins_debug_scope{};

  bool matches(const debugger::InstructionRow &row) const {
    return mnemonic == row.mnemonic && operands == row.operands &&
           comment == row.comment && user_comment == row.user_comment &&
           flow == row.flow_kind && flow_target == row.flow_target &&
           bytes == row.bytes && same_debug_value(source, row.source) &&
           same_debug_scope(debug_scope, row.debug_scope) &&
           begins_source == row.begins_source &&
           begins_function == row.begins_function &&
           begins_debug_scope == row.begins_debug_scope &&
           references.size() == row.references.size() &&
           std::equal(references.begin(), references.end(),
                      row.references.begin(),
                      [](const auto &left, const auto &right) {
                        return left.address == right.address &&
                               left.symbol == right.symbol &&
                               left.preview == right.preview &&
                               left.runtime == right.runtime &&
                               left.declaration == right.declaration &&
                               same_debug_value(left.function, right.function);
                      });
  }
};

} // namespace

struct DisassemblyTextCache {
  std::uint64_t revision{std::numeric_limits<std::uint64_t>::max()};
  std::string architecture;
  ImFont *font{};
  float font_size{};
  float annotation_wrap_width{};
  std::vector<PresentationSource> sources;
  std::vector<DisassemblyPresentation> rows;
};

void measure_disassembly_text(DisassemblyText &text, ImFont *font,
                              float font_size, float wrap_width) {
  text.runs.clear();
  text.size = ImVec2(0.0F, text.text.empty() ? 0.0F : font_size);
  const char *data = text.text.data();
  const char *end = data + text.text.size();
  std::size_t token_index{};
  float y{};
  for (const char *line = data; line < end;) {
    const char *line_end = std::find(line, end, '\n');
    if (wrap_width > 0.0F) {
      const char *wrapped =
          font->CalcWordWrapPosition(font_size, line, line_end, wrap_width);
      if (wrapped == line && line < line_end) {
        unsigned int character{};
        wrapped += ImTextCharFromUtf8(&character, line, line_end);
      }
      line_end = wrapped;
    }
    float x{};
    const auto begin_offset = static_cast<std::size_t>(line - data);
    const auto end_offset = static_cast<std::size_t>(line_end - data);
    while (token_index < text.tokens.size() &&
           text.tokens[token_index].end <= begin_offset) {
      ++token_index;
    }
    for (auto index = token_index;
         index < text.tokens.size() && text.tokens[index].begin < end_offset;
         ++index) {
      const auto &span = text.tokens[index];
      const auto begin = std::max(begin_offset, span.begin);
      const auto finish = std::min(end_offset, span.end);
      text.runs.push_back(
          {{begin, finish, span.kind, span.target}, ImVec2(x, y)});
      x += font->CalcTextSizeA(font_size, FLT_MAX, 0.0F, data + begin,
                               data + finish)
               .x;
    }
    text.size.x = std::max(text.size.x, x);
    text.size.y = y + font_size;
    line = line_end;
    if (line < end && *line == '\n')
      ++line;
    else if (wrap_width > 0.0F) {
      while (line < end && (*line == ' ' || *line == '\t'))
        ++line;
    }
    y += font_size * 1.2F;
  }
}

void draw_disassembly_text(ImDrawList *draw, const DisassemblyText &text,
                           ImFont *font, float font_size, ImVec2 position,
                           float scale) {
  for (const auto &run : text.runs) {
    const char *begin = text.text.data() + run.token.begin;
    const char *end = text.text.data() + run.token.end;
    draw->AddText(font, font_size * scale,
                  ImVec2(position.x + run.position.x * scale,
                         position.y + run.position.y * scale),
                  token_color(run.token.kind), begin, end);
  }
}

std::optional<std::uint64_t>
hit_disassembly_text(const DisassemblyText &text, ImFont *font, float font_size,
                     ImVec2 position, ImVec2 point, ImVec2 clip_min,
                     ImVec2 clip_max, float scale) {
  if (point.x < clip_min.x || point.y < clip_min.y || point.x >= clip_max.x ||
      point.y >= clip_max.y || scale <= 0.0F)
    return std::nullopt;
  const float size = font_size * scale;
  for (const auto &run : text.runs) {
    if (!run.token.target)
      continue;
    // AddText snaps each run's origin to pixels before rendering its glyphs.
    float x = std::trunc(position.x + run.position.x * scale);
    const float y = std::trunc(position.y + run.position.y * scale);
    if (point.y < y || point.y >= y + size || point.x < x)
      continue;
    const char *cursor = text.text.data() + run.token.begin;
    const char *end = text.text.data() + run.token.end;
    while (cursor < end) {
      unsigned int character{};
      const int length = ImTextCharFromUtf8(&character, cursor, end);
      if (length <= 0)
        break;
      const float width =
          font->CalcTextSizeA(size, FLT_MAX, 0.0F, cursor, cursor + length).x;
      if (point.x >= x && point.x < x + width) {
        if (character != ' ' && character != '\t' && character != '\n' &&
            character != '\r')
          return run.token.target;
        break;
      }
      x += width;
      cursor += length;
    }
  }
  return std::nullopt;
}

std::optional<std::uint64_t>
draw_disassembly_text_cell(const DisassemblyText &text,
                           const debugger::SessionSnapshot &snapshot) {
  const auto position = ImGui::GetCursorScreenPos();
  const float width = std::max(1.0F, ImGui::GetContentRegionAvail().x);
  ImGui::Dummy(ImVec2(std::min(width, text.size.x),
                      std::max(ImGui::GetTextLineHeight(), text.size.y)));
  auto *draw = ImGui::GetWindowDrawList();
  draw_disassembly_text(draw, text, ImGui::GetFont(), ImGui::GetFontSize(),
                        position);
  std::optional<std::uint64_t> clicked;
  if (!text.text.empty() &&
      ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenOverlappedByItem |
                           ImGuiHoveredFlags_AllowWhenBlockedByActiveItem)) {
    const auto target =
        hit_disassembly_text(text, ImGui::GetFont(), ImGui::GetFontSize(),
                             position, ImGui::GetIO().MousePos,
                             draw->GetClipRectMin(), draw->GetClipRectMax());
    const bool valid = target && navigable_address(snapshot, *target);
    if (valid) {
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
      if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
        clicked = target;
    }
    ImGui::BeginTooltip();
    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 90.0F);
    ImGui::TextUnformatted(text.text.c_str());
    if (valid)
      ImGui::Text("0x%" PRIx64, *target);
    ImGui::PopTextWrapPos();
    ImGui::EndTooltip();
  }
  return clicked;
}

const std::vector<DisassemblyPresentation> &
disassembly_presentations(std::shared_ptr<DisassemblyTextCache> &cache,
                          const debugger::SessionSnapshot &snapshot,
                          float annotation_wrap_width) {
  if (!cache)
    cache = std::make_shared<DisassemblyTextCache>();
  const bool architecture_changed =
      cache->architecture != snapshot.architecture;
  const bool font_changed = cache->font != ImGui::GetFont() ||
                            cache->font_size != ImGui::GetFontSize();
  annotation_wrap_width = std::max(1.0F, annotation_wrap_width);
  const bool wrap_changed =
      cache->annotation_wrap_width != annotation_wrap_width;
  const bool data_changed = cache->revision != snapshot.revision ||
                            cache->rows.size() != snapshot.instructions.size();
  if (!architecture_changed && !font_changed && !data_changed && !wrap_changed)
    return cache->rows;
  cache->rows.resize(snapshot.instructions.size());
  cache->sources.resize(snapshot.instructions.size());
  for (std::size_t i = 0; i < snapshot.instructions.size(); ++i) {
    const auto &instruction = snapshot.instructions[i];
    const bool changed =
        architecture_changed || !cache->sources[i].matches(instruction);
    if (changed) {
      cache->rows[i] =
          make_disassembly_presentation(instruction, snapshot.architecture);
      cache->sources[i] = {instruction.mnemonic,
                           instruction.operands,
                           instruction.comment,
                           instruction.user_comment,
                           instruction.flow_kind,
                           instruction.flow_target,
                           instruction.bytes,
                           instruction.references,
                           instruction.source,
                           instruction.debug_scope,
                           instruction.begins_source,
                           instruction.begins_function,
                           instruction.begins_debug_scope};
    }
    if (changed || font_changed) {
      measure_disassembly_text(cache->rows[i].instruction, ImGui::GetFont(),
                               ImGui::GetFontSize());
    }
    if (changed || font_changed || wrap_changed) {
      measure_disassembly_text(cache->rows[i].annotation, ImGui::GetFont(),
                               ImGui::GetFontSize(), annotation_wrap_width);
    }
  }
  cache->revision = snapshot.revision;
  cache->architecture = snapshot.architecture;
  cache->font = ImGui::GetFont();
  cache->font_size = ImGui::GetFontSize();
  cache->annotation_wrap_width = annotation_wrap_width;
  return cache->rows;
}

} // namespace mydbg::app
