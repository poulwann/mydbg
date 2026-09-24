#pragma once

#include "app/DisassemblyText.h"

namespace mydbg::app {

struct DisassemblyTextCache;

void measure_disassembly_text(DisassemblyText &text, ImFont *font,
                              float font_size, float wrap_width = 0.0F);
void draw_disassembly_text(ImDrawList *draw, const DisassemblyText &text,
                           ImFont *font, float font_size, ImVec2 position,
                           float scale = 1.0F);
std::optional<std::uint64_t>
hit_disassembly_text(const DisassemblyText &text, ImFont *font, float font_size,
                     ImVec2 position, ImVec2 point, ImVec2 clip_min,
                     ImVec2 clip_max, float scale = 1.0F);
std::optional<std::uint64_t>
draw_disassembly_text_cell(const DisassemblyText &text,
                           const debugger::SessionSnapshot &snapshot);
const std::vector<DisassemblyPresentation> &
disassembly_presentations(std::shared_ptr<DisassemblyTextCache> &cache,
                          const debugger::SessionSnapshot &snapshot,
                          float annotation_wrap_width);

} // namespace mydbg::app
