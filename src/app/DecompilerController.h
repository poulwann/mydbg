#pragma once

#include "backend/decompiler/DecompilerEngine.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace debugger {
class LldbEngine;
struct SessionSnapshot;
} // namespace debugger

namespace mydbg::app {

struct UiState;

enum class DecompilerDialog {
  None,
  Rename,
  SetType,
};

struct DecompilerTarget {
  debugger::DecompilerSymbolKind kind{debugger::DecompilerSymbolKind::None};
  std::string name;
  std::string text;
  std::uint64_t reference_file_address{};
  bool has_reference_file_address{};
  std::uint64_t cursor_file_address{};
  bool has_cursor_file_address{};
};

struct DecompilerNavigationLink {
  std::size_t character{};
  const debugger::DecompilerSpan *span{};
  std::uint64_t address{};
};

struct DecompilerHover {
  std::optional<DecompilerTarget> target;
  std::optional<std::uint64_t> file_address;
  std::optional<std::uint64_t> literal_address;
  std::optional<std::uint64_t> navigation_address;
};

bool decompiler_target_renamable(const DecompilerTarget &target);

bool decompiler_target_typable(const DecompilerTarget &target);

bool decompiler_name_character(char c);

std::size_t decompiler_word_end(std::string_view text, std::size_t offset);

std::optional<std::uint64_t>
decompiler_navigation_address(const debugger::SessionSnapshot &snapshot,
                              const debugger::DecompilerSnapshot &decompiled,
                              const debugger::DecompiledLine &line,
                              const debugger::DecompilerSpan &span,
                              std::size_t character_index);

std::string
selected_decompiler_text(const std::vector<debugger::DecompiledLine> &lines,
                         std::size_t start, std::size_t end);

void open_decompiler_dialog(UiState &ui, DecompilerDialog dialog,
                            const DecompilerTarget &target,
                            std::string_view initial);

void set_decompiler_type(debugger::DecompilerEngine &engine, UiState &ui,
                         const debugger::DecompilerSnapshot &decompiled,
                         const DecompilerTarget &target, std::string_view type);

void mark_decompiler_string(debugger::DecompilerEngine &decompiler, UiState &ui,
                            debugger::LldbEngine &engine,
                            const debugger::SessionSnapshot &snapshot,
                            const debugger::DecompilerSnapshot &decompiled,
                            const DecompilerTarget &target);

bool decompiler_apply_edit(debugger::DecompilerEngine &decompiler, UiState &ui,
                           const debugger::DecompilerSnapshot &decompiled,
                           const DecompilerTarget &target, bool rename,
                           const char *text);

void decompiler_sync_request(UiState &ui,
                             const debugger::DecompilerSnapshot &decompiled);

bool decompiler_content_ready(const debugger::SessionSnapshot &snapshot,
                              const debugger::DecompilerSnapshot &decompiled,
                              const UiState &ui, bool control_lease);

std::optional<std::size_t>
decompiler_closest_line(const debugger::DecompilerSnapshot &decompiled,
                        std::optional<std::uint64_t> address);

void decompiler_sync_selection(const debugger::SessionSnapshot &snapshot,
                               const debugger::DecompilerSnapshot &decompiled,
                               UiState &ui,
                               std::optional<std::size_t> selected_line);

std::optional<std::size_t>
decompiler_program_counter_line(const debugger::SessionSnapshot &snapshot,
                                const debugger::DecompilerSnapshot &decompiled);

void decompiler_navigate_file(const debugger::SessionSnapshot &snapshot,
                              const debugger::DecompilerSnapshot &decompiled,
                              debugger::LldbEngine &engine, UiState &ui,
                              std::uint64_t file_address);

void decompiler_select_source(const debugger::SessionSnapshot &snapshot,
                              const debugger::DecompilerSnapshot &decompiled,
                              UiState &ui, const debugger::DecompiledLine &line,
                              std::optional<std::uint64_t> file_address);

void decompiler_move_line(const debugger::SessionSnapshot &snapshot,
                          const debugger::DecompilerSnapshot &decompiled,
                          UiState &ui, bool up, bool down);

std::optional<DecompilerNavigationLink> decompiler_update_keyboard_target(
    const debugger::SessionSnapshot &snapshot,
    const debugger::DecompilerSnapshot &decompiled, UiState &ui, int direction);

void decompiler_resolve_hover(const debugger::SessionSnapshot &snapshot,
                              const debugger::DecompilerSnapshot &decompiled,
                              UiState &ui, const debugger::DecompiledLine &line,
                              const debugger::DecompilerSpan &span,
                              std::size_t character_index,
                              DecompilerHover &hovered);

void decompiler_update_context(const debugger::SessionSnapshot &snapshot,
                               const debugger::DecompilerSnapshot &decompiled,
                               UiState &ui,
                               const debugger::DecompiledLine &line,
                               const DecompilerHover &hovered);

void decompiler_request_comment(const debugger::SessionSnapshot &snapshot,
                                const debugger::DecompilerSnapshot &decompiled,
                                UiState &ui, std::uint64_t load_address);

void decompiler_clear_selection(UiState &ui);

void decompiler_begin_selection(const debugger::SessionSnapshot &snapshot,
                                const debugger::DecompilerSnapshot &decompiled,
                                UiState &ui,
                                const debugger::DecompiledLine &line,
                                std::size_t index,
                                std::optional<std::uint64_t> file_address);

void decompiler_extend_selection(UiState &ui, std::size_t index);

} // namespace mydbg::app
