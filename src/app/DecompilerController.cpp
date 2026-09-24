#include "app/DecompilerController.h"
#include "app/AppActions.h"
#include "app/AppState.h"
#include "app/DebuggerController.h"
#include "app/DisassemblyText.h"
#include "localization/Localization.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <limits>
#include <utility>

namespace mydbg::app {

bool decompiler_target_renamable(const DecompilerTarget &target) {
  return target.kind == debugger::DecompilerSymbolKind::Local ||
         target.kind == debugger::DecompilerSymbolKind::Parameter ||
         target.kind == debugger::DecompilerSymbolKind::Function ||
         target.kind == debugger::DecompilerSymbolKind::Global;
}

bool decompiler_target_typable(const DecompilerTarget &target) {
  return target.kind == debugger::DecompilerSymbolKind::Local ||
         target.kind == debugger::DecompilerSymbolKind::Parameter ||
         target.kind == debugger::DecompilerSymbolKind::Global ||
         target.kind == debugger::DecompilerSymbolKind::Constant;
}

DecompilerTarget
decompiler_target_from_span(const debugger::DecompiledLine &line,
                            const debugger::DecompilerSpan &span) {
  DecompilerTarget target;
  target.kind = span.symbol_kind;
  target.name = span.symbol_name;
  target.text = line.text.substr(span.start, span.length);
  target.reference_file_address = span.reference_file_address;
  target.has_reference_file_address = span.has_reference_file_address;
  target.cursor_file_address = span.file_address;
  target.has_cursor_file_address = span.has_file_address;
  if (target.name.empty()) {
    target.name = target.text;
  }
  return target;
}

std::optional<std::pair<std::string_view, std::uint64_t>>
address_token_at(std::string_view text, std::size_t character_index) {
  if (text.empty()) {
    return std::nullopt;
  }
  character_index = std::min(character_index, text.size() - 1);
  auto is_address_character = [](char character) {
    const auto value = static_cast<unsigned char>(character);
    return std::isalnum(value) != 0 || character == '_' || value >= 0x80;
  };
  if (!is_address_character(text[character_index])) {
    return std::nullopt;
  }
  std::size_t begin = character_index;
  while (begin > 0 && is_address_character(text[begin - 1])) {
    --begin;
  }
  std::size_t end = character_index + 1;
  while (end < text.size() && is_address_character(text[end])) {
    ++end;
  }
  const std::string_view token = text.substr(begin, end - begin);
  if ((begin > 0 && (text[begin - 1] == '-' || text[begin - 1] == '.')) ||
      (end < text.size() && text[end] == '.')) {
    return std::nullopt;
  }
  if (token.empty() ||
      !std::isdigit(static_cast<unsigned char>(token.front()))) {
    return std::nullopt;
  }
  auto digits = token;
  while (!digits.empty() && (digits.back() == 'u' || digits.back() == 'U' ||
                             digits.back() == 'l' || digits.back() == 'L')) {
    digits.remove_suffix(1);
  }
  const auto value = parse_value(digits);
  if (!value) {
    return std::nullopt;
  }
  return std::pair{token, *value};
}

static std::optional<std::uint64_t>
decompiler_label_address(std::string_view text,
                         const debugger::DecompilerSnapshot &decompiled) {
  text = trim_view(text);
  if (!text.starts_with("code_") || text.size() <= 7 ||
      !text.substr(6).starts_with("0x") || !text.ends_with(':')) {
    return std::nullopt;
  }
  text.remove_suffix(1);
  const auto address = parse_value(text.substr(6));
  return address && *address >= decompiled.function_min_file_address &&
                 *address <= decompiled.function_max_file_address
             ? address
             : std::nullopt;
}

bool decompiler_name_character(char c) {
  const auto value = static_cast<unsigned char>(c);
  return std::isalnum(value) || c == '_' || c == '.' || c == ':' ||
         value >= 0x80;
}

std::size_t decompiler_word_end(std::string_view text, std::size_t offset) {
  auto end_offset = offset;
  while (end_offset < text.size() &&
         decompiler_name_character(text[end_offset])) {
    ++end_offset;
  }
  return end_offset;
}

std::optional<std::uint64_t>
decompiler_navigation_address(const debugger::SessionSnapshot &snapshot,
                              const debugger::DecompilerSnapshot &decompiled,
                              const debugger::DecompiledLine &line,
                              const debugger::DecompilerSpan &span,
                              std::size_t character_index) {
  if (decompiled.loading ||
      span.kind == debugger::DecompilerTokenKind::Comment ||
      decompiled.generation != snapshot.generation) {
    return std::nullopt;
  }
  const auto from_file = [&](std::uint64_t address) {
    return load_address_for_file(snapshot, decompiled.executable_path, address);
  };
  std::size_t begin = character_index;
  if (character_index >= line.text.size() ||
      !decompiler_name_character(line.text[character_index])) {
    return std::nullopt;
  }
  while (begin > 0 && decompiler_name_character(line.text[begin - 1])) {
    --begin;
  }
  std::size_t end = character_index;
  while (end < line.text.size() && decompiler_name_character(line.text[end])) {
    ++end;
  }
  const auto word = std::string_view{line.text}.substr(begin, end - begin);
  auto after = trim_view(std::string_view{line.text}.substr(end));
  while (after.starts_with(')')) {
    after = trim_view(after.substr(1));
  }
  // A runtime indirect callee is usable only if the snapshot actually resolved
  // that instruction. Argument variables and unrelated registers aren't links.
  if (!word.empty() && after.starts_with('(') && span.has_file_address) {
    const auto cursor = from_file(span.file_address);
    const auto target_in =
        [&](const auto &instructions) -> std::optional<std::uint64_t> {
      for (const auto &instruction : instructions) {
        if (cursor == instruction.address &&
            instruction.flow_kind == debugger::InstructionFlowKind::Call &&
            instruction.flow_target &&
            navigable_address(snapshot, *instruction.flow_target)) {
          return instruction.flow_target;
        }
      }
      return std::nullopt;
    };
    if (auto target = target_in(snapshot.instructions)) {
      return target;
    }
    if (snapshot.disassembly_graph) {
      for (const auto &block : snapshot.disassembly_graph->blocks) {
        if (auto target = target_in(block.instructions)) {
          return target;
        }
      }
    }
  }
  if (span.has_reference_file_address && span.reference_file_address != 0) {
    if (auto target = from_file(span.reference_file_address)) {
      return target;
    }
  }
  // Resolve declared labels. Ghidra's generated code_<space><address> labels
  // identify the block entry; the next statement's offset can be later.
  const auto jump = line.text.find("goto ");
  if (jump != std::string::npos &&
      (jump == 0 || !decompiler_name_character(line.text[jump - 1]))) {
    auto label = trim_view(std::string_view{line.text}.substr(jump + 5));
    std::size_t length = 0;
    while (length < label.size() && decompiler_name_character(label[length])) {
      ++length;
    }
    label = label.substr(0, length);
    if (!label.empty() && (word == "goto" || word == label)) {
      bool found = false;
      for (const auto &candidate : decompiled.lines) {
        const auto text = trim_view(candidate.text);
        if (!found && text.starts_with(label) &&
            trim_view(text.substr(label.size())).starts_with(':')) {
          found = true;
          if (const auto address =
                  decompiler_label_address(candidate.text, decompiled)) {
            if (auto target = from_file(*address)) {
              return target;
            }
          }
        }
        if (found && !candidate.file_addresses.empty()) {
          return from_file(candidate.file_addresses.front());
        }
      }
    }
  }
  if (const auto token = address_token_at(line.text, character_index)) {
    if (navigable_address(snapshot, token->second)) {
      return token->second;
    }
  }
  return std::nullopt;
}

std::optional<DecompilerNavigationLink>
decompiler_keyboard_target(const debugger::SessionSnapshot &snapshot,
                           const debugger::DecompilerSnapshot &decompiled,
                           const debugger::DecompiledLine &line,
                           std::optional<std::size_t> character,
                           int direction) {
  std::optional<DecompilerNavigationLink> first, last, before, after, current;
  for (const auto &span : line.spans) {
    const auto end = std::min(line.text.size(), span.start + span.length);
    for (std::size_t offset = span.start; offset < end; ++offset) {
      if (!decompiler_name_character(line.text[offset]) ||
          (offset > span.start &&
           decompiler_name_character(line.text[offset - 1]))) {
        continue;
      }
      const auto address = decompiler_navigation_address(snapshot, decompiled,
                                                         line, span, offset);
      if (!address || !navigable_address(snapshot, *address) ||
          (last && last->address == *address)) {
        continue;
      }
      const DecompilerNavigationLink link{offset, &span, *address};
      if (!first)
        first = link;
      last = link;
      if (character) {
        if (offset < *character)
          before = link;
        if (offset == *character)
          current = link;
        if (offset > *character && !after)
          after = link;
      }
    }
  }
  if (direction < 0)
    return before ? before : last;
  if (direction > 0)
    return after ? after : first;
  return current ? current : first;
}

std::string
selected_decompiler_text(const std::vector<debugger::DecompiledLine> &lines,
                         std::size_t start, std::size_t end) {
  std::string text;
  for (std::size_t index = start; index <= end && index < lines.size();
       ++index) {
    if (!text.empty()) {
      text.push_back('\n');
    }
    text += lines[index].text;
  }
  return text;
}

debugger::DecompilerRequest
decompiler_context_from_snapshot(const debugger::DecompilerSnapshot &snapshot) {
  return debugger::DecompilerRequest{
      .executable_path = snapshot.executable_path,
      .module_id = snapshot.module_id,
      .file_address = snapshot.requested_file_address,
      .load_address = snapshot.requested_load_address,
      .generation = snapshot.generation,
      .debug_info_path = snapshot.debug_info_path,
      .session = snapshot.session,
      .analysis_revision = snapshot.analysis_revision,
  };
}

void open_decompiler_dialog(UiState &ui, DecompilerDialog dialog,
                            const DecompilerTarget &target,
                            std::string_view initial) {
  ui.decompiler_target = target;
  ui.decompiler_dialog = dialog;
  ui.decompiler_message.clear();
  if (dialog == DecompilerDialog::Rename) {
    std::snprintf(ui.decompiler_name_text.data(),
                  ui.decompiler_name_text.size(), "%.*s",
                  static_cast<int>(initial.size()), initial.data());
  } else {
    std::snprintf(ui.decompiler_type_text.data(),
                  ui.decompiler_type_text.size(), "%.*s",
                  static_cast<int>(initial.size()), initial.data());
  }
}

void set_decompiler_type(debugger::DecompilerEngine &engine, UiState &ui,
                         const debugger::DecompilerSnapshot &decompiled,
                         const DecompilerTarget &target,
                         std::string_view type) {
  const std::string type_text{trim_view(type)};
  if (type_text.empty()) {
    ui.decompiler_message = l10n::text(l10n::Key::GuiPanelsTypeRequired);
    return;
  }
  engine.edit(debugger::DecompilerEditRequest{
      .context = decompiler_context_from_snapshot(decompiled),
      .kind = debugger::DecompilerEditKind::SetType,
      .target_kind = target.kind,
      .target_name = target.name,
      .target_file_address = target.reference_file_address,
      .has_target_file_address = target.has_reference_file_address,
      .value = type_text,
  });
}

void mark_decompiler_string(debugger::DecompilerEngine &decompiler, UiState &ui,
                            debugger::LldbEngine &engine,
                            const debugger::SessionSnapshot &snapshot,
                            const debugger::DecompilerSnapshot &decompiled,
                            const DecompilerTarget &target) {
  if (!target.has_reference_file_address) {
    ui.decompiler_message =
        l10n::text(l10n::Key::GuiPanelsTokenAddressUnavailable);
    return;
  }
  decompiler.edit(debugger::DecompilerEditRequest{
      .context = decompiler_context_from_snapshot(decompiled),
      .kind = debugger::DecompilerEditKind::MarkString,
      .target_kind = target.kind,
      .target_name = target.name,
      .target_file_address = target.reference_file_address,
      .has_target_file_address = true,
      .value = {},
  });
  if (const auto load_address =
          load_address_for_file(snapshot, decompiled.executable_path,
                                target.reference_file_address)) {
    follow_memory(engine, ui, *load_address);
  }
}

bool decompiler_apply_edit(debugger::DecompilerEngine &decompiler, UiState &ui,
                           const debugger::DecompilerSnapshot &decompiled,
                           const DecompilerTarget &target, bool rename,
                           const char *text) {
  bool applied = false;
  if (rename) {
    const std::string new_name{trim_view(text)};
    if (new_name.empty()) {
      ui.decompiler_message = l10n::text(l10n::Key::GuiPanelsNameRequired);
    } else {
      decompiler.edit(debugger::DecompilerEditRequest{
          .context = decompiler_context_from_snapshot(decompiled),
          .kind = debugger::DecompilerEditKind::Rename,
          .target_kind = target.kind,
          .target_name = target.name,
          .target_file_address = target.reference_file_address,
          .has_target_file_address = target.has_reference_file_address,
          .value = new_name,
      });
      applied = true;
    }
  } else {
    set_decompiler_type(decompiler, ui, decompiled, target, text);
    applied = ui.decompiler_message.empty();
  }
  return applied;
}

void decompiler_sync_request(UiState &ui,
                             const debugger::DecompilerSnapshot &decompiled) {
  if (ui.decompiler_target_serial != decompiled.request_serial) {
    ui.decompiler_target_serial = decompiled.request_serial;
    ui.decompiler_target.reset();
    ui.decompiler_context_target.reset();
    ui.decompiler_context_load_address.reset();
    ui.decompiler_dialog = DecompilerDialog::None;
  }
}

bool decompiler_content_ready(const debugger::SessionSnapshot &snapshot,
                              const debugger::DecompilerSnapshot &decompiled,
                              const UiState &ui, bool control_lease) {
  return !decompiled.loading && decompiled.error.empty() &&
         decompiled.generation == snapshot.generation &&
         decompiled.session == snapshot.session &&
         decompiled.analysis_revision == snapshot.session_analysis_revision &&
         !ui.session_clear.valid() && !control_lease &&
         snapshot.state == debugger::SessionState::Stopped;
}

std::optional<std::size_t>
decompiler_closest_line(const debugger::DecompilerSnapshot &decompiled,
                        std::optional<std::uint64_t> address) {
  if (!address) {
    return std::nullopt;
  }
  std::optional<std::size_t> best_index;
  std::uint64_t best_distance = std::numeric_limits<std::uint64_t>::max();
  bool best_is_comment = true;
  for (std::size_t line_index = 0; line_index < decompiled.lines.size();
       ++line_index) {
    const debugger::DecompiledLine &candidate_line =
        decompiled.lines[line_index];
    if (decompiler_label_address(candidate_line.text, decompiled) == address) {
      return line_index;
    }
    const std::size_t first_text = candidate_line.text.find_first_not_of(" \t");
    const bool is_comment =
        first_text == std::string::npos ||
        candidate_line.text.compare(first_text, 2, "//") == 0;
    for (const std::uint64_t candidate : candidate_line.file_addresses) {
      const std::uint64_t distance =
          candidate > *address ? candidate - *address : *address - candidate;
      if (distance < best_distance ||
          (distance == best_distance && best_is_comment && !is_comment)) {
        best_index = line_index;
        best_distance = distance;
        best_is_comment = is_comment;
      }
    }
  }
  return best_index;
}

void decompiler_sync_selection(const debugger::SessionSnapshot &snapshot,
                               const debugger::DecompilerSnapshot &decompiled,
                               UiState &ui,
                               std::optional<std::size_t> selected_line) {
  if (ui.decompiler_keyboard_function != decompiled.function_file_address ||
      ui.decompiler_keyboard_cursor != ui.disassembly_cursor ||
      (ui.decompiler_keyboard_line &&
       *ui.decompiler_keyboard_line >= decompiled.lines.size())) {
    ui.decompiler_keyboard_function = decompiled.function_file_address;
    ui.decompiler_keyboard_line.reset();
    ui.decompiler_keyboard_span.reset();
  }
  ui.decompiler_keyboard_cursor = ui.disassembly_cursor;
  if (ui.navigation_source_restore) {
    const auto &location = *ui.navigation_source_restore;
    const auto *module = module_for_address(snapshot, ui.disassembly_cursor);
    if (location.address != ui.disassembly_cursor) {
      ui.navigation_source_restore.reset();
    } else if (!decompiled.loading &&
               decompiled.generation == snapshot.generation &&
               location.decompiler_function ==
                   decompiled.function_file_address &&
               module != nullptr &&
               module->path == decompiled.executable_path) {
      if (location.decompiler_line &&
          *location.decompiler_line < decompiled.lines.size()) {
        ui.decompiler_keyboard_line = location.decompiler_line;
        ui.decompiler_keyboard_span = location.decompiler_span;
      }
      ui.navigation_source_restore.reset();
    }
  }
  if (!ui.decompiler_keyboard_line && !decompiled.lines.empty()) {
    ui.decompiler_keyboard_line = selected_line.value_or(0);
  }
}

std::optional<std::size_t> decompiler_program_counter_line(
    const debugger::SessionSnapshot &snapshot,
    const debugger::DecompilerSnapshot &decompiled) {
  return decompiler_closest_line(
      decompiled,
      snapshot.pc_module_path == decompiled.executable_path &&
              snapshot.has_pc_file_address &&
              snapshot.pc_file_address >=
                  decompiled.function_min_file_address &&
              snapshot.pc_file_address <= decompiled.function_max_file_address
          ? std::optional<std::uint64_t>{snapshot.pc_file_address}
          : std::nullopt);
}

void decompiler_navigate_file(const debugger::SessionSnapshot &snapshot,
                              const debugger::DecompilerSnapshot &decompiled,
                              debugger::LldbEngine &engine, UiState &ui,
                              std::uint64_t file_address) {
  const auto load_address =
      load_address_for_file(snapshot, decompiled.executable_path, file_address);
  if (!load_address) {
    return;
  }
  follow_disassembly(engine, ui, *load_address);
}

void decompiler_select_source(const debugger::SessionSnapshot &snapshot,
                              const debugger::DecompilerSnapshot &decompiled,
                              UiState &ui, const debugger::DecompiledLine &line,
                              std::optional<std::uint64_t> file_address) {
  if (!file_address && !line.file_addresses.empty()) {
    file_address = line.file_addresses.front();
  }
  if (!file_address) {
    file_address = decompiler_label_address(line.text, decompiled);
  }
  if (file_address) {
    if (const auto address = load_address_for_file(
            snapshot, decompiled.executable_path, *file_address)) {
      ui.disassembly_cursor = *address;
      ui.decompiler_keyboard_cursor = *address;
    }
  }
}

void decompiler_move_line(const debugger::SessionSnapshot &snapshot,
                          const debugger::DecompilerSnapshot &decompiled,
                          UiState &ui, bool up, bool down) {
  auto &index = *ui.decompiler_keyboard_line;
  if (up && index > 0)
    --index;
  if (down && index + 1 < decompiled.lines.size())
    ++index;
  ui.decompiler_keyboard_span.reset();
  decompiler_select_source(snapshot, decompiled, ui, decompiled.lines[index],
                           std::nullopt);
}

std::optional<DecompilerNavigationLink> decompiler_update_keyboard_target(
    const debugger::SessionSnapshot &snapshot,
    const debugger::DecompilerSnapshot &decompiled, UiState &ui,
    int direction) {
  const auto index = *ui.decompiler_keyboard_line;
  const auto keyboard_target =
      decompiler_keyboard_target(snapshot, decompiled, decompiled.lines[index],
                                 ui.decompiler_keyboard_span, direction);
  ui.decompiler_keyboard_span = keyboard_target
                                    ? std::optional{keyboard_target->character}
                                    : std::nullopt;
  if (direction != 0 && keyboard_target) {
    decompiler_select_source(
        snapshot, decompiled, ui, decompiled.lines[index],
        keyboard_target->span->has_file_address
            ? std::optional{keyboard_target->span->file_address}
            : std::nullopt);
  }
  return keyboard_target;
}

void decompiler_resolve_hover(const debugger::SessionSnapshot &snapshot,
                              const debugger::DecompilerSnapshot &decompiled,
                              UiState &ui, const debugger::DecompiledLine &line,
                              const debugger::DecompilerSpan &span,
                              std::size_t character_index,
                              DecompilerHover &hovered) {
  if (span.has_file_address) {
    hovered.file_address = span.file_address;
  }
  if (span.symbol_kind != debugger::DecompilerSymbolKind::None) {
    hovered.target = decompiler_target_from_span(line, span);
    ui.decompiler_target = hovered.target;
  } else if (const auto token = address_token_at(line.text, character_index)) {
    hovered.literal_address = token->second;
    DecompilerTarget target;
    target.kind = debugger::DecompilerSymbolKind::Constant;
    target.name = std::string{token->first};
    target.text = std::string{token->first};
    if (const auto *module = module_for_address(snapshot, token->second);
        module != nullptr && module->has_load_bias &&
        module->path == decompiled.executable_path &&
        token->second >= module->load_bias &&
        navigable_address(snapshot, token->second)) {
      target.reference_file_address = token->second - module->load_bias;
      target.has_reference_file_address = true;
    }
    target.cursor_file_address = span.file_address;
    target.has_cursor_file_address = span.has_file_address;
    hovered.target = std::move(target);
    ui.decompiler_target = hovered.target;
  }
  hovered.navigation_address = decompiler_navigation_address(
      snapshot, decompiled, line, span, character_index);
}

void decompiler_update_context(const debugger::SessionSnapshot &snapshot,
                               const debugger::DecompilerSnapshot &decompiled,
                               UiState &ui,
                               const debugger::DecompiledLine &line,
                               const DecompilerHover &hovered) {
  ui.decompiler_context_target = hovered.target;
  if (hovered.navigation_address) {
    ui.decompiler_context_load_address = hovered.navigation_address;
  } else if (hovered.literal_address &&
             navigable_address(snapshot, *hovered.literal_address)) {
    ui.decompiler_context_load_address = hovered.literal_address;
  } else if (hovered.file_address) {
    ui.decompiler_context_load_address = load_address_for_file(
        snapshot, decompiled.executable_path, *hovered.file_address);
  } else if (!line.file_addresses.empty()) {
    ui.decompiler_context_load_address = load_address_for_file(
        snapshot, decompiled.executable_path, line.file_addresses.front());
  } else {
    ui.decompiler_context_load_address.reset();
  }
}

void decompiler_request_comment(const debugger::SessionSnapshot &snapshot,
                                const debugger::DecompilerSnapshot &decompiled,
                                UiState &ui, std::uint64_t load_address) {
  std::string_view text;
  for (const auto &comment : decompiled.comments) {
    if (load_address_for_file(snapshot, decompiled.executable_path,
                              comment.address.file_address) == load_address) {
      text = comment.text;
      break;
    }
  }
  debugger_request_comment_editor(snapshot, ui, load_address, text);
}

void decompiler_clear_selection(UiState &ui) {
  ui.decompiler_selection_anchor.reset();
  ui.decompiler_selection_start.reset();
  ui.decompiler_selection_end.reset();
}

void decompiler_begin_selection(const debugger::SessionSnapshot &snapshot,
                                const debugger::DecompilerSnapshot &decompiled,
                                UiState &ui,
                                const debugger::DecompiledLine &line,
                                std::size_t index,
                                std::optional<std::uint64_t> file_address) {
  ui.decompiler_keyboard_line = index;
  ui.decompiler_keyboard_span.reset();
  decompiler_select_source(snapshot, decompiled, ui, line, file_address);
  ui.decompiler_selection_anchor = index;
  ui.decompiler_selection_start = index;
  ui.decompiler_selection_end = index;
}

void decompiler_extend_selection(UiState &ui, std::size_t index) {
  ui.decompiler_selection_start =
      std::min(*ui.decompiler_selection_anchor, index);
  ui.decompiler_selection_end =
      std::max(*ui.decompiler_selection_anchor, index);
}

} // namespace mydbg::app
