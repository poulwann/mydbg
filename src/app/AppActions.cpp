#include "app/AppActions.h"
#include "app/AppState.h"
#include "app/DisassemblyText.h"
#include "plugins/PluginApi.h"

#include <algorithm>
#include <charconv>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <limits>

namespace mydbg::app {

std::string bytes_as_hex(const std::vector<std::uint8_t> &bytes) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string text;
  text.reserve(bytes.size() * 3);
  for (const std::uint8_t byte : bytes) {
    if (!text.empty()) {
      text.push_back(' ');
    }
    text.push_back(digits[byte >> 4U]);
    text.push_back(digits[byte & 0x0fU]);
  }
  return text;
}

std::optional<std::vector<std::uint8_t>>
parse_hex_byte_text(std::string_view text) {
  std::vector<std::uint8_t> bytes;
  while (!text.empty()) {
    const std::size_t start = text.find_first_not_of(" \t\r\n,");
    if (start == std::string_view::npos) {
      break;
    }
    text.remove_prefix(start);
    const std::size_t end = text.find_first_of(" \t\r\n,");
    std::string_view token = text.substr(0, end);
    if (token.starts_with("0x") || token.starts_with("0X")) {
      token.remove_prefix(2);
    }
    if (token.empty() || token.size() % 2 != 0) {
      return std::nullopt;
    }
    for (std::size_t index = 0; index < token.size(); index += 2) {
      unsigned int value{};
      const auto parsed = std::from_chars(token.data() + index,
                                          token.data() + index + 2, value, 16);
      if (parsed.ec != std::errc{} || parsed.ptr != token.data() + index + 2) {
        return std::nullopt;
      }
      bytes.push_back(static_cast<std::uint8_t>(value));
    }
    if (end == std::string_view::npos) {
      break;
    }
    text.remove_prefix(end);
  }
  return bytes.empty()
             ? std::nullopt
             : std::optional<std::vector<std::uint8_t>>{std::move(bytes)};
}

std::optional<std::uint64_t> parse_value(std::string_view text) {
  while (!text.empty() && text.front() == ' ') {
    text.remove_prefix(1);
  }
  int base = 10;
  if (text.starts_with("0x") || text.starts_with("0X")) {
    text.remove_prefix(2);
    base = 16;
  }
  std::uint64_t value = 0;
  const auto [end, error] =
      std::from_chars(text.data(), text.data() + text.size(), value, base);
  if (error != std::errc{} || end != text.data() + text.size()) {
    return std::nullopt;
  }
  return value;
}

void load_plugins(debugger::plugins::PluginLoader &loader) {
  loader.load_directory("plugins");
  if (const char *configured = std::getenv("MYDBG_PLUGIN_PATH")) {
    std::string_view paths{configured};
    while (!paths.empty()) {
      const std::size_t separator = paths.find(':');
      const std::string_view path = paths.substr(0, separator);
      if (!path.empty()) {
        loader.load_directory(std::filesystem::path{path});
      }
      if (separator == std::string_view::npos) {
        break;
      }
      paths.remove_prefix(separator + 1);
    }
  }
  if (const char *xdg = std::getenv("XDG_CONFIG_HOME")) {
    loader.load_directory(std::filesystem::path{xdg} / "mydbg" / "plugins");
  } else if (const char *home = std::getenv("HOME")) {
    loader.load_directory(std::filesystem::path{home} / ".config" / "mydbg" /
                          "plugins");
  }
  for (const std::string &error : loader.errors()) {
    std::fprintf(stderr, l10n::text(l10n::Key::GuiSupportPluginError),
                 error.c_str());
  }
}

std::optional<std::uint64_t>
pointer_at(const debugger::SessionSnapshot &snapshot, std::size_t offset) {
  const std::size_t width = snapshot.address_byte_size;
  if (width == 0 || width > sizeof(std::uint64_t) ||
      offset + width > snapshot.memory.size()) {
    return std::nullopt;
  }

  std::uint64_t value = 0;
  if (snapshot.byte_order == "big") {
    for (std::size_t index = 0; index < width; ++index) {
      value = (value << 8U) | snapshot.memory[offset + index];
    }
  } else {
    for (std::size_t index = 0; index < width; ++index) {
      value |= static_cast<std::uint64_t>(snapshot.memory[offset + index])
               << (index * 8U);
    }
  }
  return value;
}

void follow_memory(debugger::LldbEngine &engine, UiState &ui,
                   std::uint64_t address) {
  std::snprintf(ui.memory_address.data(), ui.memory_address.size(),
                "0x%" PRIx64, address);
  engine.read_memory(address);
}
static NavigationLocation current_navigation_location(const UiState &ui) {
  if (ui.navigation_source_restore &&
      ui.navigation_source_restore->address == ui.disassembly_cursor) {
    return *ui.navigation_source_restore;
  }
  NavigationLocation location{.address = ui.disassembly_cursor};
  if (ui.decompiler_keyboard_cursor == ui.disassembly_cursor) {
    location.decompiler_function = ui.decompiler_keyboard_function;
    location.decompiler_line = ui.decompiler_keyboard_line;
    location.decompiler_span = ui.decompiler_keyboard_span;
  }
  return location;
}

static void apply_disassembly_navigation(debugger::LldbEngine &engine,
                                         UiState &ui, std::uint64_t address) {
  ui.disassembly_cursor = address;
  ui.disassembly_scroll_target = address;
  ui.navigation_source_restore.reset();
  ui.decompiler_scroll_selection = std::numeric_limits<std::uint64_t>::max();
  ui.decompiler_keyboard_line.reset();
  ui.decompiler_keyboard_span.reset();
  ui.decompiler_keyboard_cursor = address;
  engine.read_instructions(address);
}

void reset_navigation_history(UiState &ui) {
  ui.navigation_history_size = 0;
  ui.navigation_history_index = 0;
  ui.navigation_source_restore.reset();
  ui.navigation_follow_requested = false;
  ui.navigation_dispatch_frame = -1;
  ui.navigation_dialog_requested = false;
  ui.navigation_dialog_open = false;
  ui.navigation_address_error.clear();
  ui.decompiler_keyboard_line.reset();
  ui.decompiler_keyboard_span.reset();
  ui.decompiler_keyboard_function.reset();
  ui.decompiler_keyboard_cursor = 0;
}

void follow_disassembly(debugger::LldbEngine &engine, UiState &ui,
                        std::uint64_t address) {
  if (address != ui.disassembly_cursor) {
    if (ui.navigation_history_size != 0) {
      // Selection moves are not jumps, but the row actually left is the
      // location to restore, rather than the original entry into this view.
      ui.navigation_history[ui.navigation_history_index] =
          current_navigation_location(ui);
      ui.navigation_history_size = ui.navigation_history_index + 1;
    } else if (ui.disassembly_cursor != 0) {
      ui.navigation_history[ui.navigation_history_size++] =
          current_navigation_location(ui);
    }
    if (ui.navigation_history_size == ui.navigation_history.size()) {
      std::move(ui.navigation_history.begin() + 1, ui.navigation_history.end(),
                ui.navigation_history.begin());
      --ui.navigation_history_size;
    }
    ui.navigation_history[ui.navigation_history_size++] = {.address = address};
    ui.navigation_history_index = ui.navigation_history_size - 1;
  }
  apply_disassembly_navigation(engine, ui, address);
}

void app_traverse_navigation_history(const debugger::SessionSnapshot &snapshot,
                                     debugger::LldbEngine &engine, UiState &ui,
                                     bool forward) {
  if (snapshot.state != debugger::SessionState::Stopped ||
      ui.navigation_history_size == 0) {
    return;
  }
  ui.navigation_history[ui.navigation_history_index] =
      current_navigation_location(ui);
  std::size_t candidate = ui.navigation_history_index;
  while (forward ? candidate + 1 < ui.navigation_history_size : candidate > 0) {
    candidate = forward ? candidate + 1 : candidate - 1;
    const auto &location = ui.navigation_history[candidate];
    const std::uint64_t address = location.address;
    if (address == ui.disassembly_cursor ||
        !std::any_of(snapshot.memory_regions.begin(),
                     snapshot.memory_regions.end(),
                     [address](const auto &region) {
                       return region.executable && address >= region.start &&
                              address < region.end;
                     })) {
      continue;
    }
    ui.navigation_history_index = candidate;
    apply_disassembly_navigation(engine, ui, address);
    if (location.decompiler_function && location.decompiler_line) {
      ui.navigation_source_restore = location;
    }
    return;
  }
}

AppNavigationTarget
app_follow_address(const debugger::SessionSnapshot &snapshot,
                   debugger::LldbEngine &engine, UiState &ui,
                   std::uint64_t address) {
  if (!navigable_address(snapshot, address)) {
    return AppNavigationTarget::None;
  }
  const auto region =
      std::find_if(snapshot.memory_regions.begin(),
                   snapshot.memory_regions.end(), [address](const auto &entry) {
                     return address >= entry.start && address < entry.end;
                   });
  if (region->executable) {
    follow_disassembly(engine, ui, address);
    return AppNavigationTarget::Disassembly;
  } else {
    follow_memory(engine, ui, address);
    return AppNavigationTarget::Memory;
  }
}

void app_request_navigation_dialog(const debugger::SessionSnapshot &snapshot,
                                   UiState &ui, bool decompiler_view) {
  ui.navigation_dialog_requested = true;
  ui.navigation_dialog_decompiler_view = decompiler_view;
  ui.navigation_dialog_generation = snapshot.generation;
  ui.navigation_address_error.clear();
  std::snprintf(ui.navigation_address.data(), ui.navigation_address.size(),
                "0x%" PRIx64, ui.disassembly_cursor);
}

void app_toggle_navigation_graph(UiState &ui) {
  ui.disassembly_graph_view = !ui.disassembly_graph_view;
  if (!ui.disassembly_graph_view) {
    ui.disassembly_graph_state.reset();
  }
  ui.disassembly_scroll_target = ui.disassembly_cursor;
}

bool app_navigation_session_valid(const debugger::SessionSnapshot &snapshot,
                                  const UiState &ui) {
  return snapshot.state == debugger::SessionState::Stopped &&
         !ui.navigation_control_locked;
}

AppNavigationResult
app_submit_navigation_address(const debugger::SessionSnapshot &snapshot,
                              debugger::LldbEngine &engine, UiState &ui) {
  std::string_view input{ui.navigation_address.data()};
  if (input.starts_with("0x") || input.starts_with("0X")) {
    input.remove_prefix(2);
  }
  std::uint64_t address{};
  const auto [end, error] =
      std::from_chars(input.data(), input.data() + input.size(), address, 16);
  if (input.empty() || error != std::errc{} ||
      end != input.data() + input.size()) {
    ui.navigation_address_error =
        l10n::text(l10n::Key::GuiSupportNavigationInvalidAddress);
    return {};
  }
  const AppNavigationTarget target =
      app_follow_address(snapshot, engine, ui, address);
  if (target == AppNavigationTarget::None) {
    ui.navigation_address_error =
        l10n::text(l10n::Key::GuiSupportNavigationUnmappedAddress);
  }
  return {target, address};
}

bool app_navigation_address_is_code(const debugger::SessionSnapshot &snapshot,
                                    std::uint64_t address) {
  return std::any_of(snapshot.memory_regions.begin(),
                     snapshot.memory_regions.end(),
                     [address](const auto &region) {
                       return region.executable && address >= region.start &&
                              address < region.end;
                     });
}

void show_in_memory_map(UiState &ui, std::uint64_t address) {
  ui.show_memory_map = true;
  ui.memory_map_address = address;
  ui.scroll_memory_map_to_address = true;
}

std::string address_specification(std::uint64_t address) {
  char text[32]{};
  std::snprintf(text, sizeof(text), "0x%" PRIx64, address);
  return text;
}

const debugger::BreakpointInfo *
breakpoint_info_at(const debugger::SessionSnapshot &snapshot,
                   std::uint64_t address) {
  const auto found =
      std::find_if(snapshot.breakpoints.begin(), snapshot.breakpoints.end(),
                   [address](const debugger::BreakpointInfo &breakpoint) {
                     return std::find(breakpoint.addresses.begin(),
                                      breakpoint.addresses.end(),
                                      address) != breakpoint.addresses.end();
                   });
  return found == snapshot.breakpoints.end() ? nullptr : &*found;
}

void request_new_condition_editor(UiState &ui, std::uint64_t address) {
  ui.editing_breakpoint.reset();
  ui.creating_conditional_breakpoint = address;
  ui.breakpoint_condition.front() = '\0';
  ui.breakpoint_condition_error.clear();
  ui.condition_editor_requested = true;
}

void request_existing_condition_editor(
    UiState &ui, const debugger::BreakpointInfo &breakpoint) {
  ui.editing_breakpoint = breakpoint.id;
  ui.creating_conditional_breakpoint.reset();
  std::snprintf(ui.breakpoint_condition.data(), ui.breakpoint_condition.size(),
                "%s", breakpoint.script_condition.c_str());
  ui.breakpoint_condition_error.clear();
  ui.condition_editor_requested = true;
}

void close_condition_editor(UiState &ui) {
  ui.editing_breakpoint.reset();
  ui.creating_conditional_breakpoint.reset();
  ui.breakpoint_condition_error.clear();
}

void request_instruction_patch_editor(
    const debugger::SessionSnapshot &snapshot, UiState &ui,
    const debugger::InstructionRow &instruction, bool assemble) {
  ui.instruction_patch_address = instruction.address;
  ui.instruction_patch_generation = snapshot.generation;
  ui.instruction_patch_original = instruction.bytes;
  ui.instruction_patch_assemble = assemble;
  const std::string initial =
      assemble && snapshot.intel_syntax
          ? instruction.mnemonic + (instruction.operands.empty()
                                        ? std::string{}
                                        : " " + instruction.operands)
      : assemble ? std::string{}
                 : bytes_as_hex(instruction.bytes);
  std::snprintf(ui.instruction_patch_text.data(),
                ui.instruction_patch_text.size(), "%s", initial.c_str());
  ui.instruction_patch_error.clear();
  ui.instruction_patch_editor_requested = true;
}

void app_close_instruction_patch_editor(UiState &ui) {
  ui.instruction_patch_address.reset();
  ui.instruction_patch_original.clear();
  ui.instruction_patch_error.clear();
}

bool app_instruction_patch_session_valid(
    const debugger::SessionSnapshot &snapshot, const UiState &ui) {
  return ui.instruction_patch_address.has_value() &&
         ui.instruction_patch_generation == snapshot.generation &&
         snapshot.state == debugger::SessionState::Stopped;
}

bool app_apply_instruction_patch(debugger::LldbEngine &engine, UiState &ui) {
  const std::string_view input{ui.instruction_patch_text.data()};
  if (input.empty()) {
    ui.instruction_patch_error =
        ui.instruction_patch_assemble
            ? l10n::text(l10n::Key::GuiSupportEnterInstruction)
            : l10n::text(l10n::Key::GuiSupportEnterHexBytes);
  } else if (!ui.instruction_patch_assemble && !parse_hex_byte_text(input)) {
    ui.instruction_patch_error =
        l10n::text(l10n::Key::GuiSupportInvalidHexBytes);
  } else {
    const std::string command =
        std::string{ui.instruction_patch_assemble ? "assemble " : "patch "} +
        address_specification(*ui.instruction_patch_address) + " " +
        std::string{input};
    engine.execute_command(command);
    app_close_instruction_patch_editor(ui);
    return true;
  }
  return false;
}

const debugger::ModuleInfo *
module_for_address(const debugger::SessionSnapshot &snapshot,
                   std::uint64_t address) {
  const auto module =
      std::find_if(snapshot.modules.begin(), snapshot.modules.end(),
                   [address](const auto &entry) {
                     return address >= entry.base && address < entry.end;
                   });
  return module == snapshot.modules.end() ? nullptr : &*module;
}

std::optional<std::uint64_t>
selected_file_address(const debugger::SessionSnapshot &snapshot,
                      const UiState &ui) {
  const auto instruction = std::find_if(
      snapshot.instructions.begin(), snapshot.instructions.end(),
      [&ui](const debugger::InstructionRow &row) {
        return row.address == ui.disassembly_cursor && row.has_file_address;
      });
  if (instruction != snapshot.instructions.end()) {
    return instruction->file_address;
  }
  if (snapshot.disassembly_graph) {
    for (const auto &block : snapshot.disassembly_graph->blocks) {
      const auto graph_instruction = std::find_if(
          block.instructions.begin(), block.instructions.end(),
          [&ui](const debugger::InstructionRow &row) {
            return row.address == ui.disassembly_cursor && row.has_file_address;
          });
      if (graph_instruction != block.instructions.end()) {
        return graph_instruction->file_address;
      }
    }
  }
  if (ui.disassembly_cursor == snapshot.pc && snapshot.has_pc_file_address) {
    return snapshot.pc_file_address;
  }
  if (const auto *module = module_for_address(snapshot, ui.disassembly_cursor);
      module != nullptr && module->has_load_bias &&
      ui.disassembly_cursor >= module->load_bias) {
    return ui.disassembly_cursor - module->load_bias;
  }
  return std::nullopt;
}

std::optional<std::uint64_t>
load_address_for_file(const debugger::SessionSnapshot &snapshot,
                      std::string_view module_path,
                      std::uint64_t file_address) {
  const auto module = std::find_if(
      snapshot.modules.begin(), snapshot.modules.end(),
      [module_path](const auto &entry) { return entry.path == module_path; });
  if (module == snapshot.modules.end() || !module->has_load_bias ||
      file_address >
          std::numeric_limits<std::uint64_t>::max() - module->load_bias) {
    return std::nullopt;
  }
  const auto address = file_address + module->load_bias;
  return navigable_address(snapshot, address)
             ? std::optional<std::uint64_t>{address}
             : std::nullopt;
}
static const debugger::ModuleInfo *
module_for_path(const debugger::SessionSnapshot &snapshot,
                std::string_view path) {
  std::error_code path_error;
  const std::filesystem::path normalized =
      std::filesystem::weakly_canonical(path, path_error);
  const auto module = std::find_if(
      snapshot.modules.begin(), snapshot.modules.end(),
      [&normalized, path, path_error](const debugger::ModuleInfo &candidate) {
        if (candidate.path == path) {
          return true;
        }
        if (path_error) {
          return false;
        }
        std::error_code candidate_error;
        return std::filesystem::weakly_canonical(
                   candidate.path, candidate_error) == normalized &&
               !candidate_error;
      });
  return module == snapshot.modules.end() ? nullptr : &*module;
}

void request_decompilation(debugger::DecompilerEngine &decompiler,
                           const debugger::SessionSnapshot &snapshot,
                           std::string executable_path,
                           std::uint64_t file_address,
                           std::uint64_t load_address) {
  const auto *module = module_for_path(snapshot, executable_path);
  decompiler.request(debugger::DecompilerRequest{
      .executable_path = std::move(executable_path),
      .module_id = module == nullptr      ? std::string{}
                   : module->uuid.empty() ? module->path
                                          : module->uuid,
      .file_address = file_address,
      .load_address = load_address,
      .generation = snapshot.generation,
      .debug_info_path =
          module == nullptr ? std::string{} : module->debug_info_path,
      .session = snapshot.session,
      .analysis_revision = snapshot.session_analysis_revision,
  });
}

bool can_start_or_continue(const debugger::SessionSnapshot &snapshot,
                           const UiState &ui) {
  return snapshot.state == debugger::SessionState::Stopped ||
         ((snapshot.state == debugger::SessionState::NoTarget ||
           snapshot.state == debugger::SessionState::TargetLoaded ||
           snapshot.state == debugger::SessionState::Exited ||
           snapshot.state == debugger::SessionState::Error) &&
          ui.executable_path.front() != '\0');
}

bool can_terminate(const debugger::SessionSnapshot &snapshot) {
  return snapshot.state == debugger::SessionState::Launching ||
         snapshot.state == debugger::SessionState::Running ||
         snapshot.state == debugger::SessionState::Stopped;
}

void start_or_continue(const debugger::SessionSnapshot &snapshot,
                       debugger::LldbEngine &engine, const UiState &ui) {
  if (snapshot.state == debugger::SessionState::Stopped) {
    engine.continue_execution();
  } else {
    engine.launch(ui.executable_path.data());
  }
}

void toggle_cursor_breakpoint(const debugger::SessionSnapshot &snapshot,
                              debugger::LldbEngine &engine, const UiState &ui) {
  if (const debugger::BreakpointInfo *breakpoint =
          breakpoint_info_at(snapshot, ui.disassembly_cursor)) {
    engine.remove_breakpoint(breakpoint->id);
    return;
  }
  char address[32]{};
  std::snprintf(address, sizeof(address), "0x%" PRIx64, ui.disassembly_cursor);
  engine.set_breakpoint(address);
}

bool debug_action_enabled(DebugAction action,
                          const debugger::SessionSnapshot &snapshot,
                          const UiState &ui) {
  const bool stopped = snapshot.state == debugger::SessionState::Stopped;
  const bool can_launch =
      !snapshot.target_path.empty() &&
      (snapshot.state == debugger::SessionState::TargetLoaded ||
       snapshot.state == debugger::SessionState::Exited ||
       snapshot.state == debugger::SessionState::Error);
  switch (action) {
  case DebugAction::StartContinue:
    return can_start_or_continue(snapshot, ui);
  case DebugAction::Pause:
    return snapshot.state == debugger::SessionState::Running;
  case DebugAction::Terminate:
    return can_terminate(snapshot);
  case DebugAction::StartMain:
  case DebugAction::StartEntry:
    return can_launch;
  case DebugAction::ToggleBreakpoint:
  case DebugAction::RunToCursor:
    return stopped && ui.disassembly_cursor != 0;
  case DebugAction::SourceStepInto:
  case DebugAction::SourceStepOver:
  case DebugAction::InstructionStepInto:
  case DebugAction::InstructionStepOver:
  case DebugAction::FinishFunction:
  case DebugAction::NextCall:
  case DebugAction::NextBranch:
  case DebugAction::NextReturn:
  case DebugAction::NextSystemCall:
    return stopped;
  case DebugAction::Count:
    return false;
  }
  return false;
}

void execute_debug_action(DebugAction action,
                          const debugger::SessionSnapshot &snapshot,
                          debugger::LldbEngine &engine, const UiState &ui) {
  switch (action) {
  case DebugAction::StartContinue:
    start_or_continue(snapshot, engine, ui);
    break;
  case DebugAction::Pause:
    engine.stop();
    break;
  case DebugAction::Terminate:
    engine.terminate();
    break;
  case DebugAction::StartMain:
    engine.execute_command("start");
    break;
  case DebugAction::StartEntry:
    engine.execute_command("entry");
    break;
  case DebugAction::ToggleBreakpoint:
    toggle_cursor_breakpoint(snapshot, engine, ui);
    break;
  case DebugAction::RunToCursor:
    engine.run_to_address(ui.disassembly_cursor);
    break;
  case DebugAction::SourceStepInto:
    engine.execute_command("step");
    break;
  case DebugAction::SourceStepOver:
    engine.execute_command("next");
    break;
  case DebugAction::InstructionStepInto:
    engine.step_instruction(false);
    break;
  case DebugAction::InstructionStepOver:
    engine.step_instruction(true);
    break;
  case DebugAction::FinishFunction:
    engine.execute_command("finish");
    break;
  case DebugAction::NextCall:
    engine.execute_command("nextcall");
    break;
  case DebugAction::NextBranch:
    engine.execute_command("nextjmp");
    break;
  case DebugAction::NextReturn:
    engine.execute_command("nextret");
    break;
  case DebugAction::NextSystemCall:
    engine.execute_command("nextsyscall");
    break;
  case DebugAction::Count:
    break;
  }
}

void app_select_theme(debugger::LldbEngine &engine, UiState &ui, bool dark) {
  ui.theme_dark = dark;
  ui.theme_sync_pending = true;
  engine.execute_command(dark ? "theme dark" : "theme light");
}

} // namespace mydbg::app
