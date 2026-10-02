#include "backend/decompiler/DecompilerEngine.h"
#include "backend/lldb/LldbEngine.h"
#include "TestSupport.h"

#include <cstdint>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <thread>

using namespace std::chrono_literals;

namespace {
using debugger::test::require;

class TemporaryDirectory {
public:
  TemporaryDirectory() {
    char pattern[] = "/tmp/mydbg-dwarf-XXXXXX";
    const char *created = ::mkdtemp(pattern);
    if (!created)
      throw std::system_error(errno, std::generic_category(), "mkdtemp");
    path = created;
  }

  ~TemporaryDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
    if (error)
      std::fprintf(stderr, "DWARF cleanup failed: %s\n",
                   error.message().c_str());
  }

  std::filesystem::path path;
};

debugger::CommandResult completed(debugger::CommandTicket ticket) {
  require(ticket.valid() && ticket.wait_for(20s), "debugger command timed out");
  auto result = ticket.get();
  require(result.success, result.message);
  return result;
}

void complete(debugger::CommandTicket ticket) {
  (void)completed(std::move(ticket));
}

debugger::SessionSnapshot stopped(debugger::LldbEngine &engine) {
  auto snapshot = engine.snapshot();
  const auto deadline = std::chrono::steady_clock::now() + 20s;
  while (snapshot.state != debugger::SessionState::Stopped) {
    require(snapshot.state != debugger::SessionState::Error &&
                snapshot.state != debugger::SessionState::Exited,
            "fixture failed to stop: " + snapshot.error);
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
    require(remaining > 0ms, "fixture stop timed out");
    const auto update = engine.wait_for_update(snapshot.revision, remaining);
    require(update.has_value(), "fixture stop update timed out");
    snapshot = *update;
  }
  return snapshot;
}

std::optional<std::uint64_t>
module_load_bias_from_image_list(debugger::LldbEngine &engine,
                                 const std::string &image_name) {
  const auto result =
      completed(engine.execute_command("image list \"" + image_name + "\""));
  const auto base_prefix = result.message.find(" 0x");
  if (base_prefix == std::string::npos)
    return std::nullopt;
  const auto base_start = base_prefix + 1;
  const auto base_end = result.message.find_first_of(" \t\r\n", base_start);
  if (base_end == std::string::npos || base_end <= base_start)
    return std::nullopt;
  return std::stoull(result.message.substr(base_start, base_end - base_start),
                     nullptr, 16);
}

std::uint64_t image_lookup_address(debugger::LldbEngine &engine,
                                   const std::string &name) {
  const auto result = completed(engine.execute_command("image lookup -n " + name));
  const auto address_label = result.message.find("Address:");
  const auto open = result.message.find('[', address_label);
  const auto close = result.message.find(']', open);
  require(address_label != std::string::npos && open != std::string::npos &&
              close != std::string::npos && close > open + 1,
          "image lookup did not report a file address for " + name + ": " +
              result.message);
  auto image_name = result.message.substr(address_label + 8,
                                          open - (address_label + 8));
  const auto first = image_name.find_first_not_of(" \t\r\n");
  const auto last = image_name.find_last_not_of(" \t\r\n");
  image_name = first == std::string::npos
                   ? std::string{}
                   : image_name.substr(first, last - first + 1);
  const auto file_address =
      std::stoull(result.message.substr(open + 1, close - open - 1), nullptr, 16);
  for (const auto &module : engine.snapshot().modules) {
    const std::filesystem::path path{module.path};
    if (module.has_load_bias &&
        (path.filename() == image_name ||
         module.path.find(image_name) != std::string::npos))
      return module.load_bias + file_address;
  }
  if (const auto load_bias = module_load_bias_from_image_list(engine, image_name))
    return *load_bias + file_address;
  throw std::runtime_error("image lookup found " + name +
                           " but no relocated module matched " + image_name);
}

std::uint64_t symbol_address(debugger::LldbEngine &engine,
                             const std::string &name) {
  const auto before = engine.snapshot();
  (void)completed(engine.set_breakpoint(name));
  const auto after = engine.snapshot();
  for (const auto &breakpoint : after.breakpoints) {
    if (!breakpoint.addresses.empty() &&
        std::none_of(before.breakpoints.begin(), before.breakpoints.end(),
                     [&](const auto &old) { return old.id == breakpoint.id; }))
      return breakpoint.addresses.front();
  }
  return image_lookup_address(engine, name);
}
std::uint64_t runtime_symbol_address(debugger::LldbEngine &engine,
                                     const std::string &name) {
  try {
    return symbol_address(engine, name);
  } catch (const std::exception &) {
    const auto before = engine.snapshot();
    complete(engine.set_breakpoint(name));
    complete(engine.continue_execution());
    const auto deadline = std::chrono::steady_clock::now() + 20s;
    auto snapshot = engine.snapshot();
    while (snapshot.state != debugger::SessionState::Stopped ||
           snapshot.stop_revision <= before.stop_revision) {
      require(snapshot.state != debugger::SessionState::Error &&
                  snapshot.state != debugger::SessionState::Exited,
              "fixture failed to stop at " + name + ": " + snapshot.error);
      const auto remaining =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              deadline - std::chrono::steady_clock::now());
      require(remaining > 0ms, "fixture timed out stopping at " + name);
      const auto update = engine.wait_for_update(snapshot.revision, remaining);
      require(update.has_value(), "fixture stop update timed out for " + name);
      snapshot = *update;
    }
    require(snapshot.pc != 0, "fixture stopped at " + name + " without a PC");
    return snapshot.pc;
  }
}


const debugger::InstructionRow &
instruction_at(const debugger::SessionSnapshot &snapshot,
               std::uint64_t address) {
  const auto found =
      std::find_if(snapshot.instructions.begin(), snapshot.instructions.end(),
                   [=](const auto &row) { return row.address == address; });
  require(found != snapshot.instructions.end(),
          "requested code was not captured");
  return *found;
}

debugger::DecompilerRequest
request_for(const debugger::SessionSnapshot &snapshot,
            const debugger::InstructionRow &instruction) {
  require(instruction.has_file_address, "code has no file address");
  const auto module =
      std::find_if(snapshot.modules.begin(), snapshot.modules.end(),
                   [&](const auto &candidate) {
                     return candidate.has_load_bias &&
                            instruction.address - instruction.file_address ==
                                candidate.load_bias;
                   });
  require(module != snapshot.modules.end(), "code has no relocated module");
  return {.executable_path = module->path,
          .module_id = module->uuid.empty() ? module->path : module->uuid,
          .file_address = instruction.file_address,
          .load_address = instruction.address,
          .generation = snapshot.generation,
          .debug_info_path = module->debug_info_path};
}

std::string decompiled(debugger::DecompilerEngine &engine,
                       const debugger::DecompilerRequest &request,
                       bool submit = true) {
  if (submit)
    engine.request(request);
  const auto deadline = std::chrono::steady_clock::now() + 30s;
  while (std::chrono::steady_clock::now() < deadline) {
    const auto result = engine.snapshot();
    if (!result->loading &&
        result->executable_path == request.executable_path &&
        result->debug_info_path == request.debug_info_path &&
        result->module_id == request.module_id &&
        result->requested_file_address == request.file_address &&
        result->requested_load_address == request.load_address &&
        result->generation == request.generation) {
      require(result->error.empty(), "decompiler failed: " + result->error);
      std::string text;
      for (const auto &line : result->lines)
        text += line.text + '\n';
      return text;
    }
    std::this_thread::sleep_for(10ms);
  }
  throw std::runtime_error("decompilation timed out");
}

bool declaration(const debugger::InstructionRow &row, std::string_view name) {
  for (auto scope = row.debug_scope; scope; scope = scope->parent) {
    if (std::any_of(scope->declarations.begin(), scope->declarations.end(),
                    [&](const auto &value) { return value.name == name; }))
      return true;
  }
  return false;
}

void require_compute_metadata(const debugger::InstructionRow &row) {
  require(row.source && row.source->path.ends_with("dwarf.cpp") &&
              row.source->line != 0,
          "browsed function lost its DWARF source location");
  require(row.debug_scope && row.debug_scope->function,
          "browsed function lost its DWARF scope");
  const auto &function = *row.debug_scope->function;
  require(function.name.find("dwarf_compute") != std::string::npos,
          "browsed function inherited the stopped main frame");
  require(std::any_of(function.parameters.begin(), function.parameters.end(),
                      [](const auto &parameter) {
                        return parameter.name == "mode" &&
                               parameter.type.find("DwarfMode") !=
                                   std::string::npos;
                      }),
          "source parameter name/type was not populated");
}

void run(const char *executable, std::string_view mode,
         const char *debug_file) {
  debugger::LldbEngine debugger;
  complete(debugger.launch({.executable = executable,
                            .arguments = {},
                            .environment = {},
                            .working_directory = {},
                            .stop_policy = debugger::LaunchStopPolicy::Main}));
  const auto initial = stopped(debugger);
  if (mode == "explicit") {
    require(debug_file != nullptr, "explicit fixture needs a symbol file");
    complete(debugger.execute_command("target symbols add \"" +
                                      std::string{debug_file} + "\""));
  }
  const auto compute = symbol_address(debugger, "dwarf_compute");
  const auto secondary = symbol_address(debugger, "dwarf_secondary");
  const auto inherited = symbol_address(debugger, "dwarf_inherited");

  const auto browse_stop = stopped(debugger);
  complete(debugger.set_disassembly_graph_enabled(true));
  complete(debugger.read_instructions(compute));
  const auto snapshot = debugger.snapshot();
  require(snapshot.pc == browse_stop.pc && snapshot.pc != compute,
          "browsing changed the stopped PC");
  const auto &row = instruction_at(snapshot, compute);
  const auto request = request_for(snapshot, row);
  require(request.load_address != request.file_address,
          "fixture did not exercise PIE relocation");

  debugger::DecompilerEngine decompiler;
  const auto text = decompiled(decompiler, request);
  std::printf("%s\n", text.c_str());
  if (mode == "stripped") {
    require(!row.debug_scope && !row.source,
            "stripped code acquired invented debug metadata");
    require(text.find("dwarf_compute") != std::string::npos &&
                text.find("DwarfPayload") == std::string::npos,
            "stripped fallback did not retain machine-code analysis");
    complete(debugger.terminate());
    return;
  }

  require_compute_metadata(row);
  require(snapshot.disassembly_graph != nullptr,
          "DWARF graph was not captured");
  bool graph_function = false;
  bool graph_local = false;
  bool graph_inline = false;
  bool typed_global = false;
  for (const auto &block : snapshot.disassembly_graph->blocks) {
    for (const auto &instruction : block.instructions) {
      if (instruction.address == compute) {
        require_compute_metadata(instruction);
        graph_function = true;
      }
      graph_local |= declaration(instruction, "correction");
      for (auto scope = instruction.debug_scope; scope; scope = scope->parent)
        graph_inline |=
            scope->inline_name.find("dwarf_inline") != std::string::npos;
      for (const auto &reference : instruction.references)
        typed_global |= (reference.declaration.name == "dwarf_total" ||
                         reference.declaration.name == "::dwarf_total") &&
                        reference.declaration.type.find("DwarfPayload") !=
                            std::string::npos;
    }
  }
  require(graph_function, "graph lost browsed function metadata");
  require(graph_local, "graph lost nested lexical local declaration");
  require(graph_inline, "graph lost inline call scope");
  require(typed_global, "graph lost typed global reference");
  if (mode == "debuglink" || mode == "explicit")
    require(!request.debug_info_path.empty() &&
                request.debug_info_path != request.executable_path,
            "LLDB-resolved external symbols were not forwarded");
  require(text.find("DwarfPayload") != std::string::npos &&
              text.find("DwarfMode") != std::string::npos &&
              text.find("bias") != std::string::npos &&
              text.find("->total") != std::string::npos &&
              text.find("dwarf_total.total") != std::string::npos &&
              text.find("choice") != std::string::npos &&
              text.find("correction") != std::string::npos,
          "decompiler lost declared prototype, padded fields, union, or local");

  if (mode == "debuglink") {
    TemporaryDirectory temporary;
    const auto local_binary = temporary.path / "fixture";
    const auto local_debug = temporary.path / "dwarf.debug";
    std::filesystem::copy_file(request.executable_path, local_binary);
    std::filesystem::copy_file(request.debug_info_path, local_debug);
    auto automatic = request;
    automatic.executable_path = local_binary.string();
    automatic.debug_info_path.clear();
    require(decompiled(decompiler, automatic).find("DwarfPayload") !=
                std::string::npos,
            "GNU debuglink did not discover matching local DWARF");

    std::ofstream changed;
    changed.exceptions(std::ios::failbit | std::ios::badbit);
    changed.open(local_debug, std::ios::binary | std::ios::app);
    changed.put('\0');
    changed.close();
    debugger::DecompilerEngine fresh_decompiler;
    require(decompiled(fresh_decompiler, automatic).find("DwarfPayload") ==
                std::string::npos,
            "GNU debuglink accepted a mismatched symbol-file checksum");
  }

  decompiler.edit({.context = request,
                   .kind = debugger::DecompilerEditKind::Rename,
                   .target_kind = debugger::DecompilerSymbolKind::Parameter,
                   .target_name = "payload",
                   .value = "renamed_payload"});
  require(decompiled(decompiler, request, false).find("renamed_payload") !=
              std::string::npos,
          "DWARF parameter rename was overwritten by its original prototype");
  decompiler.edit({.context = request,
                   .kind = debugger::DecompilerEditKind::SetType,
                   .target_kind = debugger::DecompilerSymbolKind::Parameter,
                   .target_name = "bias",
                   .value = "unsigned int"});
  const auto retyped = decompiled(decompiler, request, false);
  require(retyped.find("uint bias") != std::string::npos ||
              retyped.find("unsigned int bias") != std::string::npos,
          "DWARF parameter type edit was overwritten");

  complete(debugger.read_instructions(secondary));
  const auto second_snapshot = debugger.snapshot();
  const auto second_request =
      request_for(second_snapshot, instruction_at(second_snapshot, secondary));
  const auto second_text = decompiled(decompiler, second_request);
  require(second_text.find("increment") != std::string::npos &&
              second_text.find("->total") != std::string::npos,
          "second compilation unit lost its names or struct layout");

  complete(debugger.read_instructions(inherited));
  const auto inherited_snapshot = debugger.snapshot();
  const auto inherited_request = request_for(
      inherited_snapshot, instruction_at(inherited_snapshot, inherited));
  const auto inherited_text = decompiled(decompiler, inherited_request);
  require(inherited_text.find("DwarfCount") != std::string::npos &&
              inherited_text.find("input") != std::string::npos &&
              inherited_text.find("return input") != std::string::npos,
          "abstract-origin return type or parameter was lost");
  const auto scale = runtime_symbol_address(debugger, "dwarf_scale");
  complete(debugger.read_instructions(scale));
  const auto library_snapshot = debugger.snapshot();
  const auto library_request =
      request_for(library_snapshot, instruction_at(library_snapshot, scale));
  require(library_request.executable_path != request.executable_path,
          "shared-library fixture resolved to the executable");
  const auto library_text = decompiled(decompiler, library_request);
  std::printf("%s\n", library_text.c_str());
  const auto signature = library_text.find("dwarf_scale(");
  const auto line_start = library_text.rfind('\n', signature);
  require(signature != std::string::npos &&
              std::string_view{library_text}
                  .substr(line_start == std::string::npos ? 0 : line_start + 1)
                  .starts_with("double ") &&
              library_text.find("double factor") != std::string::npos &&
              library_text.find("->total") != std::string::npos,
          "shared-library floating-point prototype or layout was lost");
  const auto library_body = library_text.find('{');
  require(library_body != std::string::npos &&
              library_text.find("factor", library_body) != std::string::npos,
          "an inferred register shadowed the floating-point parameter");
  require(decompiled(decompiler, request).find("renamed_payload") !=
              std::string::npos,
          "returning from another module discarded user type/symbol edits");

  if (mode == "explicit") {
    auto without_symbols = request;
    without_symbols.debug_info_path.clear();
    require(decompiled(decompiler, without_symbols).find("DwarfPayload") ==
                std::string::npos,
            "changing the symbol file reused stale DWARF analysis");
    require(decompiled(decompiler, request).find("renamed_payload") !=
                std::string::npos,
            "returning to the resolved symbol file discarded edits");
  }
  auto next_session = request;
  ++next_session.generation;
  require(decompiled(decompiler, next_session).find("renamed_payload") ==
              std::string::npos,
          "new target generation inherited stale analysis edits");
  complete(debugger.terminate());
}
} // namespace

int main(int argc, char **argv) {
  try {
    require(argc >= 3,
            "usage: dwarf_debug_info_tests EXECUTABLE MODE [DEBUG_FILE]");
    run(argv[1], argv[2], argc > 3 ? argv[3] : nullptr);
    std::puts("DWARF source, declarations, layouts, ABI prototypes and edit "
              "lifetime passed");
    return 0;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "DWARF regression failed: %s\n", error.what());
    return 1;
  }
}
