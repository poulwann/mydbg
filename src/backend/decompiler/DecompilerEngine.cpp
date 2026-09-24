#include "backend/decompiler/DecompilerEngine.h"
#include "localization/Localization.h"

#include <rz_bin_dwarf.h>
#include <rz_core.h>
#include <rz_ghidra.h>
#include <rz_util/rz_annotated_code.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <limits>
#include <memory>
#include <string_view>
#include <utility>

extern RzCorePlugin rz_core_plugin_ghidra;

namespace debugger {
namespace {

struct DebugFunction {
  ut64 address{};
  ut64 end{};
  RzAnalysisDebugInfo *info{};
};

struct CoreHandle {
  RzCore *core{};
  bool plugin_initialized{};
  RzAnalysisDebugInfo *primary_debug_info{};
  std::vector<RzAnalysisDebugInfo *> split_debug_info;
  std::vector<DebugFunction> debug_functions;

  ~CoreHandle() { reset(); }

  void reset() {
    if (core == nullptr) {
      return;
    }
    rz_core_bind_cons(core);
    if (primary_debug_info != nullptr) {
      core->analysis->debug_info = primary_debug_info;
    }
    // Split contexts borrow skeletons owned by the primary DWARF tree.
    for (RzAnalysisDebugInfo *info : split_debug_info) {
      info->dw->parent = nullptr;
    }
    if (plugin_initialized) {
      rz_core_plugin_ghidra.fini(core);
    }
    // Function variables borrow their DWARF origins, so release the core before
    // the split contexts that hold those origins.
    rz_core_free(core);
    for (RzAnalysisDebugInfo *info : split_debug_info) {
      rz_analysis_debug_info_free(info);
    }
    split_debug_info.clear();
    debug_functions.clear();
    primary_debug_info = nullptr;
    core = nullptr;
    plugin_initialized = false;
  }

  void integrate_debug_functions() {
    core->analysis->debug_info = primary_debug_info;
    if (primary_debug_info != nullptr) {
      rz_analysis_dwarf_integrate_functions(core->analysis, core->flags);
    }
    for (RzAnalysisDebugInfo *info : split_debug_info) {
      core->analysis->debug_info = info;
      rz_analysis_dwarf_integrate_functions(core->analysis, core->flags);
    }
    core->analysis->debug_info = primary_debug_info;
  }

  const DebugFunction *debug_function_at(ut64 address) const {
    auto after = std::upper_bound(
        debug_functions.begin(), debug_functions.end(), address,
        [](ut64 value, const DebugFunction &function) {
          return value < function.address;
        });
    while (after != debug_functions.begin()) {
      const DebugFunction &function = *--after;
      if (address == function.address || address < function.end) {
        return &function;
      }
    }
    return nullptr;
  }
};

struct LoadedCore {
  DecompilerRequest identity;
  CoreHandle handle;
  std::string debug_info_notice;
  std::string session_notice;
  std::string module_sha256;
  std::vector<DecompilerMemoryHint> memory_hints;
  std::vector<SessionComment> comments;
  bool replay_blocked{};
  bool unsaved_edits{};
  bool session_loaded{};
  bool unpublished_edits{};
};

// Canonicalization both validates local paths and prevents the Rizin IO layer
// from interpreting an untrusted symbol path as a network/plugin URI.
std::filesystem::path local_debug_path(const std::filesystem::path &path) {
  std::error_code error;
  auto canonical = std::filesystem::canonical(path, error);
  if (error || !std::filesystem::is_regular_file(canonical, error) || error) {
    return {};
  }
  return canonical;
}

RzBinDWARF *load_dwarf_path(const std::filesystem::path &path,
                            RzBinDWARF *parent) {
  RzBinDWARF *dwarf = rz_bin_dwarf_from_path(path.c_str(), parent);
  if (dwarf != nullptr && dwarf->info != nullptr &&
      !rz_vector_empty(&dwarf->info->units)) {
    return dwarf;
  }
  // Success transfers parent ownership; failure must leave it with the caller.
  if (dwarf != nullptr) {
    dwarf->parent = nullptr;
    rz_bin_dwarf_free(dwarf);
  }
  return nullptr;
}

void append_debug_info_notice(std::string &notice, const std::string &path) {
  if (!notice.empty()) {
    notice += '\n';
  }
  notice +=
      l10n::format(l10n::Key::DecompilerDebugInfoLoadFailed, path.c_str());
}

// Open the machine-code module first. A separate symbol file supplies DWARF
// only; opening it as the core binary would discard the module's code mappings.
std::string load_debug_info(RzCore &core, const DecompilerRequest &request) {
  rz_config_set_b(core.config, "bin.dbginfo", true);
  RzBinFile *binary = rz_bin_cur(core.bin);
  if (binary == nullptr) {
    return {};
  }

  std::string notice;
  if (!request.debug_info_path.empty() &&
      request.debug_info_path != request.executable_path) {
    const auto path = local_debug_path(request.debug_info_path);
    RzBinDWARF *parent =
        path.empty() ? nullptr : rz_bin_dwarf_from_file(binary);
    RzBinDWARF *dwarf = path.empty() ? nullptr : load_dwarf_path(path, parent);
    if (dwarf != nullptr) {
      RzAnalysisDebugInfo *info = rz_analysis_debug_info_new();
      if (info != nullptr) {
        info->dw = dwarf;
        rz_analysis_debug_info_free(core.analysis->debug_info);
        core.analysis->debug_info = info;
        rz_analysis_dwarf_process_info(core.analysis, dwarf);
        return {};
      }
    }
    // A failed child load must leave its borrowed parent alive (the pinned
    // Rizin ownership fix is required here). On success the child owns it.
    if (dwarf != nullptr) {
      rz_bin_dwarf_free(dwarf);
    } else {
      rz_bin_dwarf_free(parent);
    }
    append_debug_info_notice(notice, request.debug_info_path);
  }

  // This uses Rizin's embedded DWARF, local debuglink/build-id and dSYM
  // discovery. Missing symbols are not a failure of machine-code analysis.
  rz_core_bin_apply_dwarf(&core, binary);
  return notice;
}

void load_split_debug_info(LoadedCore &loaded) {
  CoreHandle &handle = loaded.handle;
  RzCore &core = *handle.core;
  handle.primary_debug_info = core.analysis->debug_info;
  if (handle.primary_debug_info == nullptr) {
    return;
  }
  std::vector<std::filesystem::path> loaded_paths;
  if (!loaded.identity.debug_info_path.empty()) {
    const auto explicit_path =
        local_debug_path(loaded.identity.debug_info_path);
    if (!explicit_path.empty()) {
      loaded_paths.push_back(explicit_path);
    }
  }
  const auto module_directory =
      std::filesystem::path(loaded.identity.executable_path).parent_path();
  const auto symbol_directory =
      std::filesystem::path(loaded.identity.debug_info_path).parent_path();
  for (RzBinDWARF *parent = handle.primary_debug_info->dw; parent != nullptr;
       parent = parent->parent) {
    if (parent->info == nullptr) {
      continue;
    }
    for (std::size_t index = 0; index < rz_vector_len(&parent->info->units);
         ++index) {
      const auto *unit = static_cast<const RzBinDwarfCompUnit *>(
          rz_vector_index_ptr(&parent->info->units, index));
      if (unit->dwo_name == nullptr || *unit->dwo_name == '\0') {
        continue;
      }
      const std::filesystem::path name(unit->dwo_name);
      auto path =
          local_debug_path(unit->comp_dir == nullptr
                               ? name
                               : std::filesystem::path(unit->comp_dir) / name);
      if (path.empty()) {
        path = local_debug_path(module_directory / name);
      }
      if (path.empty() && !symbol_directory.empty()) {
        path = local_debug_path(symbol_directory / name);
      }
      if (path.empty()) {
        append_debug_info_notice(loaded.debug_info_notice, name.string());
        continue;
      }
      if (std::find(loaded_paths.begin(), loaded_paths.end(), path) !=
          loaded_paths.end()) {
        continue;
      }
      loaded_paths.push_back(path);
      RzBinDWARF *dwarf = load_dwarf_path(path, parent);
      bool matching_id = unit->hdr.dwo_id == 0;
      if (dwarf != nullptr) {
        for (std::size_t child = 0; child < rz_vector_len(&dwarf->info->units);
             ++child) {
          const auto *candidate = static_cast<const RzBinDwarfCompUnit *>(
              rz_vector_index_ptr(&dwarf->info->units, child));
          matching_id |= candidate->hdr.dwo_id == unit->hdr.dwo_id;
        }
        if (!matching_id) {
          dwarf->parent = nullptr;
          rz_bin_dwarf_free(dwarf);
          dwarf = nullptr;
        }
      }
      RzAnalysisDebugInfo *info =
          dwarf == nullptr ? nullptr : rz_analysis_debug_info_new();
      if (info == nullptr) {
        if (dwarf != nullptr) {
          dwarf->parent = nullptr;
          rz_bin_dwarf_free(dwarf);
        }
        append_debug_info_notice(loaded.debug_info_notice, path.string());
        continue;
      }
      // DIE offsets are local to a DWO. Keep every context independently owned
      // rather than merging its offset maps with another compilation unit.
      info->dw = dwarf;
      handle.split_debug_info.push_back(info);
      core.analysis->debug_info = info;
      rz_analysis_dwarf_process_info(core.analysis, dwarf);
    }
  }
  core.analysis->debug_info = handle.primary_debug_info;

  const auto index_context = [&handle](RzAnalysisDebugInfo *info) {
    struct IndexContext {
      CoreHandle &handle;
      RzAnalysisDebugInfo *info;
    } context{handle, info};
    ht_up_foreach(
        info->function_by_addr,
        [](void *user, ut64, const void *value) {
          auto &index = *static_cast<IndexContext *>(user);
          const auto &function =
              *static_cast<const RzAnalysisDwarfFunction *>(value);
          index.handle.debug_functions.push_back(
              {function.low_pc, function.high_pc, index.info});
          return true;
        },
        &context);
  };
  index_context(handle.primary_debug_info);
  for (RzAnalysisDebugInfo *info : handle.split_debug_info) {
    index_context(info);
  }
  std::stable_sort(handle.debug_functions.begin(), handle.debug_functions.end(),
                   [](const DebugFunction &left, const DebugFunction &right) {
                     return left.address < right.address;
                   });
}

DecompilerTokenKind convert_token_kind(RSyntaxHighlightType kind) {
  switch (kind) {
  case RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD:
    return DecompilerTokenKind::Keyword;
  case RZ_SYNTAX_HIGHLIGHT_TYPE_COMMENT:
    return DecompilerTokenKind::Comment;
  case RZ_SYNTAX_HIGHLIGHT_TYPE_DATATYPE:
    return DecompilerTokenKind::DataType;
  case RZ_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME:
    return DecompilerTokenKind::Function;
  case RZ_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_PARAMETER:
    return DecompilerTokenKind::Parameter;
  case RZ_SYNTAX_HIGHLIGHT_TYPE_LOCAL_VARIABLE:
    return DecompilerTokenKind::Local;
  case RZ_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE:
    return DecompilerTokenKind::Constant;
  case RZ_SYNTAX_HIGHLIGHT_TYPE_GLOBAL_VARIABLE:
    return DecompilerTokenKind::Global;
  }
  return DecompilerTokenKind::Plain;
}

DecompilerSymbolKind convert_annotation_kind(RzCodeAnnotationType type) {
  switch (type) {
  case RZ_CODE_ANNOTATION_TYPE_FUNCTION_NAME:
    return DecompilerSymbolKind::Function;
  case RZ_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE:
    return DecompilerSymbolKind::Global;
  case RZ_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE:
    return DecompilerSymbolKind::Constant;
  case RZ_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE:
    return DecompilerSymbolKind::Local;
  case RZ_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER:
    return DecompilerSymbolKind::Parameter;
  case RZ_CODE_ANNOTATION_TYPE_OFFSET:
  case RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT:
    return DecompilerSymbolKind::None;
  }
  return DecompilerSymbolKind::None;
}

bool valid_identifier(std::string_view text) {
  if (text.empty()) {
    return false;
  }
  const auto first = static_cast<unsigned char>(text.front());
  if (!(std::isalpha(first) || text.front() == '_')) {
    return false;
  }
  return std::all_of(text.begin() + 1, text.end(), [](char character) {
    const auto value = static_cast<unsigned char>(character);
    return std::isalnum(value) || character == '_';
  });
}

bool safe_type_text(std::string_view text) {
  return !text.empty() && text.find_first_of("\r\n") == std::string_view::npos;
}

RzCallable *debug_callable(RzCore &core, const RzAnalysisFunction &function) {
  RzAnalysisDebugInfo *info = core.analysis->debug_info;
  if (info == nullptr) {
    return nullptr;
  }
  const auto *debug = static_cast<const RzAnalysisDwarfFunction *>(
      ht_up_find(info->function_by_addr, function.addr, nullptr));
  return debug == nullptr
             ? nullptr
             : static_cast<RzCallable *>(ht_up_find(info->callable_by_offset,
                                                    debug->offset, nullptr));
}

RzCallableArg *debug_parameter(RzCallable *callable, const std::string &name) {
  if (callable == nullptr) {
    return nullptr;
  }
  for (std::size_t index = 0; index < rz_pvector_len(callable->args); ++index) {
    auto *argument =
        static_cast<RzCallableArg *>(rz_pvector_at(callable->args, index));
    if (argument != nullptr && argument->name != nullptr &&
        name == argument->name) {
      return argument;
    }
  }
  return nullptr;
}

void store_edited_callable(RzCore &core, const RzCallable &callable) {
  if (RzCallable *copy = rz_type_callable_clone(&callable)) {
    rz_type_func_update(core.analysis->typedb, copy);
  }
}

struct EditOutcome {
  bool applied{};
  std::string notice;
};

EditOutcome edit_outcome(bool applied, l10n::Key message) {
  return {applied, l10n::text(message)};
}

EditOutcome apply_decompiler_edit(RzCore &core, RzAnalysisFunction &function,
                                  const DecompilerEditRequest &edit) {
  if (edit.has_target_file_address &&
      !rz_io_is_valid_offset(core.io, edit.target_file_address, RZ_PERM_R)) {
    return edit_outcome(false, l10n::Key::DecompilerAddressUnavailable);
  }
  if (edit.kind == DecompilerEditKind::MarkString) {
    if (!edit.has_target_file_address) {
      return edit_outcome(false,
                          l10n::Key::DecompilerStringTokenMissingAddress);
    }
    rz_core_seek(&core, static_cast<ut64>(edit.target_file_address), true);
    if (rz_core_cmd0(&core, "Cs") != RZ_CORE_CMD_OK ||
        rz_meta_get_at(core.analysis, edit.target_file_address,
                       RZ_META_TYPE_STRING, nullptr) == nullptr) {
      return edit_outcome(false, l10n::Key::DecompilerStringConversionRejected);
    }
    return edit_outcome(true, l10n::Key::DecompilerStringConversionSucceeded);
  }

  if (edit.kind == DecompilerEditKind::Rename) {
    if (!valid_identifier(edit.value)) {
      return edit_outcome(false, l10n::Key::DecompilerRenameRequiresIdentifier);
    }
    switch (edit.target_kind) {
    case DecompilerSymbolKind::Local:
    case DecompilerSymbolKind::Parameter: {
      RzAnalysisVar *variable = rz_analysis_function_get_var_byname(
          &function, edit.target_name.c_str());
      if (variable == nullptr) {
        RzCallable *callable = debug_callable(core, function);
        RzCallableArg *argument =
            edit.target_kind == DecompilerSymbolKind::Parameter
                ? debug_parameter(callable, edit.target_name)
                : nullptr;
        if (argument != nullptr) {
          if (debug_parameter(callable, edit.value) != nullptr ||
              rz_analysis_function_get_var_byname(
                  &function, edit.value.c_str()) != nullptr) {
            return edit_outcome(false,
                                l10n::Key::DecompilerVariableRenameRejected);
          }
          char *name = rz_str_dup(edit.value.c_str());
          if (name == nullptr) {
            return edit_outcome(false,
                                l10n::Key::DecompilerVariableRenameRejected);
          }
          std::free(argument->name);
          argument->name = name;
          store_edited_callable(core, *callable);
          return edit_outcome(true, l10n::Key::DecompilerVariableRenamed);
        }
        return edit_outcome(false, l10n::Key::DecompilerVariableNotFound);
      }
      const bool renamed =
          rz_analysis_var_rename(variable, edit.value.c_str(), false);
      return edit_outcome(
          renamed, renamed ? l10n::Key::DecompilerVariableRenamed
                           : l10n::Key::DecompilerVariableRenameRejected);
    }
    case DecompilerSymbolKind::Function: {
      if (!edit.has_target_file_address) {
        return edit_outcome(false,
                            l10n::Key::DecompilerFunctionTokenMissingAddress);
      }
      const bool renamed = rz_core_analysis_function_rename(
          &core, static_cast<ut64>(edit.target_file_address),
          edit.value.c_str());
      return edit_outcome(
          renamed, renamed ? l10n::Key::DecompilerFunctionRenamed
                           : l10n::Key::DecompilerFunctionRenameRejected);
    }
    case DecompilerSymbolKind::Global: {
      RzAnalysisVarGlobal *global =
          edit.target_name.empty()
              ? nullptr
              : rz_analysis_var_global_get_byname(core.analysis,
                                                  edit.target_name.c_str());
      if (global != nullptr &&
          (!edit.has_target_file_address ||
           global->addr == edit.target_file_address) &&
          rz_analysis_var_global_rename(core.analysis, edit.target_name.c_str(),
                                        edit.value.c_str())) {
        return edit_outcome(true, l10n::Key::DecompilerGlobalRenamed);
      }
      return edit_outcome(false, l10n::Key::DecompilerGlobalNotFound);
    }
    case DecompilerSymbolKind::Constant:
    case DecompilerSymbolKind::None:
      return edit_outcome(false, l10n::Key::DecompilerTokenNotRenameable);
    }
  }

  if (edit.kind == DecompilerEditKind::SetType) {
    if (!safe_type_text(edit.value)) {
      return edit_outcome(false,
                          l10n::Key::DecompilerTypeRequiresSingleExpression);
    }
    char *raw_error = nullptr;
    std::unique_ptr<RzType, decltype(&rz_type_free)> parsed{
        rz_type_parse_string_single(core.analysis->typedb->parser,
                                    edit.value.c_str(), &raw_error),
        &rz_type_free};
    std::unique_ptr<char, decltype(&std::free)> parse_error{raw_error,
                                                            &std::free};
    if (!parsed) {
      return {false,
              parse_error
                  ? l10n::format(l10n::Key::DecompilerTypeParseFailureDetails,
                                 parse_error.get())
                  : l10n::text(l10n::Key::DecompilerTypeParseFailed)};
    }

    switch (edit.target_kind) {
    case DecompilerSymbolKind::Local:
    case DecompilerSymbolKind::Parameter: {
      RzAnalysisVar *variable = rz_analysis_function_get_var_byname(
          &function, edit.target_name.c_str());
      if (variable == nullptr) {
        RzCallable *callable = debug_callable(core, function);
        RzCallableArg *argument =
            edit.target_kind == DecompilerSymbolKind::Parameter
                ? debug_parameter(callable, edit.target_name)
                : nullptr;
        if (argument != nullptr) {
          rz_type_free(argument->type);
          argument->type = parsed.release();
          store_edited_callable(core, *callable);
          return edit_outcome(true, l10n::Key::DecompilerVariableTypeUpdated);
        }
        return edit_outcome(false, l10n::Key::DecompilerVariableNotFound);
      }
      rz_analysis_var_set_type(variable, parsed.release(), true);
      return edit_outcome(true, l10n::Key::DecompilerVariableTypeUpdated);
    }
    case DecompilerSymbolKind::Global:
    case DecompilerSymbolKind::Constant: {
      if (!edit.has_target_file_address) {
        return edit_outcome(false,
                            l10n::Key::DecompilerTypeTokenMissingAddress);
      }
      RzAnalysisVarGlobal *global = nullptr;
      if (edit.target_kind == DecompilerSymbolKind::Global &&
          !edit.target_name.empty()) {
        global = rz_analysis_var_global_get_byname(core.analysis,
                                                   edit.target_name.c_str());
        if (global != nullptr && global->addr != edit.target_file_address) {
          return edit_outcome(false, l10n::Key::DecompilerGlobalNotFound);
        }
      }
      if (!rz_meta_set_string(core.analysis, RZ_META_TYPE_VARTYPE,
                              static_cast<ut64>(edit.target_file_address),
                              edit.value.c_str())) {
        return edit_outcome(false, l10n::Key::DecompilerAddressTypeRejected);
      }
      if (edit.target_kind == DecompilerSymbolKind::Global) {
        if (global == nullptr) {
          global = rz_analysis_var_global_get_byaddr_at(
              core.analysis, static_cast<ut64>(edit.target_file_address));
        }
        if (global == nullptr && !edit.target_name.empty()) {
          global = rz_analysis_var_global_new(
              edit.target_name.c_str(),
              static_cast<ut64>(edit.target_file_address));
          if (global != nullptr &&
              !rz_analysis_var_global_add(core.analysis, global)) {
            rz_analysis_var_global_free(global);
            global = nullptr;
          }
        }
        if (global != nullptr) {
          rz_analysis_var_global_set_type(global, parsed.get());
        }
      }
      return edit_outcome(true, l10n::Key::DecompilerAddressTypeRecorded);
    }
    case DecompilerSymbolKind::Function:
    case DecompilerSymbolKind::None:
      return edit_outcome(false, l10n::Key::DecompilerTokenNotRetypeable);
    }
  }

  return edit_outcome(false, l10n::Key::DecompilerUnsupportedEdit);
}

void append_notice(std::string &notice, std::string_view message) {
  if (message.empty()) {
    return;
  }
  if (!notice.empty()) {
    notice += '\n';
  }
  notice += message;
}

template <typename To, typename From> To convert_analysis_kind(From kind) {
  switch (kind) {
  case From::Rename:
    return To::Rename;
  case From::SetType:
    return To::SetType;
  case From::MarkString:
    return To::MarkString;
  }
  std::terminate();
}

template <typename To, typename From> To convert_symbol_kind(From kind) {
  switch (kind) {
  case From::None:
    return To::None;
  case From::Function:
    return To::Function;
  case From::Global:
    return To::Global;
  case From::Constant:
    return To::Constant;
  case From::Local:
    return To::Local;
  case From::Parameter:
    return To::Parameter;
  }
  std::terminate();
}

SessionAnalysisEdit saved_edit(const DecompilerEditRequest &edit,
                               const RzAnalysisFunction &function) {
  return {
      .kind = convert_analysis_kind<SavedAnalysisKind>(edit.kind),
      .target_kind = convert_symbol_kind<SavedSymbolKind>(edit.target_kind),
      .function_file_address = function.addr,
      .target_name = edit.target_name,
      .target_file_address = edit.target_file_address,
      .has_target_file_address = edit.has_target_file_address,
      .value = edit.value,
  };
}

void update_memory_hints(LoadedCore &loaded,
                         const DecompilerEditRequest &edit) {
  if (edit.kind == DecompilerEditKind::Rename &&
      edit.target_kind == DecompilerSymbolKind::Global) {
    for (auto &hint : loaded.memory_hints) {
      if ((edit.has_target_file_address &&
           hint.file_address == edit.target_file_address) ||
          (!edit.has_target_file_address && hint.label == edit.target_name)) {
        hint.label = edit.value;
      }
    }
    return;
  }
  if (!edit.has_target_file_address ||
      (edit.kind != DecompilerEditKind::MarkString &&
       !(edit.kind == DecompilerEditKind::SetType &&
         (edit.target_kind == DecompilerSymbolKind::Global ||
          edit.target_kind == DecompilerSymbolKind::Constant)))) {
    return;
  }
  const auto existing =
      std::find_if(loaded.memory_hints.begin(), loaded.memory_hints.end(),
                   [&edit](const auto &hint) {
                     return hint.file_address == edit.target_file_address;
                   });
  DecompilerMemoryHint hint{
      .file_address = edit.target_file_address,
      .label = edit.target_name,
      .type =
          edit.kind == DecompilerEditKind::MarkString ? "string" : edit.value,
      .is_string = edit.kind == DecompilerEditKind::MarkString,
  };
  if (existing == loaded.memory_hints.end()) {
    loaded.memory_hints.push_back(std::move(hint));
  } else {
    *existing = std::move(hint);
  }
}

RzAnalysisFunction *ensure_function(CoreHandle &handle, ut64 address) {
  RzAnalysisFunction *function = rz_analysis_get_fcn_in(
      handle.core->analysis, address, RZ_ANALYSIS_FCN_TYPE_NULL);
  if (function == nullptr) {
    const DebugFunction *debug = handle.debug_function_at(address);
    const ut64 start = debug != nullptr ? debug->address : address;
    handle.core->analysis->debug_info =
        debug != nullptr ? debug->info : handle.primary_debug_info;
    if (rz_core_analysis_function_add(handle.core, nullptr, start, false)) {
      handle.integrate_debug_functions();
      function = rz_analysis_get_fcn_in(handle.core->analysis, address,
                                        RZ_ANALYSIS_FCN_TYPE_NULL);
    }
  }
  return function;
}

void select_debug_context(CoreHandle &handle,
                          const RzAnalysisFunction &function) {
  const DebugFunction *debug = handle.debug_function_at(function.addr);
  handle.core->analysis->debug_info =
      debug != nullptr ? debug->info : handle.primary_debug_info;
}

void restore_analysis(LoadedCore &loaded, const SessionData &session) {
  CoreHandle &handle = loaded.handle;
  const auto module =
      std::find_if(session.analysis.begin(), session.analysis.end(),
                   [&loaded](const auto &entry) {
                     return entry.sha256 == loaded.module_sha256;
                   });
  if (module != session.analysis.end()) {
    // Complete every relevant DWARF baseline before applying any overrides.
    // In particular, split-DWARF parameter names belong to their own context.
    for (const auto &edit : module->edits) {
      ensure_function(handle, edit.function_file_address);
      if (edit.target_kind == SavedSymbolKind::Function &&
          edit.has_target_file_address) {
        ensure_function(handle, edit.target_file_address);
      }
    }
    for (std::size_t index = 0; index < module->edits.size(); ++index) {
      const auto &saved = module->edits[index];
      RzAnalysisFunction *function = rz_analysis_get_fcn_in(
          handle.core->analysis, saved.function_file_address,
          RZ_ANALYSIS_FCN_TYPE_NULL);
      EditOutcome outcome =
          edit_outcome(false, l10n::Key::DecompilerNoFunctionAtAddress);
      if (function != nullptr &&
          function->addr == saved.function_file_address) {
        select_debug_context(handle, *function);
        DecompilerEditRequest edit{
            .context = {},
            .kind = convert_analysis_kind<DecompilerEditKind>(saved.kind),
            .target_kind =
                convert_symbol_kind<DecompilerSymbolKind>(saved.target_kind),
            .target_name = saved.target_name,
            .target_file_address = saved.target_file_address,
            .has_target_file_address = saved.has_target_file_address,
            .value = saved.value,
        };
        outcome = apply_decompiler_edit(*handle.core, *function, edit);
        if (outcome.applied) {
          update_memory_hints(loaded, edit);
        }
      }
      if (!outcome.applied) {
        loaded.replay_blocked = true;
        append_notice(loaded.session_notice,
                      l10n::format(l10n::Key::DecompilerReplayFailed, index + 1,
                                   static_cast<unsigned long long>(
                                       saved.function_file_address),
                                   outcome.notice.c_str()));
        // Even an apparently unrelated later edit can depend on a renamed
        // global or altered type. Retain the full suffix rather than retarget.
        break;
      }
    }
  }
  for (const auto &comment : session.comments) {
    if (comment.address.module_sha256 != loaded.module_sha256) {
      continue;
    }
    loaded.comments.push_back(comment);
  }
  std::stable_sort(loaded.comments.begin(), loaded.comments.end(),
                   [](const auto &left, const auto &right) {
                     return left.address.file_address <
                            right.address.file_address;
                   });
}

struct CharacterAnnotation {
  DecompilerTokenKind kind{DecompilerTokenKind::Plain};
  DecompilerSymbolKind symbol_kind{DecompilerSymbolKind::None};
  std::string_view symbol_name;
  std::uint64_t reference_file_address{};
  std::uint64_t file_address{};
  bool has_file_address{};
  bool has_reference_file_address{};

  bool operator==(const CharacterAnnotation &) const = default;
};

std::vector<DecompiledLine> build_lines(const RzAnnotatedCode &code) {
  const std::string_view text =
      code.code == nullptr ? std::string_view{} : std::string_view{code.code};
  std::vector<DecompiledLine> lines;

  std::size_t line_start = 0;
  while (line_start <= text.size()) {
    const std::size_t newline = text.find('\n', line_start);
    const std::size_t line_end =
        newline == std::string_view::npos ? text.size() : newline;
    DecompiledLine line;
    line.text.assign(text.substr(line_start, line_end - line_start));
    std::vector<CharacterAnnotation> characters(line.text.size());
    std::vector<std::size_t> file_address_range_sizes(
        line.text.size(), std::numeric_limits<std::size_t>::max());

    for (std::size_t annotation_index = 0;
         annotation_index < rz_vector_len(&code.annotations);
         ++annotation_index) {
      const auto *annotation = static_cast<const RzCodeAnnotation *>(
          rz_vector_index_ptr(&code.annotations, annotation_index));
      const std::size_t annotation_start =
          std::min(annotation->start, text.size());
      const std::size_t annotation_end = std::min(annotation->end, text.size());
      if (annotation_start >= line_end || annotation_end <= line_start) {
        continue;
      }

      const std::size_t start =
          std::max(annotation_start, line_start) - line_start;
      const std::size_t end = std::min(annotation_end, line_end) - line_start;
      if (end <= start) {
        continue;
      }

      if (annotation->type == RZ_CODE_ANNOTATION_TYPE_OFFSET) {
        const auto address =
            static_cast<std::uint64_t>(annotation->offset.offset);
        if (std::find(line.file_addresses.begin(), line.file_addresses.end(),
                      address) == line.file_addresses.end()) {
          line.file_addresses.push_back(address);
        }
        const std::size_t range_size = annotation_end - annotation_start;
        for (std::size_t index = start; index < end; ++index) {
          if (range_size <= file_address_range_sizes[index]) {
            characters[index].file_address = address;
            characters[index].has_file_address = true;
            file_address_range_sizes[index] = range_size;
          }
        }
        continue;
      }

      if (annotation->type == RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT) {
        const DecompilerTokenKind kind =
            convert_token_kind(annotation->syntax_highlight.type);
        for (std::size_t index = start; index < end; ++index) {
          characters[index].kind = kind;
        }
        continue;
      }

      const DecompilerSymbolKind symbol_kind =
          convert_annotation_kind(annotation->type);
      if (symbol_kind == DecompilerSymbolKind::None) {
        continue;
      }
      const char *name = nullptr;
      std::uint64_t reference = 0;
      bool has_reference = false;
      if (symbol_kind == DecompilerSymbolKind::Local ||
          symbol_kind == DecompilerSymbolKind::Parameter) {
        name = annotation->variable.name;
      } else {
        name = annotation->reference.name;
        reference = static_cast<std::uint64_t>(annotation->reference.offset);
        has_reference = true;
      }
      const std::string_view symbol_name = name == nullptr ? "" : name;
      for (std::size_t index = start; index < end; ++index) {
        auto &character = characters[index];
        character.symbol_kind = symbol_kind;
        character.symbol_name = symbol_name;
        character.reference_file_address = reference;
        character.has_reference_file_address = has_reference;
      }
    }

    std::size_t span_start = 0;
    while (span_start < characters.size()) {
      const auto &character = characters[span_start];
      std::size_t span_end = span_start + 1;
      while (span_end < characters.size() &&
             characters[span_end] == character) {
        ++span_end;
      }
      line.spans.push_back({.start = span_start,
                            .length = span_end - span_start,
                            .kind = character.kind,
                            .symbol_kind = character.symbol_kind,
                            .symbol_name = std::string{character.symbol_name},
                            .reference_file_address =
                                character.reference_file_address,
                            .file_address = character.file_address,
                            .has_file_address = character.has_file_address,
                            .has_reference_file_address =
                                character.has_reference_file_address});
      span_start = span_end;
    }
    lines.push_back(std::move(line));

    if (newline == std::string_view::npos) {
      break;
    }
    line_start = newline + 1;
  }
  return lines;
}

void add_comment_lines(std::vector<DecompiledLine> &lines,
                       const std::vector<SessionComment> &comments,
                       RzAnalysisFunction &function) {
  for (const auto &comment : comments) {
    const auto address = comment.address.file_address;
    const auto mapped =
        std::find_if(lines.begin(), lines.end(), [address](const auto &line) {
          return std::find(line.file_addresses.begin(),
                           line.file_addresses.end(),
                           address) != line.file_addresses.end();
        });
    if (mapped == lines.end() && address != function.addr &&
        !rz_analysis_function_contains(&function, address)) {
      continue;
    }
    // Render authored notes here exactly once. Provider comment annotations
    // can move away from their instruction and flatten multiline text.
    std::size_t insertion =
        mapped == lines.end()
            ? 0
            : static_cast<std::size_t>(mapped - lines.begin());
    for (std::size_t start = 0; start < comment.text.size();) {
      const auto newline = comment.text.find('\n', start);
      const auto end =
          newline == std::string::npos ? comment.text.size() : newline;
      std::string_view text(comment.text.data() + start, end - start);
      if (!text.empty() && text.back() == '\r') {
        text.remove_suffix(1);
      }
      DecompiledLine line;
      line.text = "// ";
      line.text += text;
      line.file_addresses.push_back(address);
      line.spans.push_back(DecompilerSpan{
          .start = 0,
          .length = line.text.size(),
          .kind = DecompilerTokenKind::Comment,
          .symbol_name = {},
          .file_address = address,
          .has_file_address = true,
      });
      lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(insertion),
                   std::move(line));
      ++insertion;
      if (newline == std::string::npos) {
        break;
      }
      start = newline + 1;
    }
  }
}

bool matching_context(const DecompilerSnapshot &snapshot,
                      const DecompilerRequest &request) {
  return snapshot.executable_path == request.executable_path &&
         snapshot.debug_info_path == request.debug_info_path &&
         snapshot.module_id == request.module_id &&
         snapshot.generation == request.generation &&
         snapshot.session == request.session &&
         snapshot.analysis_revision == request.analysis_revision;
}

void set_identity(DecompilerSnapshot &snapshot,
                  const DecompilerRequest &identity, std::uint64_t serial) {
  snapshot.executable_path = identity.executable_path;
  snapshot.debug_info_path = identity.debug_info_path;
  snapshot.module_id = identity.module_id;
  snapshot.requested_file_address = identity.file_address;
  snapshot.requested_load_address = identity.load_address;
  snapshot.generation = identity.generation;
  snapshot.request_serial = serial;
  snapshot.session = identity.session;
  snapshot.analysis_revision = identity.analysis_revision;
}

} // namespace

DecompilerEngine::DecompilerEngine(std::shared_ptr<SessionStore> sessions)
    : sessions_(std::move(sessions)),
      snapshot_(std::make_shared<DecompilerSnapshot>()),
      worker_(&DecompilerEngine::run, this) {}

DecompilerEngine::~DecompilerEngine() {
  {
    const std::lock_guard lock(mutex_);
    shutdown_ = true;
    request_.reset();
  }
  wake_.notify_one();
  if (worker_.joinable()) {
    worker_.join();
  }
}

void DecompilerEngine::request(DecompilerRequest request) {
  const std::lock_guard lock(mutex_);
  if (shutdown_ || request.executable_path.empty()) {
    return;
  }
  if (matching_context(*snapshot_, request) &&
      snapshot_->requested_file_address == request.file_address &&
      snapshot_->requested_load_address == request.load_address) {
    return;
  }

  const std::uint64_t serial = snapshot_->request_serial + 1;
  request_ = Request{
      .identity = std::move(request),
      .edit = std::nullopt,
      .serial = serial,
  };
  const DecompilerRequest &identity = request_->identity;
  const bool keep_existing = matching_context(*snapshot_, identity) &&
                             snapshot_->error.empty() &&
                             !snapshot_->lines.empty();
  auto loading = keep_existing
                     ? std::make_shared<DecompilerSnapshot>(*snapshot_)
                     : std::make_shared<DecompilerSnapshot>();
  set_identity(*loading, identity, serial);
  loading->loading = true;
  snapshot_ = std::move(loading);
  wake_.notify_one();
}

void DecompilerEngine::edit(DecompilerEditRequest edit) {
  const std::lock_guard lock(mutex_);
  if (shutdown_ || edit.context.executable_path.empty()) {
    return;
  }
  const std::uint64_t serial = snapshot_->request_serial + 1;
  edits_.push_back(Request{
      .identity = edit.context,
      .edit = std::move(edit),
      .serial = serial,
  });
  request_.reset();
  const auto &identity = edits_.back().identity;
  auto loading = matching_context(*snapshot_, identity)
                     ? std::make_shared<DecompilerSnapshot>(*snapshot_)
                     : std::make_shared<DecompilerSnapshot>();
  set_identity(*loading, identity, serial);
  loading->loading = true;
  loading->notice = l10n::text(l10n::Key::DecompilerApplyingEdit);
  snapshot_ = std::move(loading);
  wake_.notify_one();
}

void DecompilerEngine::cancel(std::uint64_t generation) {
  const std::lock_guard lock(mutex_);
  const std::uint64_t serial = snapshot_->request_serial + 1;
  request_.reset();
  auto cancelled = std::make_shared<DecompilerSnapshot>();
  cancelled->generation = generation;
  cancelled->request_serial = serial;
  snapshot_ = std::move(cancelled);
}

std::shared_ptr<const DecompilerSnapshot> DecompilerEngine::snapshot() const {
  const std::lock_guard lock(mutex_);
  if (sessions_ && !snapshot_->session.sha256.empty() &&
      sessions_->status(snapshot_->session.sha256).identity !=
          snapshot_->session) {
    auto cleared = std::make_shared<DecompilerSnapshot>();
    cleared->generation = snapshot_->generation;
    cleared->request_serial = snapshot_->request_serial;
    cleared->session = snapshot_->session;
    cleared->notice = l10n::text(l10n::Key::DecompilerSessionChanged);
    return cleared;
  }
  return snapshot_;
}

void DecompilerEngine::run() {
  std::vector<std::unique_ptr<LoadedCore>> cores;
  std::uint64_t loaded_generation = 0;
  const auto current_epoch = [this](const SessionIdentity &identity) {
    return !sessions_ || identity.sha256.empty() ||
           sessions_->status(identity.sha256).identity == identity;
  };

  for (;;) {
    Request work;
    {
      std::unique_lock lock(mutex_);
      wake_.wait(lock, [this] {
        return shutdown_ || !edits_.empty() || request_.has_value();
      });
      if (!edits_.empty()) {
        work = std::move(edits_.front());
        edits_.pop_front();
      } else if (shutdown_) {
        return;
      } else {
        work = std::move(*request_);
        request_.reset();
      }
      if (!work.edit && work.serial != snapshot_->request_serial) {
        continue;
      }
    }

    const DecompilerRequest &identity = work.identity;
    auto result = std::make_shared<DecompilerSnapshot>();
    set_identity(*result, identity, work.serial);
    // Never upgrade a queued edit's epoch, even when a clear completed while
    // another module was being analyzed.
    if (!current_epoch(identity.session)) {
      std::erase_if(cores, [&identity](const auto &loaded) {
        return loaded->identity.session == identity.session;
      });
      const std::lock_guard lock(mutex_);
      if (work.serial == snapshot_->request_serial) {
        result->notice = l10n::text(l10n::Key::DecompilerSessionChanged);
        snapshot_ = std::move(result);
      }
      continue;
    }

    const bool persistent = sessions_ && !identity.session.sha256.empty() &&
                            !identity.session.epoch.empty();
    const auto revision =
        persistent
            ? sessions_->status(identity.session.sha256).analysis_revision
            : identity.analysis_revision;
    if (loaded_generation != identity.generation) {
      cores.clear();
      loaded_generation = identity.generation;
    }
    // A revision rebuild removes deleted comments as well as user mutations;
    // overlaying the surviving records would leave cleared metadata behind.
    std::erase_if(cores, [&identity, revision](const auto &loaded) {
      return loaded->identity.session.sha256 == identity.session.sha256 &&
             (loaded->identity.session != identity.session ||
              loaded->identity.analysis_revision != revision);
    });
    const auto existing = std::find_if(
        cores.begin(), cores.end(), [&identity](const auto &loaded) {
          return loaded->identity.executable_path == identity.executable_path &&
                 loaded->identity.debug_info_path == identity.debug_info_path &&
                 loaded->identity.module_id == identity.module_id &&
                 loaded->identity.session == identity.session;
        });
    std::unique_ptr<LoadedCore> created;
    LoadedCore *loaded = nullptr;
    if (existing != cores.end()) {
      loaded = existing->get();
    } else {
      created = std::make_unique<LoadedCore>();
      loaded = created.get();
      loaded->identity = identity;
      loaded->identity.analysis_revision = revision;
    }
    CoreHandle &handle = loaded->handle;
    if (created) {
      std::optional<SessionData> saved;
      if (persistent) {
        try {
          saved = sessions_->read(identity.session);
          loaded->identity.analysis_revision = saved->analysis_revision;
          loaded->session_loaded = true;
        } catch (const std::exception &error) {
          append_notice(loaded->session_notice,
                        l10n::format(l10n::Key::DecompilerSessionReadFailed,
                                     error.what()));
        }
        try {
          loaded->module_sha256 =
              SessionStore::hash_file(identity.executable_path);
        } catch (const std::exception &error) {
          append_notice(loaded->session_notice,
                        l10n::format(l10n::Key::DecompilerModuleHashFailed,
                                     error.what()));
        }
      } else if (sessions_) {
        append_notice(loaded->session_notice,
                      l10n::text(l10n::Key::DecompilerSessionUnavailable));
      }
      handle.core = rz_core_new();
      if (handle.core == nullptr) {
        result->error =
            l10n::text(l10n::Key::DecompilerRizinInitializationFailed);
      } else if (!rz_core_plugin_ghidra.init(handle.core)) {
        result->error =
            l10n::text(l10n::Key::DecompilerGhidraInitializationFailed);
      } else {
        handle.plugin_initialized = true;
        rz_config_set(handle.core->config, "ghidra.sleighhome",
                      MYDBG_SLEIGH_HOME);
        rz_config_set_b(handle.core->config, "bin.dbginfo", false);
        rz_config_set_b(handle.core->config, "bin.dbginfo.debuginfod", false);
        if (!rz_core_file_open_load(handle.core,
                                    identity.executable_path.c_str(), 0,
                                    RZ_PERM_R, false)) {
          result->error = l10n::text(l10n::Key::DecompilerExecutableOpenFailed);
        } else {
          loaded->debug_info_notice = load_debug_info(*handle.core, identity);
          load_split_debug_info(*loaded);
          if (!rz_core_analysis_all(handle.core)) {
            result->error = l10n::text(l10n::Key::DecompilerAnalysisFailed);
          } else {
            handle.integrate_debug_functions();
            ensure_function(handle, identity.file_address);
            if (saved && !loaded->module_sha256.empty()) {
              restore_analysis(*loaded, *saved);
            }
          }
        }
      }
    }
    if (created && result->error.empty()) {
      cores.push_back(std::move(created));
    }
    result->analysis_revision = loaded->identity.analysis_revision;
    result->notice = loaded->debug_info_notice;
    append_notice(result->notice, loaded->session_notice);

    if (result->error.empty() && current_epoch(identity.session)) {
      // Console callbacks belong to the active core, not the previously used
      // (or just destroyed) core.
      rz_core_bind_cons(handle.core);
      RzAnalysisFunction *function =
          ensure_function(handle, identity.file_address);
      if (function == nullptr) {
        result->error = l10n::text(l10n::Key::DecompilerNoFunctionAtAddress);
      } else {
        {
          const std::lock_guard lock(mutex_);
          if (!work.edit && work.serial != snapshot_->request_serial) {
            continue;
          }
          if (!work.edit && !loaded->unpublished_edits &&
              matching_context(*snapshot_, loaded->identity) &&
              snapshot_->error.empty() && !snapshot_->lines.empty() &&
              snapshot_->function_file_address == function->addr &&
              current_epoch(identity.session)) {
            auto ready = std::make_shared<DecompilerSnapshot>(*snapshot_);
            ready->loading = false;
            snapshot_ = std::move(ready);
            continue;
          }
        }
        select_debug_context(handle, *function);
        result->function_file_address = function->addr;
        result->function_min_file_address =
            rz_analysis_function_min_addr(function);
        result->function_max_file_address =
            rz_analysis_function_max_addr(function);
        if (work.edit && current_epoch(identity.session)) {
          const auto outcome =
              apply_decompiler_edit(*handle.core, *function, *work.edit);
          append_notice(result->notice, outcome.notice);
          if (outcome.applied) {
            loaded->unpublished_edits = true;
            update_memory_hints(*loaded, *work.edit);
            if (sessions_) {
              if (!persistent || !loaded->session_loaded ||
                  loaded->module_sha256.empty()) {
                loaded->unsaved_edits = true;
                append_notice(
                    result->notice,
                    l10n::text(l10n::Key::DecompilerSessionUnavailable));
              } else if (loaded->replay_blocked || loaded->unsaved_edits) {
                append_notice(
                    result->notice,
                    l10n::text(loaded->replay_blocked
                                   ? l10n::Key::DecompilerReplayBlocked
                                   : l10n::Key::DecompilerEarlierEditUnsaved));
                loaded->unsaved_edits = true;
              } else {
                try {
                  const auto status = sessions_->append_analysis(
                      identity.session, loaded->module_sha256,
                      identity.executable_path,
                      saved_edit(*work.edit, *function));
                  if (status.analysis_revision ==
                      loaded->identity.analysis_revision + 1) {
                    // No concurrent journal/comment mutation was merged.
                    // Otherwise leave the old revision so the next request
                    // rebuilds all overrides in the durable order.
                    loaded->identity.analysis_revision =
                        status.analysis_revision;
                    result->analysis_revision = status.analysis_revision;
                  }
                } catch (const std::exception &error) {
                  loaded->unsaved_edits = true;
                  const auto notice = l10n::format(
                      l10n::Key::DecompilerSessionSaveFailed, error.what());
                  append_notice(loaded->session_notice, notice);
                  append_notice(result->notice, notice);
                }
              }
            }
          }
        }
        result->memory_hints = loaded->memory_hints;
        result->comments = loaded->comments;
        // Navigation controls publication only. Accepted edits are already
        // applied and saved even if a later request/cancel superseded them.
        {
          const std::lock_guard lock(mutex_);
          if (shutdown_ || work.serial != snapshot_->request_serial) {
            continue;
          }
        }
        if (!current_epoch(identity.session)) {
          continue;
        }
        RzAnnotatedCode *code =
            rz_ghidra_decompile_annotated_code(handle.core, function->addr);
        if (code == nullptr || code->code == nullptr) {
          result->error = l10n::text(l10n::Key::DecompilerNoCodeReturned);
        } else if (std::string_view{code->code}.starts_with(
                       "Ghidra Decompiler Error:")) {
          result->error = code->code;
        } else {
          result->lines = build_lines(*code);
          add_comment_lines(result->lines, loaded->comments, *function);
        }
        if (code != nullptr) {
          rz_annotated_code_free(code);
        }
      }
    }

    const std::lock_guard lock(mutex_);
    if (!shutdown_ && work.serial == snapshot_->request_serial &&
        current_epoch(identity.session)) {
      if (result->error.empty()) {
        loaded->unpublished_edits = false;
      }
      snapshot_ = std::move(result);
    }
  }
}

} // namespace debugger
