#include "backend/lldb/LldbInstructionCapture.h"
#include "backend/lldb/LldbEngineInternal.h"
#include "localization/Localization.h"
#if __has_include(<llvm/Config/llvm-config.h>)
#include <llvm/Config/llvm-config.h>
#endif

#include <cinttypes>
#include <rz_analysis.h>
#include <span>

namespace debugger::lldb_detail {
namespace {

InstructionFlowKind convert_flow_kind(lldb::InstructionControlFlowKind kind) {
  switch (kind) {
  case lldb::eInstructionControlFlowKindCall:
  case lldb::eInstructionControlFlowKindFarCall:
    return InstructionFlowKind::Call;
  case lldb::eInstructionControlFlowKindReturn:
  case lldb::eInstructionControlFlowKindFarReturn:
    return InstructionFlowKind::Return;
  case lldb::eInstructionControlFlowKindJump:
  case lldb::eInstructionControlFlowKindFarJump:
    return InstructionFlowKind::Jump;
  case lldb::eInstructionControlFlowKindCondJump:
    return InstructionFlowKind::ConditionalJump;
  case lldb::eInstructionControlFlowKindUnknown:
  case lldb::eInstructionControlFlowKindOther:
    return InstructionFlowKind::Other;
  }
  return InstructionFlowKind::Other;
}

std::optional<std::pair<bool, std::string>>
predict_x86_branch(const InstructionRow &row, const SessionSnapshot &state) {
  auto flags = register_numeric(state, "rflags");
  if (!flags) {
    flags = register_numeric(state, "eflags");
  }
  if (!flags || row.bytes.empty()) {
    return std::nullopt;
  }

  std::size_t opcode_index = 0;
  while (opcode_index < row.bytes.size()) {
    const std::uint8_t byte = row.bytes[opcode_index];
    if (byte == 0x66 || byte == 0x67 || byte == 0xf2 || byte == 0xf3 ||
        byte == 0x2e || byte == 0x36 || byte == 0x3e || byte == 0x26 ||
        byte == 0x64 || byte == 0x65 ||
        (state.address_byte_size == 8 && byte >= 0x40 && byte <= 0x4f)) {
      ++opcode_index;
      continue;
    }
    break;
  }
  if (opcode_index >= row.bytes.size()) {
    return std::nullopt;
  }

  std::optional<std::uint8_t> condition;
  const std::uint8_t opcode = row.bytes[opcode_index];
  if (opcode >= 0x70 && opcode <= 0x7f) {
    condition = static_cast<std::uint8_t>(opcode & 0x0fU);
  } else if (opcode == 0x0f && opcode_index + 1 < row.bytes.size() &&
             row.bytes[opcode_index + 1] >= 0x80 &&
             row.bytes[opcode_index + 1] <= 0x8f) {
    condition = static_cast<std::uint8_t>(row.bytes[opcode_index + 1] & 0x0fU);
  }
  if (!condition) {
    return std::nullopt;
  }

  const bool carry = (*flags & (1ULL << 0U)) != 0;
  const bool parity = (*flags & (1ULL << 2U)) != 0;
  const bool zero = (*flags & (1ULL << 6U)) != 0;
  const bool sign = (*flags & (1ULL << 7U)) != 0;
  const bool overflow = (*flags & (1ULL << 11U)) != 0;
  const auto prediction = [](bool taken, l10n::Key explanation) {
    return std::pair{taken, std::string{l10n::text(explanation)}};
  };
  switch (*condition) {
  case 0x0:
    return prediction(overflow, l10n::Key::SnapshotBranchOverflowSet);
  case 0x1:
    return prediction(!overflow, l10n::Key::SnapshotBranchOverflowClear);
  case 0x2:
    return prediction(carry, l10n::Key::SnapshotBranchCarrySet);
  case 0x3:
    return prediction(!carry, l10n::Key::SnapshotBranchCarryClear);
  case 0x4:
    return prediction(zero, l10n::Key::SnapshotBranchZeroSet);
  case 0x5:
    return prediction(!zero, l10n::Key::SnapshotBranchZeroClear);
  case 0x6:
    return prediction(carry || zero, l10n::Key::SnapshotBranchCarryOrZeroSet);
  case 0x7:
    return prediction(!carry && !zero,
                      l10n::Key::SnapshotBranchCarryAndZeroClear);
  case 0x8:
    return prediction(sign, l10n::Key::SnapshotBranchSignSet);
  case 0x9:
    return prediction(!sign, l10n::Key::SnapshotBranchSignClear);
  case 0xa:
    return prediction(parity, l10n::Key::SnapshotBranchParitySet);
  case 0xb:
    return prediction(!parity, l10n::Key::SnapshotBranchParityClear);
  case 0xc:
    return prediction(sign != overflow,
                      l10n::Key::SnapshotBranchSignDiffersFromOverflow);
  case 0xd:
    return prediction(sign == overflow,
                      l10n::Key::SnapshotBranchSignEqualsOverflow);
  case 0xe:
    return prediction(zero || sign != overflow,
                      l10n::Key::SnapshotBranchZeroOrSignDiffersFromOverflow);
  case 0xf:
    return prediction(!zero && sign == overflow,
                      l10n::Key::SnapshotBranchNonzeroAndSignEqualsOverflow);
  }
  return std::pair{false, std::string{}};
}

struct StaticInstructionFlow {
  bool terminates{};
  bool conditional{};
  bool returns{};
  bool unsupported{};
  unsigned delay_slots{};
  std::optional<std::uint64_t> target;
  std::optional<std::uint64_t> fallthrough;
};

namespace {

DebugSourceLocation debug_source(lldb::SBFileSpec file, std::uint32_t line,
                                 std::uint32_t column) {
  return {debug_file_path(file), line, column};
}

std::vector<DebugDeclaration> debug_declarations(lldb::SBBlock block,
                                                 lldb::SBTarget &target,
                                                 bool arguments, bool locals) {
  std::vector<DebugDeclaration> declarations;
  // The target overload exposes declarations without evaluating a location in
  // the stopped frame (which may belong to an entirely different function).
  auto values = block.GetVariables(target, arguments, locals, locals);
  declarations.reserve(values.GetSize());
  for (std::uint32_t index = 0; index < values.GetSize(); ++index) {
    auto value = values.GetValueAtIndex(index);
    if (!value.IsValid()) {
      continue;
    }
    auto type = value.GetType();
    DebugDeclaration declaration{
        safe_string(value.GetName()), safe_string(type.GetDisplayTypeName()),
        value.GetValueType() == lldb::eValueTypeVariableArgument};
    if (!declaration.name.empty() || !declaration.type.empty()) {
      declarations.push_back(std::move(declaration));
    }
  }
  return declarations;
}

// All caches live for one capture. LLDB owns parsing and address relocation;
// declarations and types are queried once per function/block, not per operand.
class InstructionDebugMetadata final {
public:
  explicit InstructionDebugMetadata(lldb::SBTarget &target) : target_(target) {}

  lldb::SBSymbolContext &context(std::uint64_t address) {
    const auto [found, inserted] = contexts_.try_emplace(address);
    if (inserted) {
      found->second = target_.ResolveLoadAddress(address).GetSymbolContext(
          lldb::eSymbolContextModule | lldb::eSymbolContextFunction |
          lldb::eSymbolContextBlock | lldb::eSymbolContextLineEntry |
          lldb::eSymbolContextSymbol);
    }
    return found->second;
  }

  std::shared_ptr<const DebugFunctionInfo> function(lldb::SBFunction function) {
    if (!function.IsValid()) {
      return {};
    }
    const auto start = function.GetStartAddress().GetLoadAddress(target_);
    if (start == LLDB_INVALID_ADDRESS) {
      return {};
    }
    const auto [found, inserted] = functions_.try_emplace(start);
    if (inserted) {
      auto info = std::make_shared<DebugFunctionInfo>();
      info->address = start;
      info->name = safe_string(function.GetName());
      auto type = function.GetType();
      info->type = safe_string(type.GetDisplayTypeName());
      info->parameters =
          debug_declarations(function.GetBlock(), target_, true, false);
      // Some producers expose a function type but omit formal-parameter DIEs.
      // Keep unnamed types unnamed; never zip ABI slots with source parameters.
      if (info->parameters.empty()) {
        auto arguments = type.GetFunctionArgumentTypes();
        for (std::uint32_t index = 0; index < arguments.GetSize(); ++index) {
          auto argument = arguments.GetTypeAtIndex(index);
          info->parameters.push_back(
              {{}, safe_string(argument.GetDisplayTypeName()), true});
        }
      }
      found->second = std::move(info);
    }
    return found->second;
  }

  void capture(InstructionRow &row) {
    auto &symbols = context(row.address);
    auto line = symbols.GetLineEntry();
    if (line.IsValid() && line.GetLine() != 0) {
      auto start = line.GetStartAddress().GetLoadAddress(target_);
      if (start == LLDB_INVALID_ADDRESS) {
        start = row.address;
      }
      const auto [found, inserted] = sources_.try_emplace(start);
      if (inserted) {
        found->second = std::make_shared<DebugSourceLocation>(
            debug_source(line.GetFileSpec(), line.GetLine(), line.GetColumn()));
      }
      row.source = found->second;
    }
    auto info = function(symbols.GetFunction());
    if (info) {
      auto block = symbols.GetBlock();
      if (!block.IsValid()) {
        block = symbols.GetFunction().GetBlock();
      }
      row.debug_scope = scope(block, info, 0);
    }
  }

  DebugDeclaration global(lldb::SBSymbolContext &symbols,
                          std::uint64_t address) {
    auto symbol = symbols.GetSymbol();
    auto module = symbols.GetModule();
    if (!symbol.IsValid() || !module.IsValid() ||
        symbols.GetFunction().IsValid()) {
      return {};
    }
    const auto start = symbol.GetStartAddress().GetLoadAddress(target_);
    if (start == LLDB_INVALID_ADDRESS || address < start) {
      return {};
    }
    auto found = globals_.find(start);
    if (found == globals_.end()) {
      found = globals_.try_emplace(start).first;
      const auto name = safe_string(symbol.GetName());
      if (!name.empty()) {
        auto values = module.FindGlobalVariables(target_, name.c_str(), 64);
        for (std::uint32_t index = 0; index < values.GetSize(); ++index) {
          auto value = values.GetValueAtIndex(index);
          // Same-name file statics can coexist. Only an address-verified
          // declaration may annotate this reference, including interior refs.
          if (value.GetAddress().GetLoadAddress(target_) != start) {
            continue;
          }
          auto type = value.GetType();
          found->second.declaration = {safe_string(value.GetName()),
                                       safe_string(type.GetDisplayTypeName()),
                                       false};
          found->second.size = type.GetByteSize();
          break;
        }
      }
    }
    return address == start || address - start < found->second.size
               ? found->second.declaration
               : DebugDeclaration{};
  }

private:
  std::shared_ptr<const DebugScopeInfo>
  scope(lldb::SBBlock block,
        const std::shared_ptr<const DebugFunctionInfo> &info, unsigned depth) {
    if (!block.IsValid() || depth == 64) {
      return {};
    }
    // SBBlock has no public identity/equality accessor. Its description carries
    // the block's opaque ID; do not parse its text for declarations or ranges.
    lldb::SBStream identity;
    block.GetDescription(identity);
    auto &blocks = scopes_[*info->address];
    const auto [found, inserted] =
        blocks.try_emplace(safe_string(identity.GetData()));
    auto &entry = found->second;
    if (inserted) {
      auto result = std::make_shared<DebugScopeInfo>();
      result->function = info;
      result->parent = scope(block.GetParent(), info, depth + 1);
      result->declarations =
          debug_declarations(block, target_, block.IsInlined(), true);
      if (block.IsInlined()) {
        result->inline_name = safe_string(block.GetInlinedName());
        result->inline_call_site = debug_source(
            block.GetInlinedCallSiteFile(), block.GetInlinedCallSiteLine(),
            block.GetInlinedCallSiteColumn());
      }
      entry = std::move(result);
    }
    return entry;
  }

  struct Global {
    DebugDeclaration declaration;
    std::uint64_t size{};
  };
  lldb::SBTarget &target_;
  std::unordered_map<std::uint64_t, lldb::SBSymbolContext> contexts_;
  std::unordered_map<std::uint64_t, std::shared_ptr<const DebugFunctionInfo>>
      functions_;
  std::unordered_map<
      std::uint64_t,
      std::unordered_map<std::string, std::shared_ptr<const DebugScopeInfo>>>
      scopes_;
  std::unordered_map<std::uint64_t, std::shared_ptr<const DebugSourceLocation>>
      sources_;
  std::unordered_map<std::uint64_t, Global> globals_;
};

void group_debug_metadata(InstructionRow &row, const InstructionRow *previous) {
  row.begins_source = row.source && (previous == nullptr || !previous->source ||
                                     *row.source != *previous->source);
  row.begins_function =
      row.debug_scope &&
      (previous == nullptr || !previous->debug_scope ||
       row.debug_scope->function != previous->debug_scope->function);
  row.begins_debug_scope =
      row.debug_scope &&
      (previous == nullptr || row.debug_scope != previous->debug_scope);
}

} // namespace

// A capture-local cache: disassembly painting never reads target memory, and
// repeated operands do not cause repeated symbol queries or pointer walks.
class InstructionReferences final {
public:
  InstructionReferences(lldb::SBTarget &target, const SessionSnapshot &state,
                        InstructionDebugMetadata &debug)
      : target_(target), process_(target.GetProcess()), state_(state),
        debug_(debug) {}

  void append(InstructionRow &row, std::uint64_t address, bool runtime,
              bool indirect = true) {
    std::array<std::uint64_t, 4> visited{};
    for (std::size_t depth = 0; depth < visited.size(); ++depth) {
      if (address == LLDB_INVALID_ADDRESS ||
          std::find(visited.begin(), visited.begin() + depth, address) !=
              visited.begin() + depth) {
        break;
      }
      visited[depth] = address;
      const CachedReference *reference = lookup(address);
      if (reference == nullptr) {
        break;
      }
      if (reference->navigable || !reference->symbol.empty() ||
          !reference->preview.empty()) {
        const auto existing =
            std::find_if(row.references.begin(), row.references.end(),
                         [address](const InstructionReference &entry) {
                           return entry.address == address;
                         });
        if (existing != row.references.end()) {
          // A static derivation is stronger than a register-dependent hint.
          existing->runtime = existing->runtime && runtime;
        } else if (row.references.size() < 12) {
          row.references.push_back(
              {address, reference->symbol, reference->preview, runtime,
               reference->declaration, reference->function});
        }
      }
      if (!indirect || !reference->preview.empty() || !reference->pointer) {
        break;
      }
      address = *reference->pointer;
    }
  }

  std::optional<std::uint64_t> pointer_at(std::uint64_t address) {
    const auto *reference = lookup(address, true);
    return reference != nullptr ? reference->pointer : std::nullopt;
  }

private:
  struct CachedReference {
    std::string symbol;
    std::string preview;
    DebugDeclaration declaration;
    std::shared_ptr<const DebugFunctionInfo> function;
    std::optional<std::uint64_t> pointer;
    bool navigable{};
    bool read_attempted{};
  };

  static std::string string_preview(const std::uint8_t *bytes,
                                    std::size_t size) {
    constexpr std::size_t maximum_characters = 96;
    std::size_t length = 0;
    std::size_t printable = 0;
    while (length < size && bytes[length] != 0) {
      const auto byte = bytes[length];
      if (byte >= 0x20 && byte <= 0x7e) {
        ++printable;
      } else if (byte != '\n' && byte != '\r' && byte != '\t' && byte != '\a' &&
                 byte != '\b' && byte != '\f' && byte != '\v') {
        return {};
      }
      ++length;
    }
    // Short unterminated reads and binary/control-heavy data are not strings.
    const bool truncated = length > maximum_characters;
    if (printable < 3 || printable * 2 < length ||
        (length == size && !truncated)) {
      return {};
    }
    std::string result;
    result.reserve(std::min(length, maximum_characters) + 8);
    result += '"';
    for (std::size_t index = 0; index < std::min(length, maximum_characters);
         ++index) {
      switch (bytes[index]) {
      case '\\':
        result += "\\\\";
        break;
      case '"':
        result += "\\\"";
        break;
      case '\n':
        result += "\\n";
        break;
      case '\r':
        result += "\\r";
        break;
      case '\t':
        result += "\\t";
        break;
      case '\a':
        result += "\\a";
        break;
      case '\b':
        result += "\\b";
        break;
      case '\f':
        result += "\\f";
        break;
      case '\v':
        result += "\\v";
        break;
      default:
        result += static_cast<char>(bytes[index]);
        break;
      }
    }
    result += '"';
    if (truncated) {
      result += "...";
    }
    return result;
  }

  const CachedReference *lookup(std::uint64_t address,
                                bool require_pointer = false) {
    auto found = cache_.find(address);
    if (found != cache_.end() &&
        (!require_pointer || found->second.read_attempted)) {
      return &found->second;
    }
    if (found == cache_.end()) {
      if (cache_.size() >= 8192) {
        return nullptr;
      }
      found = cache_.try_emplace(address).first;
      auto &symbols = debug_.context(address);
      found->second.symbol = symbol_for_address(target_, address, symbols);
      found->second.function = debug_.function(symbols.GetFunction());
      found->second.declaration = debug_.global(symbols, address);
      const auto *region = region_containing(state_, address);
      found->second.navigable =
          region != nullptr && (region->readable || region->executable);
    }
    CachedReference &reference = found->second;
    const MemoryRegionInfo *region = region_containing(state_, address);
    if (reference.read_attempted || region == nullptr || !region->readable ||
        (region->executable && !require_pointer) || remaining_reads_ == 0) {
      return &reference;
    }
    std::array<std::uint8_t, 97> bytes{};
    const auto count = static_cast<std::size_t>(
        std::min<std::uint64_t>(bytes.size(), region->end - address));
    if (count == 0) {
      return &reference;
    }
    --remaining_reads_;
    reference.read_attempted = true;
    lldb::SBError error;
    const auto read =
        process_.IsValid()
            ? process_.ReadMemory(address, bytes.data(), count, error)
            : target_.ReadMemory(target_.ResolveLoadAddress(address),
                                 bytes.data(), count, error);
    if (read == 0) {
      return &reference;
    }
    if (!region->executable) {
      reference.preview = string_preview(bytes.data(), read);
    }
    const auto width = state_.address_byte_size;
    const auto order = target_.GetByteOrder();
    if ((width == 4 || width == 8) && read >= width &&
        (order == lldb::eByteOrderLittle || order == lldb::eByteOrderBig)) {
      const auto pointer = decode_pointer(bytes.data(), width, order);
      if (const auto *destination = region_containing(state_, pointer);
          destination != nullptr &&
          (destination->readable || destination->executable)) {
        reference.pointer = pointer;
      }
    }
    return &reference;
  }

  lldb::SBTarget &target_;
  lldb::SBProcess process_;
  const SessionSnapshot &state_;
  InstructionDebugMetadata &debug_;
  std::unordered_map<std::uint64_t, CachedReference> cache_;
  std::size_t remaining_reads_{1024};
};

class InstructionAnalyzer final {
public:
  InstructionAnalyzer() : analysis_(rz_analysis_new(), &rz_analysis_free) {}

  void analyze(InstructionRow &row, lldb::SBTarget &target,
               lldb::SBProcess &process, const SessionSnapshot &state) {

    std::string failure;
    if (!configure(state, failure)) {
      ResolvedOperandInfo unavailable{};
      unavailable.role = "analysis";
      unavailable.error = std::move(failure);
      row.resolved_operands.push_back(std::move(unavailable));
      return;
    }

    RzAnalysisOp operation;
    rz_analysis_op_init(&operation);
    const int decoded = rz_analysis_op(
        analysis_.get(), &operation, static_cast<ut64>(row.address),
        row.bytes.data(), static_cast<ut64>(row.bytes.size()),
        static_cast<RzAnalysisOpMask>(RZ_ANALYSIS_OP_MASK_VAL));
    if (decoded <= 0) {
      rz_analysis_op_fini(&operation);
      ResolvedOperandInfo unavailable{};
      unavailable.role = "analysis";
      unavailable.error =
          l10n::text(l10n::Key::SnapshotInstructionDecodeFailed);
      row.resolved_operands.push_back(std::move(unavailable));
      return;
    }

    const std::uint32_t operation_type = operation.type & 0xffffU;
    if (operation_type == RZ_ANALYSIS_OP_TYPE_SWI) {
      row.flow_kind = InstructionFlowKind::Syscall;
    } else if (operation_type == RZ_ANALYSIS_OP_TYPE_CALL ||
               operation_type == RZ_ANALYSIS_OP_TYPE_UCALL) {
      row.flow_kind = InstructionFlowKind::Call;
    } else if (operation_type == RZ_ANALYSIS_OP_TYPE_RET) {
      row.flow_kind = InstructionFlowKind::Return;
    } else if (operation_type == RZ_ANALYSIS_OP_TYPE_JMP ||
               operation_type == RZ_ANALYSIS_OP_TYPE_UJMP) {
      row.flow_kind = (operation.type & RZ_ANALYSIS_OP_TYPE_COND) != 0
                          ? InstructionFlowKind::ConditionalJump
                          : InstructionFlowKind::Jump;
    }

    append_operand(row, "destination", operation.dst, target, process, state);
    for (const RzAnalysisValue *source : operation.src) {
      if (source != nullptr) {
        append_operand(row, "source", source, target, process, state);
      }
    }

    if (row.flow_kind == InstructionFlowKind::ConditionalJump) {
      row.branch.conditional = true;
      row.branch.taken_target =
          operation.jump == UT64_MAX
              ? 0
              : static_cast<std::uint64_t>(operation.jump);
      row.branch.fallthrough_target =
          operation.fail == UT64_MAX
              ? row.address + row.bytes.size()
              : static_cast<std::uint64_t>(operation.fail);
      if (is_x86_architecture(state.architecture)) {
        if (auto prediction = predict_x86_branch(row, state)) {
          row.branch.available = true;
          row.branch.taken = prediction->first;
          row.branch.explanation = std::move(prediction->second);
        } else {
          row.branch.explanation =
              l10n::text(l10n::Key::SnapshotBranchConditionUnavailable);
        }
      } else {
        row.branch.explanation =
            l10n::text(l10n::Key::SnapshotBranchArchitectureUnsupported);
      }
    }

    if (row.flow_kind == InstructionFlowKind::Call ||
        row.flow_kind == InstructionFlowKind::Syscall) {
      capture_arguments(row, target, process, state);
    }
    rz_analysis_op_fini(&operation);
  }

  bool configure_graph(const SessionSnapshot &state, std::string &failure) {
    // LLDB's public instruction API does not expose per-address ARM/Thumb
    // mode. Do not decode Thumb bytes as ARM based on the current PC's CPSR.
    if (state.address_byte_size == 4 && state.architecture.starts_with("arm")) {
      failure = l10n::text(l10n::Key::SnapshotStaticArmModeUnavailable);
      return false;
    }
    return configure(state, failure);
  }

  StaticInstructionFlow analyze_flow(InstructionRow &row,
                                     InstructionReferences *references,
                                     const SessionSnapshot &state) {
    StaticInstructionFlow flow;
    const auto lldb_target = row.flow_target;
    row.flow_target.reset();
    RzAnalysisOp operation;
    rz_analysis_op_init(&operation);
    const int decoded = rz_analysis_op(
        analysis_.get(), &operation, static_cast<ut64>(row.address),
        row.bytes.data(), static_cast<ut64>(row.bytes.size()),
        references != nullptr
            ? static_cast<RzAnalysisOpMask>(RZ_ANALYSIS_OP_MASK_BASIC |
                                            RZ_ANALYSIS_OP_MASK_VAL)
            : RZ_ANALYSIS_OP_MASK_BASIC);
    const auto operation_type = operation.type & 0xffffU;
    if (decoded <= 0 || operation.size <= 0 ||
        static_cast<std::size_t>(operation.size) != row.bytes.size() ||
        operation_type == RZ_ANALYSIS_OP_TYPE_NULL ||
        operation_type == RZ_ANALYSIS_OP_TYPE_UNK) {
      flow.terminates = true;
      flow.unsupported = true;
    } else {
      if (references != nullptr) {
        capture_references(row, operation, *references, state);
      }
      flow.conditional = (operation.type & RZ_ANALYSIS_OP_TYPE_COND) != 0;
      if (operation_type == RZ_ANALYSIS_OP_TYPE_JMP ||
          operation_type == RZ_ANALYSIS_OP_TYPE_UJMP) {
        flow.terminates = true;
        row.flow_kind = flow.conditional ? InstructionFlowKind::ConditionalJump
                                         : InstructionFlowKind::Jump;
        constexpr auto indirect = RZ_ANALYSIS_OP_TYPE_IND |
                                  RZ_ANALYSIS_OP_TYPE_REG |
                                  RZ_ANALYSIS_OP_TYPE_MEM;
        if (operation_type == RZ_ANALYSIS_OP_TYPE_JMP &&
            (operation.type & indirect) == 0 && operation.jump != UT64_MAX) {
          flow.target = operation.jump;
          row.flow_target = operation.jump;
        }
      } else if (operation_type == RZ_ANALYSIS_OP_TYPE_RET) {
        flow.terminates = true;
        flow.returns = true;
        row.flow_kind = InstructionFlowKind::Return;
      } else if (operation_type == RZ_ANALYSIS_OP_TYPE_CALL ||
                 operation_type == RZ_ANALYSIS_OP_TYPE_UCALL) {
        row.flow_kind = InstructionFlowKind::Call;
        constexpr auto indirect = RZ_ANALYSIS_OP_TYPE_IND |
                                  RZ_ANALYSIS_OP_TYPE_REG |
                                  RZ_ANALYSIS_OP_TYPE_MEM;
        if (operation_type == RZ_ANALYSIS_OP_TYPE_CALL &&
            (operation.type & indirect) == 0 && operation.jump != UT64_MAX) {
          row.flow_target = operation.jump;
        }
      } else if (operation_type == RZ_ANALYSIS_OP_TYPE_SWI) {
        row.flow_kind = InstructionFlowKind::Syscall;
      } else if (operation.eob || operation_type == RZ_ANALYSIS_OP_TYPE_ILL ||
                 operation_type == RZ_ANALYSIS_OP_TYPE_TRAP ||
                 operation_type == RZ_ANALYSIS_OP_TYPE_SWITCH ||
                 row.flow_kind == InstructionFlowKind::Jump ||
                 row.flow_kind == InstructionFlowKind::ConditionalJump ||
                 row.flow_kind == InstructionFlowKind::Return) {
        flow.terminates = true;
        flow.unsupported = true;
      }
      if (flow.terminates) {
        if (operation.delay < 0 || operation.delay > 8) {
          flow.unsupported = true;
        } else {
          flow.delay_slots = static_cast<unsigned>(operation.delay);
        }
        if (flow.conditional && operation.fail != UT64_MAX) {
          flow.fallthrough = operation.fail;
        }
      }
    }
    rz_analysis_op_fini(&operation);
    if (!row.flow_target) {
      row.flow_target = lldb_target;
      if (references != nullptr && row.flow_kind == InstructionFlowKind::Call &&
          lldb_target) {
        references->append(row, *lldb_target, false, false);
      }
    }
    return flow;
  }

private:
  bool configure(const SessionSnapshot &state, std::string &failure) {
    std::string plugin;
    if (is_x86_architecture(state.architecture)) {
      plugin = "x86";
    } else if (state.architecture.find("aarch64") != std::string::npos ||
               state.architecture.find("arm64") != std::string::npos ||
               state.architecture.starts_with("arm")) {
      plugin = "arm";
    } else if (state.architecture.find("riscv") != std::string::npos) {
      plugin = "riscv";
    } else if (state.architecture.find("mips") != std::string::npos) {
      plugin = "mips";
    } else {
      failure =
          l10n::format(l10n::Key::SnapshotAnalysisUnavailableForArchitecture,
                       state.architecture.c_str());
      return false;
    }
    const std::string configuration =
        plugin + ':' + std::to_string(state.address_byte_size * 8U) + ':' +
        state.byte_order;
    if (configuration == configuration_) {
      return true;
    }
    if (!analysis_ || !rz_analysis_use(analysis_.get(), plugin.c_str()) ||
        !rz_analysis_set_bits(analysis_.get(),
                              static_cast<int>(state.address_byte_size * 8U))) {
      failure = l10n::text(l10n::Key::SnapshotAnalysisArchitectureUnsupported);
      return false;
    }
    rz_analysis_set_big_endian(analysis_.get(),
                               state.byte_order == "big" ? 1 : 0);
    rz_analysis_set_os(analysis_.get(), "linux");
    configuration_ = configuration;
    return true;
  }

  static std::string expression_for(const RzAnalysisValue &operand) {
    if (operand.type == RZ_ANALYSIS_VAL_IMM) {
      std::ostringstream expression;
      expression << "0x" << std::hex << static_cast<std::uint64_t>(operand.imm);
      return expression.str();
    }
    std::ostringstream expression;
    if (operand.type == RZ_ANALYSIS_VAL_MEM || operand.memref != 0) {
      expression << '[';
    }
    bool has_component = false;
    if (operand.base != 0) {
      expression << "0x" << std::hex << operand.base;
      has_component = true;
    }
    if (operand.reg != nullptr && operand.reg->name != nullptr) {
      if (has_component) {
        expression << '+';
      }
      expression << operand.reg->name;
      has_component = true;
    }
    if (operand.regdelta != nullptr && operand.regdelta->name != nullptr) {
      if (has_component) {
        expression << '+';
      }
      expression << operand.regdelta->name;
      if (operand.mul > 1) {
        expression << '*' << std::dec << operand.mul;
      }
      has_component = true;
    }
    if (operand.delta != 0 || !has_component) {
      if (has_component && operand.delta >= 0) {
        expression << '+';
      }
      expression << std::showbase << std::hex << operand.delta;
    }
    if (operand.type == RZ_ANALYSIS_VAL_MEM || operand.memref != 0) {
      expression << ']';
    }
    return expression.str();
  }

  static std::optional<std::uint64_t>
  evaluate_operand(const RzAnalysisValue &operand, const InstructionRow &row,
                   const SessionSnapshot &state, bool &runtime,
                   std::string *failure = nullptr) {
    if (operand.type == RZ_ANALYSIS_VAL_IMM) {
      return static_cast<std::uint64_t>(operand.imm);
    }
    const bool x86 = is_x86_architecture(state.architecture);
    const bool memory =
        operand.type == RZ_ANALYSIS_VAL_MEM || operand.memref != 0;
    const auto unavailable = [failure](std::string_view reason) {
      if (failure != nullptr) {
        *failure = reason;
      }
    };
    const auto register_value =
        [&](const RzRegItem *reg) -> std::optional<std::uint64_t> {
      if (reg == nullptr) {
        return 0;
      }
      if (reg->name == nullptr) {
        return std::nullopt;
      }
      const std::string_view name{reg->name};
      if (x86 && memory && (name == "rip" || name == "eip")) {
        // Rizin src/dst displacements exclude the instruction length.
        const auto next = row.address + row.bytes.size();
        return name == "eip" ? static_cast<std::uint32_t>(next) : next;
      }
      if (row.address != state.pc || state.state != SessionState::Stopped) {
        return std::nullopt;
      }
      runtime = true;
      if (auto value = register_numeric(state, name)) {
        return value;
      }
      if (x86 && reg->size == 32) {
        constexpr std::array<std::pair<std::string_view, std::string_view>, 16>
            aliases{{{"eax", "rax"},
                     {"ebx", "rbx"},
                     {"ecx", "rcx"},
                     {"edx", "rdx"},
                     {"esi", "rsi"},
                     {"edi", "rdi"},
                     {"esp", "rsp"},
                     {"ebp", "rbp"},
                     {"r8d", "r8"},
                     {"r9d", "r9"},
                     {"r10d", "r10"},
                     {"r11d", "r11"},
                     {"r12d", "r12"},
                     {"r13d", "r13"},
                     {"r14d", "r14"},
                     {"r15d", "r15"}}};
        for (const auto &[alias, full] : aliases) {
          if (name == alias) {
            if (auto value = register_numeric(state, full)) {
              return static_cast<std::uint32_t>(*value);
            }
            break;
          }
        }
      }
      return std::nullopt;
    };
    // Some non-x86 plugins omit index extension/shift metadata. Do not
    // manufacture an effective address from an incomplete expression.
    if (!x86 && memory && operand.regdelta != nullptr) {
      unavailable(l10n::text(l10n::Key::SnapshotIndexedAddressIncomplete));
      return std::nullopt;
    }
    const auto base = register_value(operand.reg);
    const auto index = register_value(operand.regdelta);
    if (!base || !index) {
      unavailable(l10n::text(l10n::Key::SnapshotRegisterValueUnavailable));
      return std::nullopt;
    }
    std::uint64_t value = operand.base + *base +
                          *index * std::max<std::uint64_t>(1, operand.mul) +
                          static_cast<std::uint64_t>(operand.delta);
    if (state.address_byte_size == 4 ||
        (x86 && memory &&
         ((operand.reg != nullptr && operand.reg->size == 32) ||
          (operand.regdelta != nullptr && operand.regdelta->size == 32)))) {
      value = static_cast<std::uint32_t>(value);
    }
    if (memory && operand.seg != nullptr) {
      const std::string_view segment =
          operand.seg->name != nullptr ? operand.seg->name : "";
      if (!x86 || state.address_byte_size != 8 ||
          (segment != "cs" && segment != "ds" && segment != "es" &&
           segment != "ss" && segment != "fs" && segment != "gs")) {
        unavailable(l10n::text(l10n::Key::SnapshotSegmentBaseUnavailable));
        return std::nullopt;
      }
      if (segment == "fs" || segment == "gs") {
        if (row.address != state.pc || state.state != SessionState::Stopped) {
          return std::nullopt;
        }
        auto segment_base =
            register_numeric(state, segment == "fs" ? "fs_base" : "gs_base");
        if (!segment_base) {
          segment_base =
              register_numeric(state, segment == "fs" ? "fsbase" : "gsbase");
        }
        if (!segment_base) {
          unavailable(l10n::text(l10n::Key::SnapshotSegmentBaseUnavailable));
          return std::nullopt;
        }
        runtime = true;
        value += *segment_base;
      }
    }
    return value;
  }

  static void capture_references(InstructionRow &row,
                                 const RzAnalysisOp &operation,
                                 InstructionReferences &references,
                                 const SessionSnapshot &state) {
    const auto type = operation.type & 0xffffU;
    constexpr auto indirect = RZ_ANALYSIS_OP_TYPE_IND |
                              RZ_ANALYSIS_OP_TYPE_REG | RZ_ANALYSIS_OP_TYPE_MEM;
    if ((type == RZ_ANALYSIS_OP_TYPE_CALL || type == RZ_ANALYSIS_OP_TYPE_JMP) &&
        (operation.type & indirect) == 0 && operation.jump != UT64_MAX) {
      references.append(row, operation.jump, false, false);
    }
    const auto append_value = [&](const RzAnalysisValue *operand,
                                  bool destination) {
      if (operand == nullptr || operand->type == RZ_ANALYSIS_VAL_UNK ||
          (destination && operand->type == RZ_ANALYSIS_VAL_REG &&
           operand->memref == 0)) {
        return;
      }
      bool runtime = false;
      if (const auto address =
              evaluate_operand(*operand, row, state, runtime)) {
        references.append(row, *address, runtime);
      }
    };
    append_value(operation.dst, true);
    for (const auto *source : operation.src) {
      append_value(source, false);
    }

    const bool x86 = is_x86_architecture(state.architecture);
    const bool control =
        type == RZ_ANALYSIS_OP_TYPE_CALL || type == RZ_ANALYSIS_OP_TYPE_UCALL ||
        type == RZ_ANALYSIS_OP_TYPE_JMP || type == RZ_ANALYSIS_OP_TYPE_UJMP;
    // The x86 plugin has no src/dst values for indirect calls and jumps.
    // Its access list does include their complete memory operands (including
    // segments and scaled indexes), unlike operation.ptr, which can be only
    // a displacement. Ignore implicit stack writes.
    if (x86 && control) {
      std::optional<std::uint64_t> target_slot;
      bool target_runtime = false;
      std::size_t memory_operands = 0;
      for (const RzListIter *iterator = rz_list_head(operation.access);
           iterator != nullptr; iterator = iterator->next) {
        const auto *access =
            static_cast<const RzAnalysisValue *>(iterator->elem);
        if (access->type != RZ_ANALYSIS_VAL_MEM ||
            access->access == RZ_ANALYSIS_ACC_W) {
          continue;
        }
        ++memory_operands;
        RzAnalysisValue operand = *access;
        if (operand.reg != nullptr && operand.reg->name != nullptr &&
            (std::string_view{operand.reg->name} == "rip" ||
             std::string_view{operand.reg->name} == "eip")) {
          // Unlike src/dst values, access-list PC displacements for these
          // single-operand instructions already include the instruction size.
          operand.delta -= static_cast<st64>(row.bytes.size());
        }
        bool runtime = false;
        if (const auto address =
                evaluate_operand(operand, row, state, runtime)) {
          references.append(row, *address, runtime);
          if (operand.memref > 0 &&
              static_cast<std::uint32_t>(operand.memref) ==
                  state.address_byte_size) {
            target_slot = *address;
            target_runtime = runtime;
          }
        }
      }
      if (memory_operands == 1 && target_slot &&
          (type == RZ_ANALYSIS_OP_TYPE_UCALL ||
           type == RZ_ANALYSIS_OP_TYPE_UJMP ||
           (operation.type & indirect) != 0)) {
        // The branch consumes exactly one pointer, not the last symbol in
        // a pointer walk. Reuse the capture cache even for executable slots.
        row.flow_target = references.pointer_at(*target_slot);
        if (row.flow_target) {
          references.append(row, *row.flow_target, target_runtime, false);
        }
      }
    }
    // Rizin's explicit register destination is authoritative for register
    // branches (also AArch64 BR/BLR); a memory base register is not a target.
    if (control && operation.reg != nullptr && operation.ptr == -1 &&
        (operation.type & RZ_ANALYSIS_OP_TYPE_REG) != 0 &&
        (operation.type &
         (RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_MEM)) == 0 &&
        row.address == state.pc && state.state == SessionState::Stopped) {
      if (auto value = register_numeric(state, operation.reg)) {
        if (state.address_byte_size == 4) {
          *value = static_cast<std::uint32_t>(*value);
        }
        const auto *region = region_containing(state, *value);
        if (region != nullptr && (region->readable || region->executable)) {
          row.flow_target = *value;
        }
        references.append(row, *value, true);
      }
    }
    // Immediate PUSH has no src/dst values either. For other architectures,
    // only a LEA's decoded address is safe: LOAD ptr can be a bare
    // displacement.
    if (operation.ptr != -1 && ((x86 && type == RZ_ANALYSIS_OP_TYPE_PUSH) ||
                                (!x86 && type == RZ_ANALYSIS_OP_TYPE_LEA))) {
      references.append(row, static_cast<std::uint64_t>(operation.ptr), false);
    }
  }

  static void append_operand(InstructionRow &row, std::string role,
                             const RzAnalysisValue *operand,
                             lldb::SBTarget &target, lldb::SBProcess &process,
                             const SessionSnapshot &state) {
    if (operand == nullptr || operand->type == RZ_ANALYSIS_VAL_UNK) {
      return;
    }
    ResolvedOperandInfo resolved{};
    resolved.role = std::move(role);
    resolved.expression = expression_for(*operand);
    resolved.memory =
        operand->type == RZ_ANALYSIS_VAL_MEM || operand->memref != 0;
    bool runtime = false;
    const auto value =
        evaluate_operand(*operand, row, state, runtime, &resolved.error);
    if (value) {
      resolved.value = *value;
      resolved.has_value = true;
      if (resolved.memory ||
          region_containing(state, resolved.value) != nullptr) {
        resolved.pointer_chain =
            resolve_pointer_chain(target, process, state, resolved.value);
      }
    }
    row.resolved_operands.push_back(std::move(resolved));
  }

  static void append_register_argument(InstructionRow &row,
                                       std::string_view name,
                                       lldb::SBTarget &target,
                                       lldb::SBProcess &process,
                                       const SessionSnapshot &state) {
    AbiArgumentInfo argument{};
    argument.name = name;
    if (const auto value = register_numeric(state, name)) {
      argument.value = *value;
      argument.available = true;
      if (region_containing(state, *value) != nullptr) {
        argument.pointer_chain =
            resolve_pointer_chain(target, process, state, *value);
      }
    } else {
      argument.error = l10n::text(l10n::Key::SnapshotRegisterUnavailable);
    }
    row.arguments.push_back(std::move(argument));
  }
  static void append_stack_argument(InstructionRow &row, std::size_t index,
                                    lldb::SBTarget &target,
                                    lldb::SBProcess &process,
                                    const SessionSnapshot &state) {
    AbiArgumentInfo argument{};
    argument.name = "arg" + std::to_string(index);
    const std::uint32_t width = state.address_byte_size;
    if (width == 0 || width > sizeof(std::uint64_t) ||
        state.sp >
            std::numeric_limits<std::uint64_t>::max() - (index + 1U) * width) {
      argument.error =
          l10n::text(l10n::Key::SnapshotStackArgumentAddressUnavailable);
      row.arguments.push_back(std::move(argument));
      return;
    }
    std::array<std::uint8_t, sizeof(std::uint64_t)> bytes{};
    lldb::SBError error;
    const std::uint64_t address = state.sp + (index + 1U) * width;
    const std::size_t read =
        process.ReadMemory(address, bytes.data(), width, error);
    if (read != width || error.Fail()) {
      argument.error = error.Fail()
                           ? error_text(error)
                           : l10n::text(l10n::Key::SnapshotShortArgumentRead);
    } else {
      argument.value =
          decode_pointer(bytes.data(), width, target.GetByteOrder());
      argument.available = true;
      if (region_containing(state, argument.value) != nullptr) {
        argument.pointer_chain =
            resolve_pointer_chain(target, process, state, argument.value);
      }
    }
    row.arguments.push_back(std::move(argument));
  }

  static void capture_arguments(InstructionRow &row, lldb::SBTarget &target,
                                lldb::SBProcess &process,
                                const SessionSnapshot &state) {
    static constexpr std::array<std::string_view, 6> x86_call{
        "rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    static constexpr std::array<std::string_view, 6> x86_syscall{
        "rdi", "rsi", "rdx", "r10", "r8", "r9"};
    static constexpr std::array<std::string_view, 7> x86_32_syscall{
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"};
    static constexpr std::array<std::string_view, 8> arm64{
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
    static constexpr std::array<std::string_view, 6> arm{"r0", "r1", "r2",
                                                         "r3", "r4", "r5"};
    static constexpr std::array<std::string_view, 8> arguments{
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"};
    const bool syscall = row.flow_kind == InstructionFlowKind::Syscall;
    std::string_view syscall_register;
    std::span<const std::string_view> registers;
    if (state.architecture == "x86_64") {
      syscall_register = "rax";
      registers = syscall ? x86_syscall : x86_call;
    } else if (is_x86_architecture(state.architecture)) {
      if (!syscall) {
        for (std::size_t index = 0; index < 6; ++index) {
          append_stack_argument(row, index, target, process, state);
        }
        return;
      }
      registers = x86_32_syscall;
    } else if (state.architecture.find("aarch64") != std::string::npos ||
               state.architecture.find("arm64") != std::string::npos) {
      syscall_register = "x8";
      registers = std::span{arm64}.first(syscall ? 6 : 8);
    } else if (state.architecture.starts_with("arm")) {
      syscall_register = "r7";
      registers = std::span{arm}.first(syscall ? 6 : 4);
    } else if (state.architecture.find("riscv") != std::string::npos) {
      syscall_register = "a7";
      registers = std::span{arguments}.first(syscall ? 6 : 8);
    } else if (state.architecture.find("mips") != std::string::npos) {
      syscall_register = "v0";
      registers = std::span{arguments}.first(4);
    }
    if (syscall && !syscall_register.empty()) {
      append_register_argument(row, syscall_register, target, process, state);
    }
    for (const std::string_view name : registers) {
      append_register_argument(row, name, target, process, state);
    }
  }

  std::unique_ptr<RzAnalysis, decltype(&rz_analysis_free)> analysis_;
  std::string configuration_;
};

InstructionRow capture_instruction_row(lldb::SBInstruction instruction,
                                       lldb::SBTarget &target) {
  InstructionRow row;
  const lldb::SBAddress instruction_address = instruction.GetAddress();
  row.address = instruction_address.GetLoadAddress(target);
  const lldb::addr_t file_address = instruction_address.GetFileAddress();
  if (file_address != LLDB_INVALID_ADDRESS) {
    row.file_address = file_address;
    row.has_file_address = true;
  }
  row.mnemonic = safe_string(instruction.GetMnemonic(target));
  row.operands = safe_string(instruction.GetOperands(target));
  row.comment = safe_string(instruction.GetComment(target));
  row.flow_kind = convert_flow_kind(instruction.GetControlFlowKind(target));
  if (row.flow_kind == InstructionFlowKind::Call ||
      row.flow_kind == InstructionFlowKind::Jump ||
      row.flow_kind == InstructionFlowKind::ConditionalJump) {
    // LLDB already rendered this instruction in its per-address ISA mode.
    // Accept only a complete absolute destination, never a displacement or
    // an indirect expression. Conditional branches may have preceding
    // register/condition operands (CBZ, BEQ, etc.).
    auto operand = trim(row.operands);
    const bool indirect =
        operand.find_first_of("*[](){}!:+-/") != std::string_view::npos ||
        operand.find("ptr") != std::string_view::npos ||
        row.mnemonic.find("lr") != std::string::npos ||
        row.mnemonic.find("ctr") != std::string::npos ||
        row.mnemonic.find("tar") != std::string::npos;
    if (!indirect && row.flow_kind == InstructionFlowKind::ConditionalJump) {
      if (const auto comma = operand.rfind(',');
          comma != std::string_view::npos) {
        operand = trim(operand.substr(comma + 1));
      }
    }
    if (!indirect && (operand.starts_with("0x") || operand.starts_with("0X"))) {
      row.flow_target = parse_integer(operand);
      if (row.flow_target == LLDB_INVALID_ADDRESS) {
        row.flow_target.reset();
      }
    }
  }

  lldb::SBData data = instruction.GetData(target);
  const std::size_t byte_count = data.GetByteSize();
  row.bytes.resize(byte_count);
  if (byte_count != 0) {
    lldb::SBError data_error;
    const std::size_t bytes_read =
        data.ReadRawData(data_error, 0, row.bytes.data(), byte_count);
    if (data_error.Fail()) {
      row.bytes.clear();
    } else {
      row.bytes.resize(bytes_read);
    }
  }
  return row;
}

} // namespace

void capture_instructions(lldb::SBTarget &target, lldb::addr_t start_address,
                          SessionSnapshot &state) {
  state.instructions.clear();
  state.disassembly_graph.reset();
  const lldb::SBAddress address = target.ResolveLoadAddress(start_address);
  if (!address.IsValid()) {
    return;
  }

  lldb::SBInstructionList instructions =
      state.supports_intel_syntax
          ? target.ReadInstructions(address, 48,
                                    state.intel_syntax ? "intel" : "att")
          : target.ReadInstructions(address, 48);
  const std::size_t instruction_count = instructions.GetSize();
  state.instructions.reserve(instruction_count);
  static thread_local InstructionAnalyzer analyzer;
  InstructionDebugMetadata debug(target);
  InstructionReferences references(target, state, debug);
  std::string failure;
  const bool configured = analyzer.configure_graph(state, failure);
  lldb::SBProcess process = target.GetProcess();
  for (std::size_t index = 0; index < instruction_count; ++index) {
    state.instructions.push_back(capture_instruction_row(
        instructions.GetInstructionAtIndex(static_cast<std::uint32_t>(index)),
        target));
    auto &row = state.instructions.back();
    if (configured) {
      analyzer.analyze_flow(row, &references, state);
    }
    if (row.address == state.pc && state.state == SessionState::Stopped) {
      analyzer.analyze(row, target, process, state);
    }
    debug.capture(row);
    if (!configured && row.flow_kind == InstructionFlowKind::Call &&
        row.flow_target) {
      references.append(row, *row.flow_target, false, false);
    }
    group_debug_metadata(row,
                         index == 0 ? nullptr : &state.instructions[index - 1]);
  }
}

void capture_disassembly_graph(lldb::SBTarget &target,
                               lldb::addr_t requested_address,
                               SessionSnapshot &state) {
  constexpr std::size_t maximum_bytes = 64 * 1024;
  constexpr std::size_t maximum_instructions = 4096;
  constexpr std::size_t fallback_bytes = 4096;
  constexpr std::size_t fallback_instructions = 256;
  auto graph = std::make_shared<DisassemblyGraph>();
  graph->address = requested_address;
  const auto partial = [&graph](std::string_view reason) {
    if (graph->status.find(reason) != std::string::npos) {
      return;
    }
    graph->status += graph->status.empty()
                         ? l10n::text(l10n::Key::SnapshotPartialGraphPrefix)
                         : "; ";
    graph->status += reason;
  };
  lldb::SBAddress requested = target.ResolveLoadAddress(requested_address);
  if (!requested.IsValid()) {
    graph->status = l10n::text(l10n::Key::SnapshotGraphAddressUnresolved);
    state.disassembly_graph = std::move(graph);
    return;
  }

  struct AddressRange {
    std::uint64_t start;
    std::uint64_t end;
  };
  std::vector<AddressRange> ranges;
  lldb::SBFunction function = requested.GetFunction();
  if (function.IsValid()) {
    graph->name = safe_string(function.GetName());
#if defined(LLVM_VERSION_MAJOR) && LLVM_VERSION_MAJOR >= 21
    constexpr std::uint32_t maximum_ranges = 128;
    lldb::SBAddressRangeList function_ranges = function.GetRanges();
    const std::uint32_t count = function_ranges.GetSize();
    if (count > maximum_ranges) {
      partial(l10n::text(l10n::Key::SnapshotGraphRangeLimitReached));
    }
    for (std::uint32_t index = 0; index < std::min(count, maximum_ranges);
         ++index) {
      lldb::SBAddressRange range =
          function_ranges.GetAddressRangeAtIndex(index);
      const auto start = range.GetBaseAddress().GetLoadAddress(target);
      const auto size = range.GetByteSize();
      if (start != LLDB_INVALID_ADDRESS && size != 0 &&
          size <= std::numeric_limits<std::uint64_t>::max() - start) {
        ranges.push_back({start, start + size});
      } else {
        partial(l10n::text(l10n::Key::SnapshotGraphRangesUnavailable));
      }
    }
#else
    const auto start = function.GetStartAddress().GetLoadAddress(target);
    const auto end = function.GetEndAddress().GetLoadAddress(target);
    if (start != LLDB_INVALID_ADDRESS && end != LLDB_INVALID_ADDRESS &&
        start <= requested_address && requested_address < end) {
      ranges.push_back({start, end});
    } else {
      partial(l10n::text(l10n::Key::SnapshotGraphRangesUnavailable));
    }
#endif
  }
  if (ranges.empty()) {
    lldb::SBSymbol symbol = requested.GetSymbol();
    if (symbol.IsValid()) {
      graph->name = safe_string(symbol.GetName());
      const auto start = symbol.GetStartAddress().GetLoadAddress(target);
      const auto end = symbol.GetEndAddress().GetLoadAddress(target);
      if (start != LLDB_INVALID_ADDRESS && end != LLDB_INVALID_ADDRESS &&
          start <= requested_address && requested_address < end) {
        ranges.push_back({start, end});
      }
    }
  }
  const bool bounded_function = !ranges.empty();
  if (!bounded_function) {
    partial(l10n::text(l10n::Key::SnapshotGraphBoundsUnavailable));
    const auto size = std::min<std::uint64_t>(
        fallback_bytes,
        std::numeric_limits<std::uint64_t>::max() - requested_address);
    ranges.push_back({requested_address, requested_address + size});
  }
  std::sort(ranges.begin(), ranges.end(),
            [](const AddressRange &left, const AddressRange &right) {
              return left.start < right.start;
            });
  // Merge overlapping debug-info ranges, without inventing instructions in
  // the holes between discontiguous hot/cold fragments.
  std::size_t merged_count = 0;
  for (const AddressRange range : ranges) {
    if (merged_count != 0 && range.start <= ranges[merged_count - 1].end) {
      ranges[merged_count - 1].end =
          std::max(ranges[merged_count - 1].end, range.end);
    } else {
      ranges[merged_count++] = range;
    }
  }
  ranges.resize(merged_count);
  graph->address = ranges.front().start;
  const auto instruction_limit =
      bounded_function ? maximum_instructions : fallback_instructions;
  std::vector<InstructionRow> rows;
  std::size_t remaining_bytes = maximum_bytes;
  for (const AddressRange range : ranges) {
    if (remaining_bytes == 0 || rows.size() == instruction_limit) {
      partial(l10n::text(l10n::Key::SnapshotGraphCaptureLimitReached));
      break;
    }
    const auto byte_count = static_cast<std::size_t>(
        std::min<std::uint64_t>(range.end - range.start, remaining_bytes));
    if (byte_count < range.end - range.start) {
      partial(l10n::text(l10n::Key::SnapshotGraphByteLimitReached));
    }
    std::vector<std::uint8_t> bytes(byte_count);
    lldb::SBAddress base = target.ResolveLoadAddress(range.start);
    lldb::SBError read_error;
    const auto bytes_read =
        target.ReadMemory(base, bytes.data(), bytes.size(), read_error);
    remaining_bytes -= byte_count;
    if (bytes_read != byte_count || read_error.Fail()) {
      partial(l10n::text(l10n::Key::SnapshotGraphBytesUnreadable));
    }
    if (bytes_read == 0) {
      continue;
    }
    lldb::SBInstructionList instructions =
        state.supports_intel_syntax
            ? target.GetInstructionsWithFlavor(
                  base, state.intel_syntax ? "intel" : "att", bytes.data(),
                  bytes_read)
            : target.GetInstructions(base, bytes.data(), bytes_read);
    auto expected_address = range.start;
    for (std::uint32_t index = 0; index < instructions.GetSize(); ++index) {
      if (rows.size() == instruction_limit) {
        partial(
            bounded_function
                ? l10n::text(l10n::Key::SnapshotGraphInstructionLimitReached)
                : l10n::text(l10n::Key::SnapshotGraphFallbackLimitReached));
        break;
      }
      InstructionRow row = capture_instruction_row(
          instructions.GetInstructionAtIndex(index), target);
      if (row.address != expected_address || row.bytes.empty() ||
          row.bytes.size() > range.start + bytes_read - expected_address) {
        partial(l10n::text(l10n::Key::SnapshotGraphDecodingStopped));
        break;
      }
      expected_address += row.bytes.size();
      rows.push_back(std::move(row));
    }
    if (expected_address != range.end) {
      partial(l10n::text(l10n::Key::SnapshotGraphBytesNotDecoded));
    }
  }
  if (rows.empty()) {
    partial(l10n::text(l10n::Key::SnapshotGraphInstructionsUnavailable));
    state.disassembly_graph = std::move(graph);
    return;
  }

  InstructionAnalyzer analyzer;
  InstructionDebugMetadata debug(target);
  InstructionReferences references(target, state, debug);
  std::string failure;
  const bool configured = analyzer.configure_graph(state, failure);
  if (!configured) {
    partial(failure);
  }
  std::vector<StaticInstructionFlow> flows;
  flows.reserve(rows.size());
  std::vector<bool> leaders(rows.size(), false);
  leaders.front() = true;
  for (std::size_t index = 0; index < rows.size(); ++index) {
    // Reuse flat-view hints without rereading their operands; this also keeps
    // the views identical if the larger graph reaches its bounded read budget.
    const auto flat =
        std::lower_bound(state.instructions.begin(), state.instructions.end(),
                         rows[index].address,
                         [](const InstructionRow &row, std::uint64_t address) {
                           return row.address < address;
                         });
    const bool reuse = flat != state.instructions.end() &&
                       flat->address == rows[index].address &&
                       flat->bytes == rows[index].bytes;
    flows.push_back(configured
                        ? analyzer.analyze_flow(
                              rows[index], reuse ? nullptr : &references, state)
                        : StaticInstructionFlow{});
    if (reuse) {
      rows[index].flow_target = flat->flow_target;
      rows[index].references = flat->references;
    }
    debug.capture(rows[index]);
    if (!configured && !reuse &&
        rows[index].flow_kind == InstructionFlowKind::Call &&
        rows[index].flow_target) {
      references.append(rows[index], *rows[index].flow_target, false, false);
    }
    group_debug_metadata(rows[index], index == 0 ? nullptr : &rows[index - 1]);
    if (index != 0 && rows[index - 1].address + rows[index - 1].bytes.size() !=
                          rows[index].address) {
      leaders[index] = true;
    }
  }
  const std::size_t no_instruction = rows.size();
  std::vector<std::size_t> terminators(rows.size(), no_instruction);
  std::vector<std::size_t> delay_owners(rows.size(), no_instruction);
  for (std::size_t index = 0; index < rows.size(); ++index) {
    StaticInstructionFlow &flow = flows[index];
    if (!flow.terminates) {
      continue;
    }
    auto end = index;
    for (unsigned slot = 0; slot < flow.delay_slots; ++slot) {
      if (end + 1 == rows.size() || leaders[end + 1] ||
          flows[end + 1].terminates ||
          rows[end + 1].flow_kind == InstructionFlowKind::Call) {
        flow.unsupported = true;
        partial(l10n::text(l10n::Key::SnapshotGraphDelaySlotUnsupported));
        end = index;
        break;
      }
      ++end;
    }
    if (flow.unsupported) {
      partial(l10n::text(l10n::Key::SnapshotGraphInstructionFlowUnsupported));
    } else {
      for (auto slot = index + 1; slot <= end; ++slot) {
        delay_owners[slot] = index;
      }
      if (flow.conditional && flow.delay_slots != 0) {
        // Rizin's basic operation records delay count, but not whether a
        // conditional instruction annuls the slot on its untaken path.
        partial(
            l10n::text(l10n::Key::SnapshotGraphDelaySlotAnnulmentUnsupported));
      }
    }
    const auto continuation = rows[end].address + rows[end].bytes.size();
    if (flow.conditional &&
        (!flow.fallthrough ||
         (flow.delay_slots != 0 && *flow.fallthrough < continuation))) {
      // Some Rizin plugins report fail at the delay instruction itself.
      flow.fallthrough = continuation;
    }
    terminators[end] = index;
    if (end + 1 < rows.size()) {
      leaders[end + 1] = true;
    }
  }
  const auto mark_destination = [&](std::optional<std::uint64_t> &address) {
    if (!address) {
      return;
    }
    const auto found =
        std::lower_bound(rows.begin(), rows.end(), *address,
                         [](const InstructionRow &row, std::uint64_t value) {
                           return row.address < value;
                         });
    if (found != rows.end() && found->address == *address) {
      leaders[static_cast<std::size_t>(found - rows.begin())] = true;
    } else if (found != rows.begin()) {
      const InstructionRow &previous = *(found - 1);
      if (*address < previous.address + previous.bytes.size()) {
        partial(l10n::text(l10n::Key::SnapshotGraphBranchEntersInstruction));
        address.reset();
      }
    }
  };
  for (StaticInstructionFlow &flow : flows) {
    if (!flow.unsupported) {
      mark_destination(flow.target);
      mark_destination(flow.fallthrough);
    }
  }
  for (std::size_t index = 0; index < rows.size(); ++index) {
    if (!leaders[index] || delay_owners[index] == no_instruction) {
      continue;
    }
    const auto owner = delay_owners[index];
    flows[owner].unsupported = true;
    partial(l10n::text(l10n::Key::SnapshotGraphDelaySlotBranchUnsupported));
    for (auto end = owner + 1; end < rows.size() && delay_owners[end] == owner;
         ++end) {
      terminators[end] = no_instruction;
    }
    terminators[owner] = owner;
    leaders[owner + 1] = true;
  }
  for (std::size_t start = 0; start < rows.size();) {
    auto end = start + 1;
    while (end < rows.size() && !leaders[end]) {
      ++end;
    }
    DisassemblyGraphBlock block;
    block.address = rows[start].address;
    // A block is also an independent reading entry point; retain its source
    // location even when the preceding block ended on the same source line.
    rows[start].begins_source = rows[start].source != nullptr;
    const auto last = end - 1;
    const auto continuation = rows[last].address + rows[last].bytes.size();
    if (configured) {
      if (terminators[last] != no_instruction) {
        const StaticInstructionFlow &flow = flows[terminators[last]];
        if (flow.unsupported) {
          block.edges.push_back(
              {DisassemblyGraphEdge::Kind::Jump, std::nullopt});
        } else if (flow.conditional) {
          block.edges.push_back(
              {DisassemblyGraphEdge::Kind::Taken, flow.target});
          block.edges.push_back(
              {DisassemblyGraphEdge::Kind::Fallthrough, flow.fallthrough});
        } else if (!flow.returns) {
          block.edges.push_back(
              {DisassemblyGraphEdge::Kind::Jump, flow.target});
        }
        if (!flow.returns && !flow.target) {
          partial(
              l10n::text(l10n::Key::SnapshotGraphIndirectBranchesUnresolved));
        }
      } else {
        block.edges.push_back(
            {DisassemblyGraphEdge::Kind::Fallthrough, continuation});
      }
    }
    block.instructions.reserve(end - start);
    for (auto index = start; index < end; ++index) {
      block.instructions.push_back(std::move(rows[index]));
    }
    graph->blocks.push_back(std::move(block));
    start = end;
  }
  state.disassembly_graph = std::move(graph);
}

} // namespace debugger::lldb_detail
