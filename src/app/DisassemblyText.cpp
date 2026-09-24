#include "app/DisassemblyText.h"
#include "app/AppActions.h"
#include "localization/Localization.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cinttypes>
#include <cstdio>

namespace mydbg::app {
namespace {

using Kind = DisassemblyTokenKind;

enum class Architecture {
  X86,
  Arm,
  Arm64,
  RiscV,
  Mips,
  PowerPC,
  Sparc,
  LoongArch,
  SystemZ,
  Other
};

Architecture assembly_architecture(std::string_view name) {
  if (name.starts_with("x86") || name == "amd64" || name == "i386" ||
      name == "i486" || name == "i586" || name == "i686") {
    return Architecture::X86;
  }
  if (name.starts_with("aarch64") || name.starts_with("arm64")) {
    return Architecture::Arm64;
  }
  if (name.starts_with("arm") || name.starts_with("thumb")) {
    return Architecture::Arm;
  }
  if (name.starts_with("riscv"))
    return Architecture::RiscV;
  if (name.starts_with("mips"))
    return Architecture::Mips;
  if (name.starts_with("powerpc") || name.starts_with("ppc")) {
    return Architecture::PowerPC;
  }
  if (name.starts_with("sparc"))
    return Architecture::Sparc;
  if (name.starts_with("loongarch"))
    return Architecture::LoongArch;
  if (name.starts_with("s390") || name.starts_with("systemz")) {
    return Architecture::SystemZ;
  }
  return Architecture::Other;
}

bool one_of(std::string_view word,
            std::initializer_list<std::string_view> choices) {
  return std::find(choices.begin(), choices.end(), word) != choices.end();
}

bool numbered(std::string_view word, std::string_view prefix, unsigned maximum,
              unsigned minimum = 0) {
  if (!word.starts_with(prefix))
    return false;
  word.remove_prefix(prefix.size());
  if (word.empty() || (word.size() > 1 && word.front() == '0'))
    return false;
  unsigned value{};
  const auto result =
      std::from_chars(word.data(), word.data() + word.size(), value);
  return result.ec == std::errc{} && result.ptr == word.data() + word.size() &&
         value >= minimum && value <= maximum;
}

bool assembly_register(std::string_view word, Architecture architecture) {
  const bool dollar_register = word.starts_with('$');
  if (!word.empty() && (word.front() == '%' || word.front() == '$')) {
    word.remove_prefix(1);
  }
  // Register names are short ASCII identifiers. Never search inside a symbol.
  std::array<char, 32> lower{};
  if (word.empty() || word.size() >= lower.size())
    return false;
  for (std::size_t i = 0; i < word.size(); ++i) {
    lower[i] =
        static_cast<char>(std::tolower(static_cast<unsigned char>(word[i])));
  }
  word = std::string_view(lower.data(), word.size());
  switch (architecture) {
  case Architecture::X86: {
    if (one_of(word, {"rax", "rbx", "rcx", "rdx",   "rsi",    "rdi",    "rbp",
                      "rsp", "eax", "ebx", "ecx",   "edx",    "esi",    "edi",
                      "ebp", "esp", "ax",  "bx",    "cx",     "dx",     "si",
                      "di",  "bp",  "sp",  "al",    "bl",     "cl",     "dl",
                      "ah",  "bh",  "ch",  "dh",    "sil",    "dil",    "bpl",
                      "spl", "rip", "eip", "ip",    "cs",     "ds",     "es",
                      "fs",  "gs",  "ss",  "flags", "eflags", "rflags", "mxcsr",
                      "st"})) {
      return true;
    }
    for (auto prefix : {"xmm", "ymm", "zmm", "cr", "dr"}) {
      if (numbered(word, prefix, 31))
        return true;
    }
    for (auto prefix : {"mm", "st", "k", "tmm"}) {
      if (numbered(word, prefix, 7))
        return true;
    }
    if (word.starts_with('r')) {
      if (word.ends_with('b') || word.ends_with('w') || word.ends_with('d')) {
        word.remove_suffix(1);
      }
      return numbered(word, "r", 31, 8);
    }
    return false;
  }
  case Architecture::Arm:
  case Architecture::Arm64: {
    const auto suffix = word.find('.');
    if (suffix != std::string_view::npos) {
      // AArch64 lane/arrangement suffixes: v0.16b, z1.d, p0.b.
      const auto arrangement = word.substr(suffix + 1);
      if (arrangement.empty() ||
          !one_of(arrangement.substr(arrangement.size() - 1),
                  {"b", "h", "s", "d", "q"}) ||
          !std::all_of(arrangement.begin(), arrangement.end() - 1,
                       [](char c) { return c >= '0' && c <= '9'; })) {
        return false;
      }
      word = word.substr(0, suffix);
      if (word.empty() || !one_of(word.substr(0, 1), {"v", "z", "p"})) {
        return false;
      }
    }
    if (one_of(word, {"sp", "lr", "fp", "pc", "ip", "cpsr", "spsr", "fpscr"})) {
      return true;
    }
    if (architecture == Architecture::Arm) {
      return numbered(word, "r", 15) || numbered(word, "s", 31) ||
             numbered(word, "d", 31) || numbered(word, "q", 15);
    }
    if (one_of(word, {"xzr", "wzr", "wsp", "nzcv", "fpcr", "fpsr", "ffr"})) {
      return true;
    }
    for (auto prefix : {"x", "w"}) {
      if (numbered(word, prefix, 30))
        return true;
    }
    for (auto prefix : {"v", "q", "d", "s", "h", "b", "z"}) {
      if (numbered(word, prefix, 31))
        return true;
    }
    return numbered(word, "p", 15);
  }
  case Architecture::RiscV:
    return one_of(word, {"zero", "ra", "sp", "gp", "tp", "fp", "pc"}) ||
           numbered(word, "x", 31) || numbered(word, "f", 31) ||
           numbered(word, "v", 31) || numbered(word, "a", 7) ||
           numbered(word, "s", 11) || numbered(word, "t", 6) ||
           numbered(word, "fa", 7) || numbered(word, "fs", 11) ||
           numbered(word, "ft", 11);
  case Architecture::Mips:
    return one_of(word, {"zero", "at", "gp", "sp", "fp", "s8", "ra", "hi", "lo",
                         "pc"}) ||
           (dollar_register && numbered(word, "", 31)) ||
           numbered(word, "r", 31) || numbered(word, "f", 31) ||
           numbered(word, "fcc", 7) || numbered(word, "v", 1) ||
           numbered(word, "a", 7) || numbered(word, "t", 9) ||
           numbered(word, "s", 7) || numbered(word, "k", 1);
  case Architecture::PowerPC:
    return one_of(word, {"lr", "ctr", "xer", "cr", "pc", "msr"}) ||
           numbered(word, "r", 31) || numbered(word, "f", 31) ||
           numbered(word, "v", 31) || numbered(word, "vs", 63) ||
           numbered(word, "cr", 7);
  case Architecture::Sparc:
    return one_of(word, {"sp", "fp", "pc", "npc", "y", "psr", "icc", "xcc"}) ||
           numbered(word, "g", 7) || numbered(word, "o", 7) ||
           numbered(word, "l", 7) || numbered(word, "i", 7) ||
           numbered(word, "f", 63);
  case Architecture::LoongArch:
    return one_of(word, {"zero", "ra", "tp", "sp", "fp", "pc"}) ||
           numbered(word, "r", 31) || numbered(word, "f", 31) ||
           numbered(word, "vr", 31) || numbered(word, "xr", 31) ||
           numbered(word, "a", 7) || numbered(word, "t", 8) ||
           numbered(word, "s", 8) || numbered(word, "fcc", 7);
  case Architecture::SystemZ:
    return one_of(word, {"psw", "fpc"}) || numbered(word, "r", 15) ||
           numbered(word, "f", 15) || numbered(word, "v", 31) ||
           numbered(word, "a", 15);
  case Architecture::Other:
    return false;
  }
  return false;
}

bool word_character(char c) {
  return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' ||
         c == '.' || c == '$' || c == '@' || c == '?';
}

bool number(std::string_view word) {
  if (word.empty() ||
      (!std::isdigit(static_cast<unsigned char>(word.front())) &&
       word.front() != '.')) {
    return false;
  }
  int base = 10;
  if (word.starts_with("0x") || word.starts_with("0X")) {
    word.remove_prefix(2);
    base = 16;
  } else if (word.starts_with("0b") || word.starts_with("0B")) {
    word.remove_prefix(2);
    base = 2;
  } else if (word.ends_with('h') || word.ends_with('H')) {
    word.remove_suffix(1);
    base = 16;
  }
  std::uint64_t value{};
  const auto result =
      std::from_chars(word.data(), word.data() + word.size(), value, base);
  if (result.ec == std::errc{} && result.ptr == word.data() + word.size())
    return true;
  if (base == 10) {
    double floating{};
    const auto decimal =
        std::from_chars(word.data(), word.data() + word.size(), floating);
    return decimal.ec == std::errc{} &&
           decimal.ptr == word.data() + word.size();
  }
  return false;
}

void token(DisassemblyText &text, std::size_t begin, std::size_t end, Kind kind,
           std::optional<std::uint64_t> target = std::nullopt) {
  if (begin == end)
    return;
  if (!text.tokens.empty() && text.tokens.back().kind == kind &&
      text.tokens.back().end == begin && text.tokens.back().target == target) {
    text.tokens.back().end = end;
  } else {
    text.tokens.push_back({begin, end, kind, target});
  }
}

void append(DisassemblyText &text, std::string_view value, Kind kind,
            std::optional<std::uint64_t> target = std::nullopt) {
  const auto begin = text.text.size();
  text.text += value;
  token(text, begin, text.text.size(), kind, target);
}

void tokenize(DisassemblyText &text, std::size_t start,
              Architecture architecture, bool comment = false) {
  bool symbol_brackets{};
  for (std::size_t i = start; i < text.text.size();) {
    const auto begin = i;
    const char c = text.text[i++];
    Kind kind = comment ? Kind::Comment : Kind::Punctuation;
    if (c == '"' || c == '\'') {
      while (i < text.text.size()) {
        const char next = text.text[i++];
        if (next == '\\' && i < text.text.size())
          ++i;
        else if (next == c)
          break;
      }
      kind = Kind::String;
    } else if (!comment &&
               (c == ';' ||
                (c == '#' && architecture != Architecture::Arm &&
                 architecture != Architecture::Arm64) ||
                (c == '/' && i < text.text.size() && text.text[i] == '/'))) {
      comment = true;
      kind = Kind::Comment;
    } else if (c == '$' && architecture == Architecture::X86 && !comment) {
      // AT&T immediate sigil, not part of the numeric literal or symbol.
    } else if (word_character(c) || c == '%') {
      while (i < text.text.size()) {
        if (word_character(text.text[i]))
          ++i;
        else if (text.text[i] == ':' && i + 1 < text.text.size() &&
                 text.text[i + 1] == ':')
          i += 2;
        else
          break;
      }
      const auto word = std::string_view(text.text).substr(begin, i - begin);
      const bool immediate_symbol = architecture == Architecture::X86 &&
                                    begin > 0 && text.text[begin - 1] == '$';
      if (!comment && !symbol_brackets && !immediate_symbol &&
          assembly_register(word, architecture)) {
        kind = Kind::Register;
      } else if (number(word)) {
        kind = Kind::Number;
      } else if (!comment) {
        kind = one_of(word, {"byte", "word", "dword", "qword", "tbyte", "xword",
                             "xmmword", "ymmword", "zmmword", "ptr", "offset"})
                   ? Kind::Punctuation
                   : Kind::Symbol;
      }
    } else if (!comment) {
      if (c == '<')
        symbol_brackets = true;
      if (c == '>')
        symbol_brackets = false;
      if (std::isspace(static_cast<unsigned char>(c)))
        kind = Kind::Plain;
    }
    token(text, begin, i, kind);
  }
}

std::optional<std::uint64_t> address_literal(std::string_view word) {
  if (word.starts_with("0x") || word.starts_with("0X"))
    word.remove_prefix(2);
  else if (word.ends_with('h') || word.ends_with('H'))
    word.remove_suffix(1);
  else
    return std::nullopt;
  std::uint64_t address{};
  const auto result =
      std::from_chars(word.data(), word.data() + word.size(), address, 16);
  if (result.ec != std::errc{} || result.ptr != word.data() + word.size())
    return std::nullopt;
  return address;
}

// Only complete operands qualify as literal pointers. Displacements, scales,
// decimal scalars and numeric substrings inside symbols are not addresses.
void link_operands(DisassemblyText &text, std::size_t start,
                   const debugger::InstructionRow &instruction,
                   Architecture architecture) {
  std::vector<std::pair<std::size_t, std::size_t>> operands;
  std::size_t begin = start;
  unsigned depth{};
  for (std::size_t i = start; i < text.text.size(); ++i) {
    const char c = text.text[i];
    if (c == '[' || c == '(' || c == '{' || c == '<')
      ++depth;
    else if ((c == ']' || c == ')' || c == '}' || c == '>') && depth > 0)
      --depth;
    else if (c == ',' && depth == 0) {
      operands.emplace_back(begin, i);
      begin = i + 1;
    }
  }
  operands.emplace_back(begin, text.text.size());
  std::optional<std::size_t> destination;
  if (instruction.flow_target) {
    if (architecture == Architecture::PowerPC &&
        (instruction.mnemonic.find("lr") != std::string::npos ||
         instruction.mnemonic.find("ctr") != std::string::npos)) {
      // LR/CTR are implicit; even a sole explicit operand is a condition.
    } else if (operands.size() == 1) {
      destination = 0;
    } else {
      switch (architecture) {
      case Architecture::Arm:
      case Architecture::Arm64:
        if (one_of(instruction.mnemonic, {"braa", "brab", "blraa", "blrab"}))
          destination = 0;
        else
          destination = operands.size() - 1;
        break;
      case Architecture::RiscV:
        destination = instruction.mnemonic == "jalr" && operands.size() == 3
                          ? 1
                          : operands.size() - 1;
        break;
      case Architecture::Mips:
      case Architecture::SystemZ:
        destination = operands.size() - 1;
        break;
      case Architecture::Sparc:
        destination = instruction.mnemonic == "jmpl" ? 0 : operands.size() - 1;
        break;
      case Architecture::LoongArch:
        destination = instruction.mnemonic == "jirl" ? 1 : operands.size() - 1;
        break;
      case Architecture::PowerPC:
        destination = operands.size() - 1;
        break;
      default:
        break;
      }
    }
  }
  for (std::size_t operand = 0; operand < operands.size(); ++operand) {
    const auto [first, last] = operands[operand];
    for (auto &span : text.tokens) {
      if (span.begin < first || span.end > last)
        continue;
      if (destination == operand && span.kind != Kind::Plain &&
          span.kind != Kind::Comment) {
        span.target = instruction.flow_target;
        continue;
      }
      // Non-target control operands are condition masks/registers/immediates.
      if (instruction.flow_kind != debugger::InstructionFlowKind::Other ||
          span.kind != Kind::Number)
        continue;
      const auto literal = address_literal(std::string_view(text.text).substr(
          span.begin, span.end - span.begin));
      if (!literal)
        continue;
      const bool complete = std::all_of(
          text.tokens.begin(), text.tokens.end(), [&](const auto &other) {
            if (other.begin < first || other.end > last ||
                other.begin == span.begin || other.kind == Kind::Plain)
              return true;
            if (other.kind != Kind::Punctuation)
              return false;
            auto word = std::string_view(text.text).substr(
                other.begin, other.end - other.begin);
            if (one_of(word, {"byte", "word", "dword", "qword", "tbyte",
                              "xword", "ptr", "offset"}))
              return true;
            return std::all_of(word.begin(), word.end(), [](char c) {
              return c == '[' || c == ']' || c == '$' || c == '#' || c == '*' ||
                     std::isspace(static_cast<unsigned char>(c));
            });
          });
      if (complete)
        span.target = literal;
    }
  }
}

bool link_reference(DisassemblyText &text, std::string_view value,
                    std::uint64_t address) {
  if (value.empty())
    return false;
  bool found = false;
  for (auto at = text.text.find(value); at != std::string::npos;
       at = text.text.find(value, at + 1)) {
    const auto end = at + value.size();
    if ((at > 0 && word_character(text.text[at - 1])) ||
        (end < text.text.size() && word_character(text.text[end])))
      continue;
    found = true;
    for (std::size_t i = 0; i < text.tokens.size(); ++i) {
      auto span = text.tokens[i];
      if (span.end <= at || span.begin >= end)
        continue;
      if (span.begin < at) {
        text.tokens[i].end = at;
        span.begin = at;
        text.tokens.insert(text.tokens.begin() + ++i, span);
      }
      if (span.end > end) {
        text.tokens[i].end = end;
        span.begin = end;
        text.tokens.insert(text.tokens.begin() + i + 1, span);
      }
      if (text.tokens[i].kind != Kind::Plain)
        text.tokens[i].target = address;
    }
  }
  return found;
}

void annotation_line(DisassemblyText &text) {
  if (!text.text.empty())
    append(text, "\n", Kind::Plain);
}

void append_debug_source(DisassemblyText &text,
                         const debugger::DebugSourceLocation &source) {
  append(text, source.path, Kind::Comment);
  if (source.line != 0) {
    append(text, ":", Kind::Punctuation);
    append(text, std::to_string(source.line), Kind::Number);
    if (source.column != 0) {
      append(text, ":", Kind::Punctuation);
      append(text, std::to_string(source.column), Kind::Number);
    }
  }
}

void append_declaration(DisassemblyText &text,
                        const debugger::DebugDeclaration &declaration) {
  // Name : type also renders arrays, references and function-pointer types
  // correctly without trying to splice names into a C/C++ type string.
  if (!declaration.name.empty()) {
    append(text, declaration.name, Kind::Symbol);
    if (!declaration.type.empty())
      append(text, " : ", Kind::Punctuation);
  }
  append(text, declaration.type, Kind::Type);
}

void append_debug_function(DisassemblyText &text,
                           const debugger::DebugFunctionInfo &function,
                           std::optional<std::uint64_t> target) {
  append(text, function.name, Kind::Symbol, target);
  if (!function.type.empty()) {
    append(text, " : ", Kind::Punctuation);
    append(text, function.type, Kind::Type);
  }
}

void append_declarations(
    DisassemblyText &text,
    const std::vector<debugger::DebugDeclaration> &declarations,
    bool parameters, bool new_line = true) {
  bool first = true;
  for (const auto &declaration : declarations) {
    if (declaration.parameter != parameters)
      continue;
    if (first) {
      if (new_line)
        annotation_line(text);
      else
        append(text, "  [", Kind::Punctuation);
      append(text,
             l10n::text(parameters
                            ? l10n::Key::GuiDisassemblyTextDebugParameters
                            : l10n::Key::GuiDisassemblyTextDebugLocals),
             Kind::Comment);
    } else {
      append(text, ", ", Kind::Punctuation);
    }
    append_declaration(text, declaration);
    first = false;
  }
  if (!first && !new_line)
    append(text, "]", Kind::Punctuation);
}

void append_debug_scope(DisassemblyText &text,
                        const debugger::DebugScopeInfo &scope) {
  if (scope.parent)
    append_debug_scope(text, *scope.parent);
  if (!scope.inline_name.empty()) {
    annotation_line(text);
    append(text, l10n::text(l10n::Key::GuiDisassemblyTextDebugInline),
           Kind::Comment);
    append(text, scope.inline_name, Kind::Symbol);
    if (!scope.inline_call_site.path.empty()) {
      append(text, " @ ", Kind::Punctuation);
      append_debug_source(text, scope.inline_call_site);
    }
  }
  append_declarations(text, scope.declarations, true);
  append_declarations(text, scope.declarations, false);
}

} // namespace

DisassemblyPresentation
make_disassembly_presentation(const debugger::InstructionRow &instruction,
                              std::string_view architecture) {
  DisassemblyPresentation presentation;
  auto &assembly = presentation.instruction;
  append(assembly, instruction.mnemonic,
         instruction.flow_kind == debugger::InstructionFlowKind::Other
             ? Kind::Mnemonic
             : Kind::ControlFlow,
         instruction.flow_target);
  if (!instruction.operands.empty()) {
    append(assembly, " ", Kind::Plain);
    const auto start = assembly.text.size();
    assembly.text += instruction.operands;
    const auto arch = assembly_architecture(architecture);
    tokenize(assembly, start, arch);
    link_operands(assembly, start, instruction, arch);
  }
  auto &annotation = presentation.annotation;
  annotation.text = instruction.comment;
  tokenize(annotation, 0, Architecture::Other, true);
  for (const auto &reference : instruction.references) {
    const bool symbol_present =
        link_reference(annotation, reference.symbol, reference.address);
    const bool preview_present =
        link_reference(annotation, reference.preview, reference.address);
    if (!annotation.text.empty())
      append(annotation, "  |  ", Kind::Punctuation);
    if (reference.runtime)
      append(annotation, l10n::text(l10n::Key::GuiDisassemblyTextCurrentState),
             Kind::Runtime);
    char address[32]{};
    std::snprintf(address, sizeof(address), "0x%" PRIx64, reference.address);
    link_reference(annotation, address, reference.address);
    append(annotation, address, Kind::Number, reference.address);
    const bool local_branch =
        (instruction.flow_kind == debugger::InstructionFlowKind::Jump ||
         instruction.flow_kind ==
             debugger::InstructionFlowKind::ConditionalJump) &&
        instruction.debug_scope && reference.function &&
        instruction.debug_scope->function &&
        reference.function->address ==
            instruction.debug_scope->function->address;
    if (reference.function && !local_branch) {
      append(annotation, " <", Kind::Punctuation);
      append_debug_function(annotation, *reference.function, reference.address);
      append(annotation, ">", Kind::Punctuation);
      append_declarations(annotation, reference.function->parameters, true,
                          false);
    } else if (!reference.symbol.empty() && !symbol_present) {
      append(annotation, " <", Kind::Punctuation);
      append(annotation, reference.symbol, Kind::Symbol, reference.address);
      append(annotation, ">", Kind::Punctuation);
    }
    if (!reference.declaration.type.empty()) {
      append(annotation, "  [", Kind::Punctuation);
      append_declaration(annotation, reference.declaration);
      append(annotation, "]", Kind::Punctuation);
    }
    if (!reference.preview.empty() && !preview_present) {
      append(annotation, " ", Kind::Plain);
      append(annotation, reference.preview, Kind::String, reference.address);
    }
  }
  if (instruction.begins_source && instruction.source) {
    annotation_line(annotation);
    append_debug_source(annotation, *instruction.source);
  }
  if (instruction.debug_scope) {
    if (instruction.begins_function && instruction.debug_scope->function) {
      const auto &function = *instruction.debug_scope->function;
      annotation_line(annotation);
      // Context headers are not operand targets. Only reference/call labels
      // participate in the existing follow-target keyboard action.
      append_debug_function(annotation, function, std::nullopt);
      append_declarations(annotation, function.parameters, true);
    }
    if (instruction.begins_debug_scope)
      append_debug_scope(annotation, *instruction.debug_scope);
  }
  if (!instruction.user_comment.empty()) {
    annotation_line(annotation);
    append(annotation, l10n::text(l10n::Key::GuiSessionCommentPrefix),
           Kind::Comment);
    append(annotation, instruction.user_comment, Kind::Comment);
  }
  presentation.bytes = bytes_as_hex(instruction.bytes);
  return presentation;
}

bool navigable_address(const debugger::SessionSnapshot &snapshot,
                       std::uint64_t address) {
  return std::any_of(snapshot.memory_regions.begin(),
                     snapshot.memory_regions.end(),
                     [address](const auto &region) {
                       return address >= region.start && address < region.end &&
                              (region.readable || region.executable);
                     });
}

std::optional<std::uint64_t>
disassembly_navigation_target(const debugger::SessionSnapshot &snapshot,
                              const debugger::InstructionRow &instruction,
                              const DisassemblyPresentation &presentation) {
  if (instruction.flow_target &&
      navigable_address(snapshot, *instruction.flow_target)) {
    return *instruction.flow_target;
  }
  for (const auto *cell :
       {&presentation.instruction, &presentation.annotation}) {
    for (const auto &token : cell->tokens) {
      if (token.target && navigable_address(snapshot, *token.target)) {
        return *token.target;
      }
    }
  }
  return std::nullopt;
}

} // namespace mydbg::app
