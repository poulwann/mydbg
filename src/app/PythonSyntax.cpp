#include "app/PythonSyntax.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <initializer_list>
#include <string_view>
#include <vector>

namespace mydbg::app::python_syntax {
namespace {

using Palette = TextEditor::PaletteIndex;

// These are lexical roles, not name resolution: a shadowed builtin still has
// its builtin role, just as in a grammar-based highlighter such as MagicPython.
template <std::size_t N>
constexpr auto sorted(std::array<std::string_view, N> words) {
  std::sort(words.begin(), words.end());
  return words;
}

constexpr auto keywords = sorted(std::to_array<std::string_view>(
    {"False",  "None",     "True",  "and",    "as",       "assert",
     "async",  "await",    "break", "class",  "continue", "def",
     "del",    "elif",     "else",  "except", "finally",  "for",
     "from",   "global",   "if",    "import", "in",       "is",
     "lambda", "nonlocal", "not",   "or",     "pass",     "raise",
     "return", "try",      "while", "with",   "yield"}));

constexpr auto builtins =
    sorted(std::to_array<std::string_view>({"ArithmeticError",
                                            "AssertionError",
                                            "AttributeError",
                                            "BaseException",
                                            "BaseExceptionGroup",
                                            "BlockingIOError",
                                            "BrokenPipeError",
                                            "BufferError",
                                            "BytesWarning",
                                            "ChildProcessError",
                                            "ConnectionAbortedError",
                                            "ConnectionError",
                                            "ConnectionRefusedError",
                                            "ConnectionResetError",
                                            "DeprecationWarning",
                                            "EOFError",
                                            "Ellipsis",
                                            "EncodingWarning",
                                            "EnvironmentError",
                                            "Exception",
                                            "ExceptionGroup",
                                            "FileExistsError",
                                            "FileNotFoundError",
                                            "FloatingPointError",
                                            "FutureWarning",
                                            "GeneratorExit",
                                            "IOError",
                                            "ImportError",
                                            "ImportWarning",
                                            "IndentationError",
                                            "IndexError",
                                            "InterruptedError",
                                            "IsADirectoryError",
                                            "KeyError",
                                            "KeyboardInterrupt",
                                            "LookupError",
                                            "MemoryError",
                                            "ModuleNotFoundError",
                                            "NameError",
                                            "NotADirectoryError",
                                            "NotImplemented",
                                            "NotImplementedError",
                                            "OSError",
                                            "OverflowError",
                                            "PendingDeprecationWarning",
                                            "PermissionError",
                                            "ProcessLookupError",
                                            "RecursionError",
                                            "ReferenceError",
                                            "ResourceWarning",
                                            "RuntimeError",
                                            "RuntimeWarning",
                                            "StopAsyncIteration",
                                            "StopIteration",
                                            "SyntaxError",
                                            "SyntaxWarning",
                                            "SystemError",
                                            "SystemExit",
                                            "TabError",
                                            "TimeoutError",
                                            "TypeError",
                                            "UnboundLocalError",
                                            "UnicodeDecodeError",
                                            "UnicodeEncodeError",
                                            "UnicodeError",
                                            "UnicodeTranslateError",
                                            "UnicodeWarning",
                                            "UserWarning",
                                            "ValueError",
                                            "Warning",
                                            "ZeroDivisionError",
                                            "__build_class__",
                                            "__debug__",
                                            "__import__",
                                            "abs",
                                            "aiter",
                                            "all",
                                            "anext",
                                            "any",
                                            "ascii",
                                            "bin",
                                            "bool",
                                            "breakpoint",
                                            "bytearray",
                                            "bytes",
                                            "callable",
                                            "chr",
                                            "classmethod",
                                            "compile",
                                            "complex",
                                            "copyright",
                                            "credits",
                                            "delattr",
                                            "dict",
                                            "dir",
                                            "divmod",
                                            "enumerate",
                                            "eval",
                                            "exec",
                                            "exit",
                                            "filter",
                                            "float",
                                            "format",
                                            "frozenset",
                                            "getattr",
                                            "globals",
                                            "hasattr",
                                            "hash",
                                            "help",
                                            "hex",
                                            "id",
                                            "input",
                                            "int",
                                            "isinstance",
                                            "issubclass",
                                            "iter",
                                            "len",
                                            "license",
                                            "list",
                                            "locals",
                                            "map",
                                            "max",
                                            "memoryview",
                                            "min",
                                            "next",
                                            "object",
                                            "oct",
                                            "open",
                                            "ord",
                                            "pow",
                                            "print",
                                            "property",
                                            "quit",
                                            "range",
                                            "repr",
                                            "reversed",
                                            "round",
                                            "set",
                                            "setattr",
                                            "slice",
                                            "sorted",
                                            "staticmethod",
                                            "str",
                                            "sum",
                                            "super",
                                            "tuple",
                                            "type",
                                            "vars",
                                            "zip"}));

template <std::size_t N>
bool contains(const std::array<std::string_view, N> &words,
              std::string_view word) {
  return std::binary_search(words.begin(), words.end(), word);
}

bool one_of(std::string_view word,
            std::initializer_list<std::string_view> choices) {
  return std::find(choices.begin(), choices.end(), word) != choices.end();
}

bool digit(char c) { return c >= '0' && c <= '9'; }
bool hex_digit(char c) {
  return digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
bool identifier_start(char c) {
  const auto byte = static_cast<unsigned char>(c);
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
         byte >= 0x80;
}
bool identifier_part(char c) { return identifier_start(c) || digit(c); }
bool space(char c) { return c == ' ' || c == '\t' || c == '\f' || c == '\r'; }
bool quote(char c) { return c == '\'' || c == '"'; }

std::size_t skip_space(std::string_view text, std::size_t pos) {
  while (pos < text.size() && space(text[pos]))
    ++pos;
  return pos;
}

int columns(std::string_view text, int tab_size, int column = 0) {
  for (const unsigned char c : text) {
    if (c == '\t')
      column += tab_size - column % tab_size;
    else if ((c & 0xc0) != 0x80)
      ++column;
  }
  return column;
}

std::size_t whitespace_end(std::string_view text) {
  std::size_t pos = 0;
  while (pos < text.size() && (text[pos] == ' ' || text[pos] == '\t'))
    ++pos;
  return pos;
}

enum class Kind { Word, Number, String, Escape, Punctuation, Comment };

struct Token {
  std::size_t begin;
  std::size_t end;
  Kind kind;
  // Only outer Python tokens participate in statement indentation. Replacement
  // expressions are still colored as Python, but do not open outer suites.
  bool outer;
};

enum class Mode { String, Replacement, Format };

struct Context {
  Mode mode = Mode::String;
  char quote = 0;
  bool triple = false;
  bool raw = false;
  bool bytes = false;
  bool interpolated = false;
  bool outer = false;
  bool escaped_newline = false;
  int depth = 0;
};

class Lexer {
public:
  bool in_literal() const {
    return !contexts_.empty() && contexts_.back().mode != Mode::Replacement;
  }
  bool has_context() const { return !contexts_.empty(); }

  // Called only after a complete physical line, not at the cursor. An
  // unfinished ordinary quote recovers on the next line; triples and escaped
  // newlines retain their state. Replacement expressions allow PEP 701 lines.
  void newline() {
    while (!contexts_.empty() && contexts_.back().mode == Mode::String &&
           !contexts_.back().triple && !contexts_.back().escaped_newline) {
      contexts_.pop_back();
    }
    if (!contexts_.empty())
      contexts_.back().escaped_newline = false;
  }

  template <typename Emit> void line(std::string_view text, Emit &&emit) {
    std::size_t pos = 0;
    while (pos < text.size()) {
      if (!contexts_.empty() && contexts_.back().mode != Mode::Replacement) {
        literal(text, pos, emit);
        continue;
      }
      const bool outer = contexts_.empty();
      const std::size_t begin = pos;
      const char c = text[pos];
      if (space(c)) {
        ++pos;
        continue;
      }
      if (c == '#') {
        emit(Token{pos, text.size(), Kind::Comment, outer});
        break;
      }
      if (!outer && contexts_.back().depth == 0) {
        if (c == '}') {
          emit(Token{pos, pos + 1, Kind::Punctuation, false});
          ++pos;
          contexts_.pop_back();
          continue;
        }
        if (c == ':') {
          emit(Token{pos, pos + 1, Kind::Punctuation, false});
          ++pos;
          contexts_.back().mode = Mode::Format;
          continue;
        }
        if (c == '!' && pos + 1 < text.size() && text[pos + 1] != '=') {
          ++pos;
          if (one_of(text.substr(pos, 1), {"s", "r", "a"}))
            ++pos;
          emit(Token{begin, pos, Kind::Escape, false});
          continue;
        }
      }
      if (quote(c)) {
        open_string(text, pos, pos, outer, emit);
        continue;
      }
      if (identifier_start(c)) {
        while (++pos < text.size() && identifier_part(text[pos])) {
        }
        if (pos < text.size() && quote(text[pos]) &&
            string_prefix(text.substr(begin, pos - begin))) {
          open_string(text, begin, pos, outer, emit);
          continue;
        }
        emit(Token{begin, pos, Kind::Word, outer});
        continue;
      }
      if (digit(c) ||
          (c == '.' && pos + 1 < text.size() && digit(text[pos + 1]))) {
        pos = number_end(text, pos);
        emit(Token{begin, pos, Kind::Number, outer});
        continue;
      }
      if (!outer) {
        if (c == '(' || c == '[' || c == '{')
          ++contexts_.back().depth;
        else if ((c == ')' || c == ']' || c == '}') &&
                 contexts_.back().depth > 0)
          --contexts_.back().depth;
      }
      ++pos;
      // Delimiters remain individual tokens for bracket and suite analysis.
      if (pos < text.size() &&
          one_of(text.substr(begin, 2),
                 {"==", "!=", "<=", ">=", ":=", "->", "+=", "-=", "*=", "/=",
                  "%=", "&=", "|=", "^=", "**", "//", "<<", ">>"})) {
        ++pos;
        if (pos < text.size() && text[pos] == '=' &&
            one_of(text.substr(begin, 2), {"**", "//", "<<", ">>"}))
          ++pos;
      } else if (c == '.' && text.substr(begin, 3) == "...") {
        pos += 2;
      }
      emit(Token{begin, pos, Kind::Punctuation, outer});
    }
  }

private:
  std::vector<Context> contexts_;

  static bool string_prefix(std::string_view prefix) {
    if (prefix.size() > 2)
      return false;
    std::array<char, 2> lower{};
    for (std::size_t i = 0; i < prefix.size(); ++i) {
      const char c = prefix[i];
      lower[i] = c >= 'A' && c <= 'Z' ? static_cast<char>(c + 'a' - 'A') : c;
    }
    return one_of(
        std::string_view(lower.data(), prefix.size()),
        {"r", "u", "b", "f", "br", "rb", "fr", "rf", "t", "tr", "rt"});
  }

  template <typename Emit>
  void open_string(std::string_view text, std::size_t begin, std::size_t &pos,
                   bool outer, Emit &emit) {
    Context context;
    context.quote = text[pos];
    context.outer = outer;
    for (std::size_t i = begin; i < pos; ++i) {
      context.raw |= text[i] == 'r' || text[i] == 'R';
      context.bytes |= text[i] == 'b' || text[i] == 'B';
      context.interpolated |=
          text[i] == 'f' || text[i] == 'F' || text[i] == 't' || text[i] == 'T';
    }
    context.triple = pos + 2 < text.size() && text[pos + 1] == context.quote &&
                     text[pos + 2] == context.quote;
    pos += context.triple ? 3 : 1;
    emit(Token{begin, pos, Kind::String, outer});
    contexts_.push_back(context);
  }

  static std::size_t number_end(std::string_view text, std::size_t pos) {
    if (text[pos] == '0' && pos + 1 < text.size() &&
        one_of(text.substr(pos + 1, 1), {"b", "B", "o", "O", "x", "X"})) {
      const char base = text[pos + 1];
      pos += 2;
      while (pos < text.size()) {
        const char c = text[pos];
        const bool valid = (base == 'x' || base == 'X') ? hex_digit(c)
                           : (base == 'o' || base == 'O')
                               ? c >= '0' && c <= '7'
                               : c == '0' || c == '1';
        if (!valid && c != '_')
          break;
        ++pos;
      }
      return pos;
    }
    while (pos < text.size() && (digit(text[pos]) || text[pos] == '_'))
      ++pos;
    if (pos < text.size() && text[pos] == '.' &&
        (pos + 1 == text.size() || text[pos + 1] != '.')) {
      ++pos;
      while (pos < text.size() && (digit(text[pos]) || text[pos] == '_'))
        ++pos;
    }
    if (pos < text.size() && (text[pos] == 'e' || text[pos] == 'E')) {
      std::size_t exponent = pos + 1;
      if (exponent < text.size() &&
          (text[exponent] == '+' || text[exponent] == '-'))
        ++exponent;
      if (exponent < text.size() && digit(text[exponent])) {
        pos = exponent + 1;
        while (pos < text.size() && (digit(text[pos]) || text[pos] == '_'))
          ++pos;
      }
    }
    if (pos < text.size() && (text[pos] == 'j' || text[pos] == 'J'))
      ++pos;
    return pos;
  }

  template <typename Emit>
  void literal(std::string_view text, std::size_t &pos, Emit &emit) {
    const Context context = contexts_.back();
    const std::size_t begin = pos;
    const char c = text[pos];
    if (context.mode == Mode::Format) {
      if (c == '{') {
        emit(Token{pos, pos + 1, Kind::Punctuation, false});
        ++pos;
        Context replacement = context;
        replacement.mode = Mode::Replacement;
        replacement.outer = false;
        replacement.depth = 0;
        contexts_.push_back(replacement);
        return;
      } else if (c == '}') {
        emit(Token{pos, pos + 1, Kind::Punctuation, false});
        ++pos;
        contexts_.pop_back();
        return;
      }
    }
    if (context.mode == Mode::String && c == context.quote &&
        (!context.triple ||
         (pos + 2 < text.size() && text[pos + 1] == c && text[pos + 2] == c))) {
      pos += context.triple ? 3 : 1;
      emit(Token{begin, pos, Kind::String, context.outer});
      contexts_.pop_back();
      return;
    }
    if (context.mode == Mode::String && context.interpolated &&
        (c == '{' || c == '}')) {
      if (pos + 1 < text.size() && text[pos + 1] == c) {
        pos += 2;
        emit(Token{begin, pos, Kind::String, context.outer});
      } else if (c == '{') {
        ++pos;
        emit(Token{begin, pos, Kind::Punctuation, false});
        Context replacement = context;
        replacement.mode = Mode::Replacement;
        replacement.outer = false;
        replacement.depth = 0;
        contexts_.push_back(replacement);
      } else {
        ++pos;
        emit(Token{begin, pos, Kind::String, context.outer});
      }
      return;
    }
    if (c == '\\') {
      ++pos;
      if (pos == text.size()) {
        contexts_.back().escaped_newline = true;
      } else if (!(context.interpolated &&
                   (text[pos] == '{' || text[pos] == '}'))) {
        const char escaped = text[pos++];
        if (!context.raw) {
          int remaining = escaped == 'x'                     ? 2
                          : !context.bytes && escaped == 'u' ? 4
                          : !context.bytes && escaped == 'U' ? 8
                                                             : 0;
          while (remaining-- > 0 && pos < text.size() && hex_digit(text[pos]))
            ++pos;
          if (escaped >= '0' && escaped <= '7') {
            for (int i = 0; i < 2 && pos < text.size() && text[pos] >= '0' &&
                            text[pos] <= '7';
                 ++i)
              ++pos;
          } else if (!context.bytes && escaped == 'N' && pos < text.size() &&
                     text[pos] == '{') {
            ++pos;
            while (pos < text.size() && text[pos] != '}' &&
                   text[pos] != context.quote)
              ++pos;
            if (pos < text.size() && text[pos] == '}')
              ++pos;
          }
        }
      }
      emit(Token{begin, pos, context.raw ? Kind::String : Kind::Escape,
                 context.outer});
      return;
    }
    // Scan runs rather than emitting one token per byte. UTF-8 is never decoded
    // into a separate glyph stream: every source byte retains its own glyph.
    do {
      ++pos;
    } while (pos < text.size() && text[pos] != '\\' &&
             (context.mode == Mode::Format || text[pos] != context.quote) &&
             !(context.interpolated && (text[pos] == '{' || text[pos] == '}')));
    emit(Token{begin, pos, Kind::String, context.outer});
  }
};

enum class StatementKind { Other, Suite, Async, Match, Case, Terminal };

struct Delimiter {
  char close;
  int line;
  int indent;
  int alignment = -1;
};

// The same outer-token analysis drives soft-keyword coloring and indentation.
// It is deliberately lexical: it must remain useful before a header is valid.
class Statement {
public:
  explicit Statement(int tab_size) : tab_size_(tab_size) {}

  void begin_line(std::string_view text, int line) {
    line_ = line;
    column_ = 0;
    column_byte_ = 0;
    line_indent = columns(text.substr(0, whitespace_end(text)), tab_size_);
    if (!continuing_) {
      kind = StatementKind::Other;
      base_line = line;
      base_indent = line_indent;
      token_count = 0;
      suite_colon = false;
      inline_suite = false;
      soft_line = -1;
      lambdas_ = 0;
      after_semicolon_ = false;
      terminal_operand_ = false;
      terminal_bare_only_ = false;
      complete = false;
    }
    backslash = false;
  }

  void end_line(bool string_open) {
    continuing_ = string_open || !delimiters.empty() || backslash;
  }

  void consume(std::string_view text, const Token &token) {
    if (!token.outer || token.kind == Kind::Comment)
      return;
    column_ = columns(text.substr(column_byte_, token.begin - column_byte_),
                      tab_size_, column_);
    column_byte_ = token.begin;
    if (after_semicolon_)
      kind = StatementKind::Other;
    const auto word = text.substr(token.begin, token.end - token.begin);
    const bool punctuation = token.kind == Kind::Punctuation;
    const int depth = static_cast<int>(delimiters.size());
    const bool closing = punctuation && one_of(word, {")", "]", "}"});
    if (!delimiters.empty() && delimiters.back().alignment < 0 && !closing) {
      auto &open = delimiters.back();
      if (open.line == line_)
        open.alignment = column_;
      else if (line_indent > open.indent)
        open.alignment = line_indent;
    }
    backslash = punctuation && word == "\\";
    if (token_count == 0) {
      if (token.kind == Kind::Word) {
        if (one_of(word, {"if", "elif", "else", "for", "while", "try", "except",
                          "finally", "with", "def", "class"}))
          kind = StatementKind::Suite;
        else if (word == "async")
          kind = StatementKind::Async;
        else if (word == "match" || word == "case") {
          kind = word == "match" ? StatementKind::Match : StatementKind::Case;
          soft_line = line_;
          soft_begin = token.begin;
          soft_end = token.end;
        } else if (one_of(word,
                          {"return", "raise", "break", "continue", "pass"})) {
          kind = StatementKind::Terminal;
          terminal_bare_only_ = one_of(word, {"break", "continue", "pass"});
        }
      }
    } else if (token_count == 1 && kind == StatementKind::Async) {
      kind = token.kind == Kind::Word && one_of(word, {"def", "for", "with"})
                 ? StatementKind::Suite
                 : StatementKind::Other;
    }
    if (depth == 0) {
      if (token.kind == Kind::Word && word == "lambda")
        ++lambdas_;
      if (suite_colon)
        inline_suite = true;
      if (punctuation && word == ":") {
        if (lambdas_ > 0) {
          --lambdas_;
        } else if (!suite_colon && (kind == StatementKind::Suite ||
                                    ((kind == StatementKind::Match ||
                                      kind == StatementKind::Case) &&
                                     token_count > 1))) {
          suite_colon = true;
        }
      }
      if ((kind == StatementKind::Match || kind == StatementKind::Case) &&
          !suite_colon && punctuation &&
          (word == "=" || word == ":=" ||
           (token_count == 1 && (word == ":" || word == ".")))) {
        kind = StatementKind::Other;
        soft_line = -1;
      }
      if (punctuation && word == ";") {
        after_semicolon_ = true;
        ++token_count;
        return;
      }
    }
    if (punctuation && one_of(word, {"(", "[", "{"})) {
      delimiters.push_back({word == "("   ? ')'
                            : word == "[" ? ']'
                                          : '}',
                            line_, line_indent});
    } else if (closing && !delimiters.empty() &&
               delimiters.back().close == word[0]) {
      delimiters.pop_back();
    }
    ++token_count;
    if (kind == StatementKind::Terminal) {
      terminal_operand_ |= token_count > 1;
      complete = token.kind == Kind::Number || token.kind == Kind::String ||
                 token.kind == Kind::Escape || closing || word == "..." ||
                 (word == "," && terminal_operand_) ||
                 (token.kind == Kind::Word &&
                  (!contains(keywords, word) ||
                   one_of(word, {"True", "False", "None", "return", "raise",
                                 "break", "continue", "pass"})));
      if (terminal_bare_only_ && terminal_operand_)
        complete = false;
    }
  }

  bool opens_suite() const { return suite_colon && !inline_suite; }
  bool started() const { return token_count != 0; }

  int base_line = 0;
  int base_indent = 0;
  int line_indent = 0;
  bool backslash = false;
  bool complete = false;
  bool suite_colon = false;
  bool inline_suite = false;
  StatementKind kind = StatementKind::Other;
  std::size_t token_count = 0;
  int soft_line = -1;
  std::size_t soft_begin = 0;
  std::size_t soft_end = 0;
  std::vector<Delimiter> delimiters;

private:
  int tab_size_;
  int line_ = 0;
  int column_ = 0;
  std::size_t column_byte_ = 0;
  bool continuing_ = false;
  bool terminal_operand_ = false;
  bool terminal_bare_only_ = false;
  bool after_semicolon_ = false;
  int lambdas_ = 0;
};

Palette basic_palette(Kind kind) {
  switch (kind) {
  case Kind::Word:
    return Palette::Identifier;
  case Kind::Number:
    return Palette::Number;
  case Kind::String:
    return Palette::String;
  case Kind::Escape:
    return Palette::CharLiteral;
  case Kind::Punctuation:
    return Palette::Punctuation;
  case Kind::Comment:
    return Palette::Comment;
  }
  return Palette::Default;
}

void paint(TextEditor::Line &line, std::size_t begin, std::size_t end,
           Palette color) {
  for (std::size_t pos = begin; pos < end; ++pos)
    line[pos].mColorIndex = color;
}

void load_line(const TextEditor::Line &line, std::string &buffer,
               std::size_t end) {
  buffer.clear();
  buffer.reserve(end);
  for (std::size_t pos = 0; pos < end; ++pos)
    buffer.push_back(static_cast<char>(line[pos].mChar));
}

std::string leading(const TextEditor::Line &line, std::size_t end) {
  std::string prefix;
  for (std::size_t pos = 0; pos < end; ++pos) {
    const char c = static_cast<char>(line[pos].mChar);
    if (c != ' ' && c != '\t')
      break;
    prefix.push_back(c);
  }
  return prefix;
}

std::string make_indent(int width, std::string_view preferred, int tab_size) {
  width = std::max(width, 0);
  if (columns(preferred, tab_size) == width)
    return std::string(preferred);
  // Preserve existing tabs, including mixed alignment prefixes. Never add tabs
  // to a space-indented line; only a pure-tab prefix opts into new tabs.
  if (preferred.find('\t') == std::string_view::npos)
    return std::string(static_cast<std::size_t>(width), ' ');
  std::string result;
  result.reserve(static_cast<std::size_t>(width));
  int column = 0;
  for (const char c : preferred) {
    const int next =
        c == '\t' ? column + tab_size - column % tab_size : column + 1;
    if (next > width)
      break;
    result.push_back(c);
    column = next;
  }
  if (preferred.find(' ') == std::string_view::npos) {
    while (column + tab_size - column % tab_size <= width) {
      result.push_back('\t');
      column += tab_size - column % tab_size;
    }
  }
  result.append(static_cast<std::size_t>(width - column), ' ');
  return result;
}

} // namespace

void colorize(TextEditor::Lines &lines) {
  Lexer lexer;
  Statement statement(4);
  std::string buffer;
  bool definition_name = false;
  bool decorator = false;
  bool attribute = false;
  for (std::size_t line_index = 0; line_index < lines.size(); ++line_index) {
    auto &line = lines[line_index];
    for (auto &glyph : line) {
      glyph.mColorIndex = Palette::Default;
      glyph.mComment = false;
      glyph.mMultiLineComment = false;
      glyph.mPreprocessor = false;
    }
    load_line(line, buffer, line.size());
    statement.begin_line(buffer, static_cast<int>(line_index));
    if (!statement.started()) {
      definition_name = false;
      decorator = false;
      attribute = false;
    }
    lexer.line(buffer, [&](const Token &token) {
      const auto word =
          std::string_view(buffer).substr(token.begin, token.end - token.begin);
      Palette palette = basic_palette(token.kind);
      const bool first = token.outer && !statement.started();
      const bool after_definition = definition_name;
      definition_name = false;
      if (first && word == "@") {
        decorator = true;
        palette = Palette::Preprocessor;
      } else if (decorator && (token.kind == Kind::Word || word == ".")) {
        palette = Palette::Preprocessor;
      } else {
        decorator = false;
        if (token.kind == Kind::Word) {
          const auto next = skip_space(buffer, token.end);
          const bool alias = first && word == "type" && next < buffer.size() &&
                             identifier_start(buffer[next]);
          if (contains(keywords, word) || alias) {
            palette = Palette::Keyword;
            definition_name = word == "def" || word == "class" || alias;
          } else if (after_definition) {
            palette = Palette::PreprocIdentifier;
          } else if (!attribute && contains(builtins, word)) {
            palette = Palette::KnownIdentifier;
          } else if (next < buffer.size() && buffer[next] == '(') {
            palette = Palette::PreprocIdentifier;
          }
        }
      }
      paint(line, token.begin, token.end, palette);
      attribute = word == ".";
      statement.consume(buffer, token);
      if (statement.suite_colon && statement.soft_line >= 0) {
        paint(lines[static_cast<std::size_t>(statement.soft_line)],
              statement.soft_begin, statement.soft_end, Palette::Keyword);
        statement.soft_line = -1;
      }
    });
    lexer.newline();
    statement.end_line(lexer.has_context());
  }
}

std::string indentation(const TextEditor::Lines &lines, int line,
                        int byte_column, int tab_size) {
  if (lines.empty())
    return {};
  line = std::clamp(line, 0, static_cast<int>(lines.size()) - 1);
  tab_size = std::max(tab_size, 1);
  const auto &current = lines[static_cast<std::size_t>(line)];
  const auto end = static_cast<std::size_t>(
      std::clamp(byte_column, 0, static_cast<int>(current.size())));
  const std::string prefix = leading(current, end);
  Lexer lexer;
  Statement statement(tab_size);
  std::string buffer;
  for (int index = 0; index <= line; ++index) {
    const auto &source = lines[static_cast<std::size_t>(index)];
    load_line(source, buffer, index == line ? end : source.size());
    statement.begin_line(buffer, index);
    lexer.line(buffer,
               [&](const Token &token) { statement.consume(buffer, token); });
    if (index < line) {
      lexer.newline();
      statement.end_line(lexer.has_context());
    }
  }
  if (lexer.in_literal())
    return prefix;
  if (!statement.delimiters.empty()) {
    const auto &open = statement.delimiters.back();
    const int width =
        open.alignment >= 0 ? open.alignment : open.indent + tab_size;
    return make_indent(width, prefix, tab_size);
  }
  if (lexer.has_context())
    return prefix;
  const auto &base = lines[static_cast<std::size_t>(statement.base_line)];
  const std::string base_prefix = leading(base, base.size());
  if (statement.backslash)
    return make_indent(
        std::max(statement.base_indent + tab_size, statement.line_indent),
        base_prefix, tab_size);
  if (statement.opens_suite())
    return make_indent(statement.base_indent + tab_size, base_prefix, tab_size);
  if (statement.kind == StatementKind::Terminal && statement.complete)
    return make_indent(statement.base_indent - tab_size, base_prefix, tab_size);
  if (statement.started() && statement.base_line != line)
    return make_indent(statement.base_indent, base_prefix, tab_size);
  return prefix;
}

} // namespace mydbg::app::python_syntax
