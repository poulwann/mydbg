#pragma once

#include "ManualContent.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace debugger::help {

struct HelpLink {
  std::optional<std::size_t> chapter;
  std::string url;
};

struct HelpContent {
  std::span<const manual::ChapterAsset> chapters{manual::chapters};
  std::vector<std::string> titles;
  std::vector<std::string> search_texts;

  HelpContent();
  bool matches(std::size_t index, std::string_view filter) const;
  std::optional<std::size_t> find_chapter(std::string_view file_name) const;
  HelpLink resolve_link(std::string_view target) const;
};

std::string help_search_filter(std::string_view value);
bool help_safe_relative_path(std::string_view path);

struct HelpPngImage {
  int width{};
  int height{};
  std::vector<std::uint8_t> pixels;
};

// Called after path validation and the renderer's texture-cache lookup.
HelpPngImage help_load_image(const std::string &key, const char *base_path);

struct HelpCodeBlock {
  std::string_view language;
  std::string_view code;
  std::size_t next_cursor{};
};

std::optional<HelpCodeBlock> help_code_block(std::string_view markdown,
                                             std::size_t fence);

} // namespace debugger::help
