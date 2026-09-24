#include "app/HelpContent.h"

#include <png.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <utility>

namespace debugger::help {
namespace {

std::string chapter_title(std::string_view markdown,
                          std::string_view fallback) {
  const std::size_t heading = markdown.find("# ");
  if (heading != std::string_view::npos) {
    const std::size_t start = heading + 2;
    const std::size_t end = markdown.find('\n', start);
    return std::string{markdown.substr(start, end - start)};
  }
  return std::string{fallback};
}

struct PngReader {
  png_image image{};

  ~PngReader() { png_image_free(&image); }
};

HelpPngImage load_png(const std::filesystem::path &path) {
  PngReader reader;
  reader.image.version = PNG_IMAGE_VERSION;
  if (!png_image_begin_read_from_file(&reader.image, path.c_str()))
    return {};
  if (reader.image.width == 0 || reader.image.height == 0 ||
      reader.image.width > 4096 || reader.image.height > 4096)
    return {};

  reader.image.format = PNG_FORMAT_RGBA;
  HelpPngImage image{
      .width = static_cast<int>(reader.image.width),
      .height = static_cast<int>(reader.image.height),
      .pixels = std::vector<std::uint8_t>(PNG_IMAGE_SIZE(reader.image))};
  if (!png_image_finish_read(&reader.image, nullptr, image.pixels.data(), 0,
                             nullptr))
    return {};
  return image;
}

} // namespace

HelpContent::HelpContent() {
  titles.reserve(chapters.size());
  search_texts.reserve(chapters.size());
  for (const manual::ChapterAsset &chapter : chapters) {
    titles.push_back(chapter_title(chapter.markdown, chapter.file_name));
    search_texts.push_back(help_search_filter(titles.back() + " " +
                                              std::string{chapter.markdown}));
  }
}

bool HelpContent::matches(std::size_t index, std::string_view filter) const {
  return filter.empty() ||
         search_texts[index].find(filter) != std::string::npos;
}

std::optional<std::size_t>
HelpContent::find_chapter(std::string_view file_name) const {
  const auto found =
      std::find_if(chapters.begin(), chapters.end(),
                   [file_name](const manual::ChapterAsset &candidate) {
                     return candidate.file_name == file_name;
                   });
  if (found != chapters.end())
    return static_cast<std::size_t>(std::distance(chapters.begin(), found));
  return std::nullopt;
}

HelpLink HelpContent::resolve_link(std::string_view target) const {
  std::string link{target};
  const std::size_t anchor = link.find('#');
  if (anchor != std::string::npos)
    link.resize(anchor);
  if (const auto chapter = find_chapter(link))
    return {.chapter = chapter, .url = {}};
  if (link.starts_with("https://") || link.starts_with("http://"))
    return {.chapter = std::nullopt, .url = std::move(link)};
  return {};
}

std::string help_search_filter(std::string_view value) {
  std::string result{value};
  std::transform(result.begin(), result.end(), result.begin(), [](char byte) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(byte)));
  });
  return result;
}

bool help_safe_relative_path(std::string_view path) {
  const std::filesystem::path candidate{path};
  if (candidate.empty() || candidate.is_absolute())
    return false;
  return std::none_of(candidate.begin(), candidate.end(),
                      [](const auto &part) { return part == ".."; });
}

HelpPngImage help_load_image(const std::string &key, const char *base_path) {
  const std::array candidates{
      std::filesystem::path{MYDBG_MANUAL_ASSET_DIR} / key,
      (base_path != nullptr ? std::filesystem::path{base_path}
                            : std::filesystem::path{}) /
          "manual" / key,
  };
  HelpPngImage image;
  for (const std::filesystem::path &path : candidates) {
    try {
      image = load_png(path);
    } catch (...) {
      image = {};
    }
    if (!image.pixels.empty())
      break;
  }
  return image;
}

std::optional<HelpCodeBlock> help_code_block(std::string_view markdown,
                                             std::size_t fence) {
  const std::size_t language_end = markdown.find('\n', fence + 3);
  const std::size_t close = language_end == std::string_view::npos
                                ? std::string_view::npos
                                : markdown.find("```", language_end + 1);
  if (close == std::string_view::npos)
    return std::nullopt;
  const std::string_view language =
      markdown.substr(fence + 3, language_end - fence - 3);
  std::string_view code =
      markdown.substr(language_end + 1, close - language_end - 1);
  if (!code.empty() && code.back() == '\n')
    code.remove_suffix(1);
  return HelpCodeBlock{language, code, close + 3};
}

} // namespace debugger::help
