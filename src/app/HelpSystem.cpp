#include "app/HelpSystem.h"

#include "app/HelpContent.h"
#include "localization/Localization.h"

#include <SDL3/SDL.h>
#include <SDL3/SDL_opengl.h>
#include <imgui.h>
#include <imgui_markdown.h>

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <unordered_map>

namespace debugger::help {

struct HelpSystem::Impl {
  struct Texture {
    GLuint id{};
    int width{};
    int height{};
  };

  bool visible{};
  std::size_t selected{};
  std::array<char, 128> search{};
  HelpContent content;
  std::unordered_map<std::string, Texture> textures;

  static void link_callback(ImGui::MarkdownLinkCallbackData data) {
    auto &self = *static_cast<Impl *>(data.userData);
    if (data.isImage)
      return;
    const HelpLink link = self.content.resolve_link(
        {data.link, static_cast<std::size_t>(data.linkLength)});
    if (link.chapter) {
      self.selected = *link.chapter;
      return;
    }
    if (!link.url.empty())
      SDL_OpenURL(link.url.c_str());
  }

  Texture *texture(std::string_view relative_path) {
    if (!help_safe_relative_path(relative_path))
      return nullptr;
    const std::string key{relative_path};
    if (const auto found = textures.find(key); found != textures.end())
      return found->second.id == 0 ? nullptr : &found->second;

    const char *base_path = SDL_GetBasePath();
    HelpPngImage image = help_load_image(key, base_path);
    if (image.pixels.empty()) {
      textures.emplace(key, Texture{});
      return nullptr;
    }

    GLuint id = 0;
    glGenTextures(1, &id);
    glBindTexture(GL_TEXTURE_2D, id);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, image.width, image.height, 0,
                 GL_RGBA, GL_UNSIGNED_BYTE, image.pixels.data());
    glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
    glBindTexture(GL_TEXTURE_2D, 0);
    auto [inserted, unused] = textures.emplace(
        key, Texture{.id = id, .width = image.width, .height = image.height});
    (void)unused;
    return &inserted->second;
  }

  static ImGui::MarkdownImageData
  image_callback(ImGui::MarkdownLinkCallbackData data) {
    auto &self = *static_cast<Impl *>(data.userData);
    const std::string_view path{data.link,
                                static_cast<std::size_t>(data.linkLength)};
    Texture *image = self.texture(path);
    if (image == nullptr)
      return {};
    ImVec2 size{static_cast<float>(image->width),
                static_cast<float>(image->height)};
    const float available = ImGui::GetContentRegionAvail().x;
    if (size.x > available && available > 0.0F) {
      size.y *= available / size.x;
      size.x = available;
    }
    ImGui::MarkdownImageData result;
    result.isValid = true;
    result.useLinkCallback = false;
    result.user_texture_id = static_cast<ImTextureID>(image->id);
    result.size = size;
    return result;
  }

  ImGui::MarkdownConfig markdown_config() {
    ImGui::MarkdownConfig config;
    config.linkCallback = link_callback;
    config.imageCallback = image_callback;
    config.linkIcon = "";
    config.userData = this;
    config.formatFlags = ImGuiMarkdownFormatFlags_GithubStyle;
    ImFont *font = ImGui::GetFont();
    const float base = ImGui::GetStyle().FontSizeBase;
    config.headingFormats[0] = {font, true, base * 1.65F};
    config.headingFormats[1] = {font, true, base * 1.35F};
    config.headingFormats[2] = {font, false, base * 1.15F};
    return config;
  }

  static void draw_code(std::string_view language, std::string_view code,
                        int index) {
    int lines = 1;
    for (const char byte : code)
      lines += byte == '\n' ? 1 : 0;
    const float height =
        std::min(280.0F, ImGui::GetTextLineHeightWithSpacing() *
                                 static_cast<float>(lines) +
                             34.0F);
    ImGui::PushID(index);
    ImGui::PushStyleColor(ImGuiCol_ChildBg,
                          ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
    ImGui::BeginChild("code", ImVec2(-1.0F, height), ImGuiChildFlags_Borders,
                      ImGuiWindowFlags_HorizontalScrollbar);
    if (!language.empty())
      ImGui::TextDisabled("%.*s", static_cast<int>(language.size()),
                          language.data());
    ImGui::TextUnformatted(code.data(), code.data() + code.size());
    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::PopID();
  }

  void render_markdown(std::string_view markdown) {
    const ImGui::MarkdownConfig config = markdown_config();
    std::size_t cursor = 0;
    int code_index = 0;
    while (cursor < markdown.size()) {
      const std::size_t fence = markdown.find("```", cursor);
      if (fence == std::string_view::npos) {
        ImGui::Markdown(markdown.data() + cursor, markdown.size() - cursor,
                        config);
        break;
      }
      if (fence > cursor)
        ImGui::Markdown(markdown.data() + cursor, fence - cursor, config);
      const auto block = help_code_block(markdown, fence);
      if (!block) {
        ImGui::Markdown(markdown.data() + fence, markdown.size() - fence,
                        config);
        break;
      }
      draw_code(block->language, block->code, code_index++);
      cursor = block->next_cursor;
    }
  }

  void draw() {
    if (!visible)
      return;
    ImGui::SetNextWindowSize(ImVec2(1080.0F, 760.0F), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(l10n::label(l10n::Key::WindowDebuggerManual), &visible,
                      ImGuiWindowFlags_NoCollapse)) {
      ImGui::End();
      return;
    }

    ImGui::BeginChild("chapters", ImVec2(230.0F, 0.0F),
                      ImGuiChildFlags_Borders);
    ImGui::TextUnformatted(l10n::text(l10n::Key::GuiHelpManualChapters));
    ImGui::SetNextItemWidth(-1.0F);
    ImGui::InputTextWithHint("##manual-search",
                             l10n::text(l10n::Key::GuiHelpFilterChapters),
                             search.data(), search.size());
    ImGui::Separator();
    const std::string filter = help_search_filter(search.data());
    for (std::size_t index = 0; index < content.chapters.size(); ++index) {
      if (!content.matches(index, filter)) {
        continue;
      }
      if (ImGui::Selectable(content.titles[index].c_str(), selected == index))
        selected = index;
    }
    ImGui::EndChild();
    ImGui::SameLine();

    ImGui::BeginChild("chapter-content", ImVec2(0.0F, 0.0F),
                      ImGuiChildFlags_Borders);
    if (ImGui::Button(l10n::label(l10n::Key::GuiHelpPrevious)) && selected > 0)
      --selected;
    ImGui::SameLine();
    if (ImGui::Button(l10n::label(l10n::Key::GuiHelpNext)) &&
        selected + 1 < content.chapters.size())
      ++selected;
    ImGui::SameLine();
    ImGui::TextDisabled("%zu / %zu", selected + 1, content.chapters.size());
    ImGui::Separator();
    render_markdown(content.chapters[selected].markdown);
    ImGui::EndChild();
    ImGui::End();
  }

  void shutdown() {
    for (const auto &[unused, texture] : textures) {
      (void)unused;
      if (texture.id != 0)
        glDeleteTextures(1, &texture.id);
    }
    textures.clear();
  }
};

HelpSystem::HelpSystem() : impl_(std::make_unique<Impl>()) {}
HelpSystem::~HelpSystem() = default;

void HelpSystem::open(std::string_view chapter) {
  impl_->visible = true;
  if (chapter.empty())
    return;
  if (const auto found = impl_->content.find_chapter(chapter))
    impl_->selected = *found;
}

void HelpSystem::draw() { impl_->draw(); }
void HelpSystem::shutdown() { impl_->shutdown(); }

} // namespace debugger::help
