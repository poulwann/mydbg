#include "app/UiSupport.h"
#include "app/AppActions.h"
#include "app/AppState.h"

#include <SDL3/SDL.h>
#include <imgui_internal.h>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <initializer_list>

namespace mydbg::app {

const std::array<UiPanelSetting, 8> ui_panel_settings{{
    {"ShowThreads", l10n::Key::WindowThreads, &UiState::show_threads},
    {"ShowBacktrace", l10n::Key::WindowBacktrace, &UiState::show_backtrace},
    {"ShowStack", l10n::Key::WindowStackTelescope, &UiState::show_stack},
    {"ShowMemoryMap", l10n::Key::WindowMemoryMap, &UiState::show_memory_map},
    {"ShowModules", l10n::Key::WindowModules, &UiState::show_modules},
    {"ShowSecurity", l10n::Key::WindowElfSecurity, &UiState::show_security},
    {"ShowHeap", l10n::Key::WindowGlibcHeap, &UiState::show_heap},
    {"ShowScans", l10n::Key::WindowScans, &UiState::show_scans},
}};

constexpr float minimum_ui_scale = 0.75F;
constexpr float maximum_ui_scale = 4.0F;

static float clamp_ui_scale(float scale) {
  return std::clamp(scale, minimum_ui_scale, maximum_ui_scale);
}

float configured_ui_scale(float fallback) {
  const char *configured = std::getenv("MYDBG_UI_SCALE");
  if (configured == nullptr || *configured == '\0') {
    return fallback;
  }
  char *end = nullptr;
  const float scale = std::strtof(configured, &end);
  if (end == configured || *end != '\0' || !std::isfinite(scale)) {
    std::fprintf(stderr, l10n::text(l10n::Key::GuiSupportInvalidUiScale),
                 configured);
    return 1.0F;
  }
  return clamp_ui_scale(scale);
}

float window_display_scale(SDL_Window *window) {
  const float scale = SDL_GetWindowDisplayScale(window);
  return std::isfinite(scale) && scale > 0.0F ? scale : 1.0F;
}

void capture_window_state(SDL_Window *window, UiState &ui) {
  const SDL_WindowFlags flags = SDL_GetWindowFlags(window);
  ui.window_maximized = (flags & SDL_WINDOW_MAXIMIZED) != 0;
  if (ui.window_maximized || (flags & SDL_WINDOW_MINIMIZED) != 0 ||
      (flags & SDL_WINDOW_FULLSCREEN) != 0) {
    return;
  }
  SDL_GetWindowPosition(window, &ui.window_x, &ui.window_y);
  SDL_GetWindowSize(window, &ui.window_width, &ui.window_height);
  ui.window_position_saved = ui.window_width > 0 && ui.window_height > 0;
}

void SDLCALL executable_dialog_callback(void *userdata,
                                        const char *const *filelist, int) {
  auto &ui = *static_cast<UiState *>(userdata);
  const std::lock_guard lock{ui.file_dialog_mutex};
  ui.file_dialog_open = false;
  ui.selected_executable.reset();
  ui.selected_script.reset();
  if (filelist == nullptr) {
    ui.file_dialog_error = SDL_GetError();
  } else if (filelist[0] != nullptr) {
    if (ui.script_dialog) {
      ui.selected_script = filelist[0];
    } else {
      ui.selected_executable = filelist[0];
    }
    ui.file_dialog_error.clear();
  }
}

static void show_file_dialog(UiState &ui,
                             const std::array<SDL_DialogFileFilter, 2> &filters,
                             bool script) {
  {
    const std::lock_guard lock{ui.file_dialog_mutex};
    if (ui.file_dialog_open) {
      return;
    }
    ui.file_dialog_open = true;
    ui.file_dialog_error.clear();
    ui.script_dialog = script;
    ui.file_dialog_location =
        script ? ui.script_path.data() : ui.executable_path.data();
  }
  SDL_ShowOpenFileDialog(executable_dialog_callback, &ui, ui.main_window,
                         filters.data(), static_cast<int>(filters.size()),
                         ui.file_dialog_location.empty()
                             ? nullptr
                             : ui.file_dialog_location.c_str(),
                         false);
}

void show_executable_dialog(UiState &ui) {
  static const std::array<SDL_DialogFileFilter, 2> filters{{
      {l10n::text(l10n::Key::GuiSupportExecutableFiles), "elf;bin;out;so"},
      {l10n::text(l10n::Key::GuiSupportAllFiles), "*"},
  }};
  show_file_dialog(ui, filters, false);
}

void show_script_dialog(UiState &ui) {
  static const std::array<SDL_DialogFileFilter, 2> filters{{
      {l10n::text(l10n::Key::GuiSupportPythonScripts), "py"},
      {l10n::text(l10n::Key::GuiSupportAllFiles), "*"},
  }};
  show_file_dialog(ui, filters, true);
}

float effective_ui_scale(const UiState &ui) {
  return clamp_ui_scale(ui.display_scale * ui.user_scale);
}

void apply_ui_style(bool dark, float scale) {
  ImGui::GetStyle() = ImGuiStyle{};
  if (dark) {
    ImGui::StyleColorsDark();
  } else {
    ImGui::StyleColorsLight();
  }
  ImGuiStyle &style = ImGui::GetStyle();
  style.FontScaleMain = scale;
  style.ScaleAllSizes(scale);
}

void add_system_font(UiState &ui, std::string id, std::string label,
                     std::initializer_list<const char *> candidates) {
  for (const char *path : candidates) {
    if (!std::filesystem::exists(path)) {
      continue;
    }
    ImFont *font = ImGui::GetIO().Fonts->AddFontFromFileTTF(path, 13.0F);
    if (font != nullptr) {
      ui.fonts.push_back(UiFontChoice{std::move(id), std::move(label), font});
      return;
    }
  }
}

void load_ui_fonts(UiState &ui) {
  ui.fonts.push_back(UiFontChoice{
      "proggy-vector", l10n::label(l10n::Key::GuiSupportVectorFont),
      ImGui::GetIO().Fonts->AddFontDefaultVector()});
  add_system_font(
      ui, "system-monospace", l10n::label(l10n::Key::GuiSupportMonospaceFont),
      {"/usr/share/fonts/TTF/DejaVuSansMono.ttf",
       "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
       "/usr/share/fonts/liberation/LiberationMono-Regular.ttf",
       "C:/Windows/Fonts/consola.ttf", "/System/Library/Fonts/Menlo.ttc"});
  add_system_font(ui, "system-sans", l10n::label(l10n::Key::GuiSupportSansFont),
                  {"/usr/share/fonts/noto/NotoSans-Regular.ttf",
                   "/usr/share/fonts/TTF/DejaVuSans.ttf",
                   "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
                   "C:/Windows/Fonts/segoeui.ttf",
                   "/System/Library/Fonts/Helvetica.ttc"});
}

void select_ui_font(UiState &ui) {
  auto selected = std::find_if(
      ui.fonts.begin(), ui.fonts.end(),
      [&ui](const UiFontChoice &choice) { return choice.id == ui.font_id; });
  if (selected == ui.fonts.end()) {
    selected = ui.fonts.begin();
    ui.font_id = selected->id;
  }
  ImGui::GetIO().FontDefault = selected->font;
}

void *open_ui_settings(ImGuiContext *, ImGuiSettingsHandler *handler,
                       const char *name) {
  return std::strcmp(name, "Settings") == 0 ? handler->UserData : nullptr;
}

static bool navigation_mouse_key(ImGuiKey key) {
  return key >= ImGuiKey_MouseLeft && key <= ImGuiKey_MouseX2;
}

static bool binding_key_supported(ImGuiKey key, bool allow_mouse) {
  return (key >= ImGuiKey_NamedKey_BEGIN && key < ImGuiKey_GamepadStart) ||
         (allow_mouse && navigation_mouse_key(key));
}

void read_ui_setting(ImGuiContext *, ImGuiSettingsHandler *, void *entry,
                     const char *line) {
  auto &ui = *static_cast<UiState *>(entry);
  const std::string_view setting{line};
  const std::size_t separator = setting.find('=');
  if (separator == std::string_view::npos) {
    return;
  }
  const std::string_view key = setting.substr(0, separator);
  const std::string_view value = setting.substr(separator + 1);
  const auto integer_value = [value]() -> std::optional<int> {
    int parsed_value{};
    const auto parsed = std::from_chars(
        value.data(), value.data() + value.size(), parsed_value);
    return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size()
               ? std::optional<int>{parsed_value}
               : std::nullopt;
  };
  for (const auto &panel : ui_panel_settings) {
    if (key == panel.name) {
      ui.*panel.visible = value == "1";
      return;
    }
  }
  if (key == "Theme") {
    ui.theme_dark = value != "light";
  } else if (key == "UIScale") {
    std::string owned{value};
    char *end = nullptr;
    const float scale = std::strtof(owned.c_str(), &end);
    if (end != owned.c_str() && *end == '\0' && std::isfinite(scale)) {
      ui.user_scale = clamp_ui_scale(scale);
    }
  } else if (key == "Font") {
    if (!value.empty()) {
      ui.font_id = value;
    }
  } else if (key == "DisassemblyGraph") {
    ui.disassembly_graph_view = value == "1";
  } else if (key == "WindowX") {
    if (const auto parsed = integer_value()) {
      ui.window_x = *parsed;
    }
  } else if (key == "WindowY") {
    if (const auto parsed = integer_value()) {
      ui.window_y = *parsed;
    }
  } else if (key == "WindowWidth") {
    if (const auto parsed = integer_value(); parsed && *parsed > 0) {
      ui.window_width = *parsed;
    }
  } else if (key == "WindowHeight") {
    if (const auto parsed = integer_value(); parsed && *parsed > 0) {
      ui.window_height = *parsed;
    }
  } else if (key == "WindowPositionSaved") {
    ui.window_position_saved = value == "1";
  } else if (key == "WindowMaximized") {
    ui.window_maximized = value == "1";
  } else if (key.starts_with("Keybinding.") ||
             key.starts_with("PythonKeybinding.") ||
             key.starts_with("NavigationKeybinding.")) {
    const bool python_binding = key.starts_with("PythonKeybinding.");
    const bool navigation_binding = key.starts_with("NavigationKeybinding.");
    const std::string_view prefix =
        python_binding       ? std::string_view{"PythonKeybinding."}
        : navigation_binding ? std::string_view{"NavigationKeybinding."}
                             : std::string_view{"Keybinding."};
    const std::string_view id = key.substr(prefix.size());
    int raw_binding = 0;
    const auto parsed =
        std::from_chars(value.data(), value.data() + value.size(), raw_binding);
    if (parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size()) {
      const ImGuiKey key_code =
          static_cast<ImGuiKey>(raw_binding & ~ImGuiMod_Mask_);
      if (raw_binding == 0 ||
          binding_key_supported(key_code, navigation_binding)) {
        const auto load_binding = [&](const auto &actions, auto &bindings) {
          const auto action = std::find_if(
              actions.begin(), actions.end(),
              [id](const auto &definition) { return definition.id == id; });
          if (action != actions.end()) {
            bindings[action_index(action->action)] = raw_binding;
          }
        };
        if (python_binding) {
          load_binding(script_actions, ui.script_keybindings);
        } else if (navigation_binding) {
          load_binding(navigation_actions, ui.navigation_keybindings);
        } else {
          load_binding(debug_actions, ui.keybindings);
        }
      }
    }
  }
}

void write_ui_settings(ImGuiContext *, ImGuiSettingsHandler *handler,
                       ImGuiTextBuffer *output) {
  const auto &ui = *static_cast<const UiState *>(handler->UserData);
  output->appendf("[MyDbg][Settings]\n"
                  "Theme=%s\n"
                  "UIScale=%.3f\n"
                  "Font=%s\n",
                  ui.theme_dark ? "dark" : "light",
                  static_cast<double>(ui.user_scale), ui.font_id.c_str());
  for (const auto &panel : ui_panel_settings) {
    output->appendf("%s=%d\n", panel.name, ui.*panel.visible ? 1 : 0);
  }
  output->appendf("DisassemblyGraph=%d\n"
                  "WindowX=%d\n"
                  "WindowY=%d\n"
                  "WindowWidth=%d\n"
                  "WindowHeight=%d\n"
                  "WindowPositionSaved=%d\n"
                  "WindowMaximized=%d\n",
                  ui.disassembly_graph_view ? 1 : 0, ui.window_x, ui.window_y,
                  ui.window_width, ui.window_height,
                  ui.window_position_saved ? 1 : 0,
                  ui.window_maximized ? 1 : 0);
  for (const DebugActionDefinition &action : debug_actions) {
    output->appendf("Keybinding.%s=%d\n", action.id,
                    ui.keybindings[action_index(action.action)]);
  }
  for (const ScriptActionDefinition &action : script_actions) {
    output->appendf("PythonKeybinding.%s=%d\n", action.id,
                    ui.script_keybindings[action_index(action.action)]);
  }
  for (const NavigationActionDefinition &action : navigation_actions) {
    output->appendf("NavigationKeybinding.%s=%d\n", action.id,
                    ui.navigation_keybindings[action_index(action.action)]);
  }
  output->append("\n");
}

void register_ui_settings(UiState &ui) {
  ImGuiSettingsHandler handler;
  handler.TypeName = "MyDbg";
  handler.TypeHash = ImHashStr(handler.TypeName);
  handler.ReadOpenFn = open_ui_settings;
  handler.ReadLineFn = read_ui_setting;
  handler.WriteAllFn = write_ui_settings;
  handler.UserData = &ui;
  ImGui::AddSettingsHandler(&handler);
}

std::string migrate_window_layout(std::string_view layout) {
  struct WindowIdentity {
    std::string_view legacy_name;
    std::string_view stable_name;
    ImGuiID legacy_id;
    ImGuiID stable_id;
  };
  std::vector<WindowIdentity> identities;
  identities.reserve(l10n::window_keys().size() + 1);
  const auto add_identity = [&identities](l10n::Key key) {
    const char *legacy = l10n::english(key);
    const std::string_view translated = l10n::label(key);
    const std::string_view stable = translated.substr(translated.rfind("###"));
    identities.push_back(
        {legacy, stable, ImHashStr(legacy), ImHashStr(stable.data())});
  };
  for (const l10n::Key key : l10n::window_keys()) {
    add_identity(key);
  }
  add_identity(l10n::Key::GuiSupportPatchInstruction);

  std::string migrated;
  migrated.reserve(layout.size());
  bool docking_section = false;
  while (!layout.empty()) {
    const std::size_t newline = layout.find('\n');
    const std::string_view line = layout.substr(0, newline);
    const std::string_view content =
        line.ends_with('\r') ? line.substr(0, line.size() - 1) : line;
    if (content.starts_with('[')) {
      docking_section = content == "[Docking][Data]";
    }
    const WindowIdentity *window = nullptr;
    if (content.starts_with("[Window][") && content.ends_with(']')) {
      const std::string_view name = content.substr(9, content.size() - 10);
      for (const auto &identity : identities) {
        if (name == identity.legacy_name) {
          window = &identity;
          break;
        }
      }
    }
    if (window != nullptr) {
      migrated.append("[Window][");
      migrated.append(window->stable_name);
      migrated.push_back(']');
      if (line.ends_with('\r')) {
        migrated.push_back('\r');
      }
    } else if (docking_section) {
      // Dock nodes retain their IDs; only references to window IDs change.
      std::size_t copied = 0;
      for (std::size_t offset = 0; offset < line.size(); ++offset) {
        const std::string_view field = line.substr(offset);
        const std::size_t prefix = field.starts_with(" Selected=0x") ? 12
                                   : field.starts_with(" Window=0x") ? 10
                                                                     : 0;
        if (prefix == 0) {
          continue;
        }
        const char *begin = line.data() + offset + prefix;
        ImGuiID old_id{};
        const auto [end, error] =
            std::from_chars(begin, line.data() + line.size(), old_id, 16);
        if (error != std::errc{} ||
            (end != line.data() + line.size() && *end != ' ' && *end != '\t' &&
             *end != '\r')) {
          continue;
        }
        for (const auto &identity : identities) {
          if (old_id == identity.legacy_id) {
            migrated.append(line.substr(copied, offset + prefix - copied));
            char id[9]{};
            std::snprintf(id, sizeof(id), "%08X", identity.stable_id);
            migrated.append(id);
            copied = static_cast<std::size_t>(end - line.data());
            break;
          }
        }
        offset = static_cast<std::size_t>(end - line.data()) - 1;
      }
      migrated.append(line.substr(copied));
    } else {
      migrated.append(line);
    }
    if (newline == std::string_view::npos) {
      break;
    }
    migrated.push_back('\n');
    layout.remove_prefix(newline + 1);
  }
  return migrated;
}

std::uint32_t panel_visibility(const UiState &ui) {
  std::uint32_t visibility = 0;
  for (std::size_t index = 0; index < std::size(ui_panel_settings); ++index) {
    if (ui.*ui_panel_settings[index].visible)
      visibility |= 1U << index;
  }
  return visibility;
}

void ui_focus_navigation_target(AppNavigationTarget target) {
  if (target == AppNavigationTarget::Memory) {
    ImGui::SetWindowCollapsed(l10n::label(l10n::Key::WindowMemoryDump), false);
    ImGui::SetWindowFocus(l10n::label(l10n::Key::WindowMemoryDump));
  }
}

bool follow_address(const debugger::SessionSnapshot &snapshot,
                    debugger::LldbEngine &engine, UiState &ui,
                    std::uint64_t address) {
  const AppNavigationTarget target =
      app_follow_address(snapshot, engine, ui, address);
  ui_focus_navigation_target(target);
  return target != AppNavigationTarget::None;
}

bool navigation_input_allowed(const UiState &ui) {
  return !ui.keybinding_capture && !ImGui::GetIO().WantTextInput &&
         ImGui::GetActiveID() == 0 && !ui.condition_editor_requested &&
         !ui.editing_breakpoint && !ui.creating_conditional_breakpoint &&
         !ui.instruction_patch_address && ui.register_edit_name.empty() &&
         !ui.memory_edit_mode &&
         ui.decompiler_dialog == DecompilerDialog::None &&
         !ui.navigation_dialog_requested && !ui.navigation_dialog_open &&
         !ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId |
                                          ImGuiPopupFlags_AnyPopupLevel);
}

void dispatch_navigation_shortcuts(const debugger::SessionSnapshot &snapshot,
                                   debugger::LldbEngine &engine, UiState &ui,
                                   bool decompiler_view, bool control_lease) {
  ui.navigation_control_locked = control_lease;
  if (control_lease || snapshot.state != debugger::SessionState::Stopped ||
      ui.navigation_dispatch_frame == ImGui::GetFrameCount() ||
      !navigation_input_allowed(ui)) {
    return;
  }
  const bool focused =
      ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
  const bool hovered =
      ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows);
  for (const NavigationActionDefinition &definition : navigation_actions) {
    const ImGuiKeyChord binding =
        ui.navigation_keybindings[action_index(definition.action)];
    const ImGuiKey key = static_cast<ImGuiKey>(binding & ~ImGuiMod_Mask_);
    const bool mouse = navigation_mouse_key(key);
    if (binding == 0 || !(mouse ? hovered : focused) ||
        !ImGui::Shortcut(binding, mouse ? ImGuiInputFlags_RouteAlways
                                        : ImGuiInputFlags_RouteFocused)) {
      continue;
    }
    // Focus changes may make the second code pane eligible later this frame.
    ui.navigation_dispatch_frame = ImGui::GetFrameCount();
    ImGui::SetKeyOwner(key, ImGui::GetCurrentWindow()->ID,
                       ImGuiInputFlags_LockThisFrame);
    switch (definition.action) {
    case NavigationAction::Back:
    case NavigationAction::MouseBack:
      app_traverse_navigation_history(snapshot, engine, ui, false);
      break;
    case NavigationAction::Forward:
    case NavigationAction::MouseForward:
      app_traverse_navigation_history(snapshot, engine, ui, true);
      break;
    case NavigationAction::Follow:
      ui.navigation_follow_requested = true;
      break;
    case NavigationAction::JumpAddress:
      app_request_navigation_dialog(snapshot, ui, decompiler_view);
      break;
    case NavigationAction::ToggleGraph:
      if (decompiler_view) {
        ImGui::SetWindowCollapsed(l10n::label(l10n::Key::WindowDisassembly),
                                  false);
        ImGui::SetWindowFocus(l10n::label(l10n::Key::WindowDisassembly));
      }
      app_toggle_navigation_graph(ui);
      ImGui::MarkIniSettingsDirty();
      break;
    case NavigationAction::SwitchView: {
      const char *window =
          l10n::label(decompiler_view ? l10n::Key::WindowDisassembly
                                      : l10n::Key::WindowDecompiler);
      ImGui::SetWindowCollapsed(window, false);
      ImGui::SetWindowFocus(window);
      break;
    }
    case NavigationAction::Count:
      break;
    }
    break;
  }
}

std::string keybinding_name(const UiState &ui, DebugAction action) {
  const ImGuiKeyChord binding = ui.keybindings[action_index(action)];
  return binding == 0 ? std::string{}
                      : std::string{ImGui::GetKeyChordName(binding)};
}

void dispatch_debugger_shortcuts(const debugger::SessionSnapshot &snapshot,
                                 debugger::LldbEngine &engine,
                                 const UiState &ui, bool control_lease) {
  if (ui.keybinding_capture || ImGui::GetIO().WantTextInput) {
    return;
  }
  const ImGuiWindow *focused = ImGui::GetCurrentContext()->NavWindow;
  const bool code_focused =
      focused != nullptr &&
      (focused->RootWindow->ID ==
           ImHashStr(l10n::label(l10n::Key::WindowDisassembly)) ||
       focused->RootWindow->ID ==
           ImHashStr(l10n::label(l10n::Key::WindowDecompiler)));
  const bool navigation_active =
      code_focused && !control_lease &&
      snapshot.state == debugger::SessionState::Stopped &&
      navigation_input_allowed(ui);
  constexpr ImGuiInputFlags route = ImGuiInputFlags_RouteGlobal;
  for (const DebugActionDefinition &definition : debug_actions) {
    const bool lease_allows_action =
        !control_lease || definition.action == DebugAction::Pause ||
        definition.action == DebugAction::Terminate;
    const ImGuiKeyChord binding =
        ui.keybindings[action_index(definition.action)];
    // Navigation has priority even for collisions loaded from an older ini,
    // before the code panels register their focused shortcut routes.
    if (navigation_active &&
        std::find(ui.navigation_keybindings.begin(),
                  ui.navigation_keybindings.end(),
                  binding) != ui.navigation_keybindings.end()) {
      continue;
    }
    if (lease_allows_action && binding != 0 &&
        ImGui::Shortcut(binding, route) &&
        debug_action_enabled(definition.action, snapshot, ui)) {
      execute_debug_action(definition.action, snapshot, engine, ui);
      break;
    }
  }
}

bool modifier_key(ImGuiKey key) {
  return key == ImGuiKey_LeftCtrl || key == ImGuiKey_RightCtrl ||
         key == ImGuiKey_LeftShift || key == ImGuiKey_RightShift ||
         key == ImGuiKey_LeftAlt || key == ImGuiKey_RightAlt ||
         key == ImGuiKey_LeftSuper || key == ImGuiKey_RightSuper;
}

void assign_keybinding(UiState &ui, std::size_t capture_index,
                       ImGuiKeyChord binding) {
  ui.keybinding_message.clear();
  const auto remove_duplicates = [&](auto &bindings, const auto &actions,
                                     std::size_t keep, l10n::Key message) {
    if (binding == 0) {
      return;
    }
    for (std::size_t other = 0; other < bindings.size(); ++other) {
      if (other != keep && bindings[other] == binding) {
        bindings[other] = 0;
        ui.keybinding_message =
            l10n::format(message, l10n::text(actions[other].label));
      }
    }
  };
  const std::size_t navigation_begin =
      debug_actions.size() + script_actions.size();
  if (capture_index < debug_actions.size()) {
    remove_duplicates(ui.keybindings, debug_actions, capture_index,
                      l10n::Key::GuiSupportDuplicateNativeBinding);
    remove_duplicates(ui.navigation_keybindings, navigation_actions,
                      navigation_actions.size(),
                      l10n::Key::GuiSupportDuplicateNavigationBinding);
    ui.keybindings[capture_index] = binding;
  } else if (capture_index < navigation_begin) {
    const std::size_t script_index = capture_index - debug_actions.size();
    remove_duplicates(ui.script_keybindings, script_actions, script_index,
                      l10n::Key::GuiSupportDuplicatePythonBinding);
    ui.script_keybindings[script_index] = binding;
  } else if (capture_index < navigation_begin + navigation_actions.size()) {
    const std::size_t navigation_index = capture_index - navigation_begin;
    remove_duplicates(ui.navigation_keybindings, navigation_actions,
                      navigation_index,
                      l10n::Key::GuiSupportDuplicateNavigationBinding);
    remove_duplicates(ui.keybindings, debug_actions, debug_actions.size(),
                      l10n::Key::GuiSupportDuplicateNativeBinding);
    ui.navigation_keybindings[navigation_index] = binding;
  } else {
    ui.keybinding_capture.reset();
    return;
  }
  ui.keybinding_capture.reset();
  ImGui::MarkIniSettingsDirty();
}

void ui_restore_keybindings(UiState &ui) {
  ui.keybindings = default_keybindings();
  ui.script_keybindings = default_script_keybindings();
  ui.navigation_keybindings = default_navigation_keybindings();
  ui.keybinding_capture.reset();
  ui.keybinding_message = l10n::text(l10n::Key::GuiSupportDefaultsRestored);
  ImGui::MarkIniSettingsDirty();
}

void ui_capture_keybinding(UiState &ui) {
  if (ui.keybinding_capture) {
    ImGui::SetNextFrameWantCaptureKeyboard(true);
    const bool navigation_capture =
        *ui.keybinding_capture >= debug_actions.size() + script_actions.size();
    if (navigation_capture) {
      ImGui::SetNextFrameWantCaptureMouse(true);
    }
    // A binding button's activation must not assign that same input.
    if (ui.keybinding_capture_frame != ImGui::GetFrameCount()) {
      const ImGuiKey clear_key =
          navigation_capture ? ImGuiKey_Delete : ImGuiKey_Escape;
      if (ImGui::IsKeyPressed(clear_key, false)) {
        assign_keybinding(ui, *ui.keybinding_capture, 0);
      } else {
        const int key_end =
            navigation_capture ? ImGuiKey_MouseX2 + 1 : ImGuiKey_GamepadStart;
        for (int raw_key = ImGuiKey_NamedKey_BEGIN; raw_key < key_end;
             ++raw_key) {
          const ImGuiKey key = static_cast<ImGuiKey>(raw_key);
          if (binding_key_supported(key, navigation_capture) &&
              !modifier_key(key) && ImGui::IsKeyPressed(key, false)) {
            assign_keybinding(ui, *ui.keybinding_capture,
                              ImGui::GetIO().KeyMods | key);
            break;
          }
        }
      }
    }
  }
}

} // namespace mydbg::app
