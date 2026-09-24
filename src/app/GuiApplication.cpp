#include "app/GuiApplication.h"
#include "DefaultLayout.h"
#include "app/AppActions.h"
#include "app/AppDrawing.h"
#include "app/AppState.h"
#include "app/ApplicationController.h"
#include "app/HelpSystem.h"
#include "app/PythonPanels.h"
#include "app/UiSupport.h"
#include "plugins/PluginApi.h"

#include <SDL3/SDL.h>
#include <SDL3/SDL_opengl.h>
#include <backends/imgui_impl_opengl3.h>
#include <backends/imgui_impl_sdl3.h>
#include <imgui_internal.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <string>

namespace mydbg::app {

int run_gui(const char *initial_executable, const char *initial_script) {
  if (!SDL_Init(SDL_INIT_VIDEO)) {
    std::fprintf(stderr, l10n::text(l10n::Key::AppSdlInitializationFailed),
                 SDL_GetError());
    return 10;
  }

  SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
  SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 0);
  SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 0);

  SDL_Window *window =
      SDL_CreateWindow(l10n::text(l10n::Key::AppWindowTitle), 1440, 900,
                       SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE |
                           SDL_WINDOW_HIGH_PIXEL_DENSITY | SDL_WINDOW_HIDDEN);
  if (window == nullptr) {
    std::fprintf(stderr, l10n::text(l10n::Key::AppWindowCreationFailed),
                 SDL_GetError());
    SDL_Quit();
    return 11;
  }
  UiState ui;
  ui.main_window = window;

  SDL_GLContext gl_context = SDL_GL_CreateContext(window);
  if (gl_context == nullptr) {
    std::fprintf(stderr, l10n::text(l10n::Key::AppOpenGlContextFailed),
                 SDL_GetError());
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 12;
  }
  SDL_GL_MakeCurrent(window, gl_context);
  SDL_GL_SetSwapInterval(1);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
  const char *base_path = SDL_GetBasePath();
  const std::filesystem::path user_layout_path =
      base_path != nullptr ? std::filesystem::path{base_path} / "mydbg.ini"
                           : std::filesystem::path{"mydbg.ini"};
  const std::string user_layout_filename = user_layout_path.string();
  io.IniFilename = user_layout_filename.c_str();
  register_ui_settings(ui);
  const bool has_local_layout =
      std::filesystem::is_regular_file(user_layout_path);
  std::string layout;
  if (has_local_layout) {
    std::size_t size = 0;
    const std::unique_ptr<char, decltype(&ImGui::MemFree)> saved{
        static_cast<char *>(ImFileLoadToMemory(io.IniFilename, "rb", &size)),
        ImGui::MemFree};
    layout = migrate_window_layout(saved ? std::string_view{saved.get(), size}
                                         : std::string_view{});
  } else {
    layout = migrate_window_layout(default_layout);
  }
  ImGui::LoadIniSettingsFromMemory(layout.c_str(), layout.size());
  SDL_SetWindowSize(window, std::max(ui.window_width, 640),
                    std::max(ui.window_height, 480));
  if (ui.window_position_saved) {
    SDL_SetWindowPosition(window, ui.window_x, ui.window_y);
  }
  SDL_ShowWindow(window);
  if (ui.window_maximized) {
    SDL_MaximizeWindow(window);
    SDL_SyncWindow(window);
  }
  ui.display_scale = window_display_scale(window);
  ui.user_scale = configured_ui_scale(ui.user_scale);
  load_ui_fonts(ui);
  select_ui_font(ui);
  ui.applied_ui_scale = effective_ui_scale(ui);
  ui.applied_dark_theme = ui.theme_dark;
  apply_ui_style(ui.theme_dark, ui.applied_ui_scale);
  ImGui_ImplSDL3_InitForOpenGL(window, gl_context);
  ImGui_ImplOpenGL3_Init("#version 330 core");

  debugger::plugins::PluginLoader plugin_loader;
  load_plugins(plugin_loader);
  const auto sessions = std::make_shared<debugger::SessionStore>(
      debugger::SessionStore::default_directory());
  debugger::LldbEngine engine{sessions};
  debugger::scripting::PythonRuntime python{engine};
  debugger::DecompilerEngine decompiler{sessions};
  debugger::help::HelpSystem help;
  initialize_application(initial_executable, initial_script, engine, python,
                         ui);

  bool done = false;
  bool focus_disassembly_on_first_frame =
      !has_local_layout && initial_script == nullptr;
  while (!done) {
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
      ImGui_ImplSDL3_ProcessEvent(&event);
      if (event.type == SDL_EVENT_QUIT) {
        done = true;
      }
      if (event.type == SDL_EVENT_WINDOW_DISPLAY_SCALE_CHANGED &&
          event.window.windowID == SDL_GetWindowID(window)) {
        ui.display_scale = window_display_scale(window);
      }
      const bool geometry_event = event.type == SDL_EVENT_WINDOW_MOVED ||
                                  event.type == SDL_EVENT_WINDOW_RESIZED ||
                                  event.type == SDL_EVENT_WINDOW_MAXIMIZED ||
                                  event.type == SDL_EVENT_WINDOW_RESTORED;
      if (geometry_event && event.window.windowID == SDL_GetWindowID(window)) {
        capture_window_state(window, ui);
        ImGui::MarkIniSettingsDirty();
      }
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL3_NewFrame();
    ImGui::NewFrame();
    debugger::SessionSnapshot snapshot = engine.snapshot();
    update_application_session(snapshot, *sessions, ui);
    const debugger::scripting::ScriptSnapshot script = python.snapshot();
    if (synchronize_application_theme(snapshot, ui)) {
      ImGui::MarkIniSettingsDirty();
    }
    const float requested_ui_scale = effective_ui_scale(ui);
    if (ui.applied_dark_theme != ui.theme_dark ||
        std::abs(ui.applied_ui_scale - requested_ui_scale) > 0.001F) {
      apply_ui_style(ui.theme_dark, requested_ui_scale);
      ui.applied_dark_theme = ui.theme_dark;
      ui.applied_ui_scale = requested_ui_scale;
    }
    const std::uint32_t visibility_before = panel_visibility(ui);
    update_application_selection(snapshot, ui);
    const auto decompiled =
        update_application_decompiler(snapshot, decompiler, ui);
    dispatch_contextual_shortcuts(snapshot, engine, python, ui, script);
    draw_application_workspace(
        snapshot, script, decompiled, engine, decompiler, python, ui, help,
        focus_disassembly_on_first_frame, visibility_before);
    ImGui::Render();
    int width = 0;
    int height = 0;
    SDL_GetWindowSizeInPixels(window, &width, &height);
    glViewport(0, 0, width, height);
    glClearColor(0.06F, 0.07F, 0.09F, 1.0F);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    SDL_GL_SwapWindow(window);
  }
  python.shutdown();

  capture_window_state(window, ui);
  ImGui::SaveIniSettingsToDisk(io.IniFilename);
  help.shutdown();
  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplSDL3_Shutdown();
  ImGui::DestroyContext();
  SDL_GL_DestroyContext(gl_context);
  SDL_DestroyWindow(window);
  SDL_Quit();
  return 0;
}

} // namespace mydbg::app
