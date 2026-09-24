#include "app/AppDrawing.h"
#include "app/AppMenus.h"
#include "app/AppState.h"
#include "app/DebuggerPanels.h"
#include "app/DecompilerPanels.h"
#include "app/HelpSystem.h"
#include "app/MemoryPanels.h"
#include "app/PythonPanels.h"
#include "app/UiSupport.h"
#include "plugins/PluginApi.h"

#include <imgui_internal.h>

namespace mydbg::app {

void draw_application_workspace(
    const debugger::SessionSnapshot &snapshot,
    const debugger::scripting::ScriptSnapshot &script,
    const std::shared_ptr<const debugger::DecompilerSnapshot> &decompiled,
    debugger::LldbEngine &engine, debugger::DecompilerEngine &decompiler,
    debugger::scripting::PythonRuntime &python, UiState &ui,
    debugger::help::HelpSystem &help, bool &focus_disassembly_on_first_frame,
    std::uint32_t visibility_before) {
  const bool native_views_locked =
      script.control_lease &&
      script.debug_state != debugger::scripting::ScriptDebugState::Paused;
  ImGui::DockSpaceOverViewport();
  const ImGuiViewport *viewport = ImGui::GetMainViewport();
  const ImVec2 origin = viewport->WorkPos;
  const ImVec2 size = viewport->WorkSize;

  const auto place_panel = [&](float x, float y, float width, float height) {
    ImGui::SetNextWindowPos(
        ImVec2(origin.x + size.x * x, origin.y + size.y * y),
        ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(size.x * width, size.y * height),
                             ImGuiCond_FirstUseEver);
  };
  place_panel(0.0F, 0.0F, 0.20F, 0.40F);
  draw_session_panel(snapshot, engine, ui, script.control_lease);

  place_panel(0.0F, 0.40F, 0.20F, 0.60F);
  draw_breakpoints_panel(snapshot, engine, ui);

  place_panel(0.20F, 0.0F, 0.50F, 0.36F);
  draw_disassembly_panel(snapshot, engine, ui, native_views_locked);

  place_panel(0.20F, 0.36F, 0.50F, 0.36F);
  draw_decompiler_panel(snapshot, decompiled, decompiler, engine, ui,
                        native_views_locked);

  place_panel(0.20F, 0.72F, 0.40F, 0.28F);
  draw_console_panel(snapshot, engine, python, ui, script.control_lease);

  ImGui::BeginDisabled(script.control_lease);
  place_panel(0.70F, 0.0F, 0.30F, 0.72F);
  draw_register_panel(snapshot, engine, ui);

  place_panel(0.60F, 0.72F, 0.40F, 0.28F);
  draw_memory_panel(snapshot, engine, ui);

  draw_threads_panel(snapshot, engine, ui);
  draw_backtrace_panel(snapshot, engine, ui);
  draw_stack_panel(snapshot, engine, ui);
  draw_heap_panel(snapshot, engine, ui);
  draw_memory_map_panel(snapshot, engine, ui);
  draw_modules_panel(snapshot, engine, ui);
  draw_security_panel(snapshot, ui);
  ImGui::SetNextWindowSize(ImVec2(size.x * 0.65F, size.y * 0.55F),
                           ImGuiCond_FirstUseEver);
  draw_scans_panel(snapshot, engine, ui);
  for (const auto &surface :
       debugger::plugins::PluginRegistry::instance().surfaces()) {
    if (surface.surface != debugger::plugins::Surface::Menu) {
      surface.callback(snapshot, engine);
    }
  }
  ImGui::EndDisabled();
  place_panel(0.10F, 0.08F, 0.80F, 0.84F);
  draw_python_panel(python, ui);
  if (focus_disassembly_on_first_frame) {
    ImGui::SetWindowFocus(l10n::label(l10n::Key::WindowDisassembly));
    focus_disassembly_on_first_frame = false;
  }

  draw_keybindings_settings(ui);
  draw_navigation_dialog(snapshot, engine, ui);
  draw_comment_editor(snapshot, engine, ui, script.control_lease);
  help.draw();
  draw_debugger_menu(snapshot, engine, ui, help, script.control_lease);
  if (panel_visibility(ui) != visibility_before) {
    ImGui::MarkIniSettingsDirty();
  }
}

} // namespace mydbg::app
