#pragma once

namespace mydbg::app {

int run_headless(const char *executable, const char *attach_executable);
int run_keybinding_headless();
int run_condition_headless(const char *executable);
int run_heap_headless(const char *executable);
int run_scans_headless(const char *executable);
int run_stop_intelligence_headless(const char *executable);

} // namespace mydbg::app
