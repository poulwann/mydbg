#pragma once

#include "app/DebuggerState.h"
#include "app/DecompilerState.h"
#include "app/FileDialogState.h"
#include "app/MemoryState.h"
#include "app/NavigationState.h"
#include "app/PythonState.h"
#include "app/RopState.h"
#include "app/WorkspaceState.h"

struct SDL_Window;

namespace mydbg::app {

struct UiState {
  SessionInputState session;
  CommentState comments;
  BreakpointState breakpoints;
  InstructionPatchState patch;
  RegisterState registers;
  MemoryState memory;
  DecompilerState decompiler;
  FileDialogState files;
  PythonState python;
  RopState rop;
  WorkspaceState workspace;
  NavigationState navigation;
  ScanState scans;
  HistoryState history;
  SDL_Window *main_window{};
};

} // namespace mydbg::app
