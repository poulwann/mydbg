#pragma once

#include <array>
#include <memory>

namespace mydbg::app {

struct RopView;

struct RopState {
  std::array<char, 128> address{'$', 's', 'p', '\0'};
  int stack_bytes{512};
  int max_instructions{256};
  int max_nodes{64};
  float timeout_seconds{5.0F};
  bool window_focused{};
  bool focus_requested{};
  bool sync_live_views{true};
  std::shared_ptr<RopView> view;
};

} // namespace mydbg::app
