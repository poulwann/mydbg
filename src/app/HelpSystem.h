#pragma once

#include <memory>
#include <string_view>

namespace debugger::help {

class HelpSystem {
public:
  HelpSystem();
  ~HelpSystem();

  HelpSystem(const HelpSystem &) = delete;
  HelpSystem &operator=(const HelpSystem &) = delete;

  void open(std::string_view chapter = {});
  void draw();
  void shutdown();

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace debugger::help
