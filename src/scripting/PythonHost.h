#pragma once

#include <memory>

namespace debugger::scripting {

class PythonHost final {
public:
  PythonHost();
  ~PythonHost();

  PythonHost(const PythonHost &) = delete;
  PythonHost &operator=(const PythonHost &) = delete;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace debugger::scripting
