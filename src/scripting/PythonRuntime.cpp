#include "scripting/PythonRuntime.h"
#include "localization/Localization.h"
#include "scripting/PythonBindings.h"

#include <pybind11/embed.h>

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace py = pybind11;

namespace debugger::scripting {
namespace {

constexpr std::size_t maximum_script_output = 1024U * 1024U;
constexpr std::size_t maximum_traceback = 1024U * 1024U;

bool finished(ScriptStatus status) {
  return status == ScriptStatus::Idle || status == ScriptStatus::Succeeded ||
         status == ScriptStatus::Failed || status == ScriptStatus::Cancelled ||
         status == ScriptStatus::ShuttingDown;
}

void normalize_breakpoints(std::vector<std::uint32_t> &breakpoints) {
  std::ranges::sort(breakpoints);
  std::erase(breakpoints, 0);
  breakpoints.erase(std::unique(breakpoints.begin(), breakpoints.end()),
                    breakpoints.end());
}

std::string bounded_traceback(std::string traceback) {
  if (traceback.size() <= maximum_traceback) {
    return traceback;
  }
  const std::string_view notice =
      std::string_view{l10n::text(l10n::Key::PythonRuntimeTracebackTruncated)}
          .substr(0, maximum_traceback);
  traceback.erase(0, traceback.size() - maximum_traceback + notice.size());
  traceback.insert(0, notice);
  return traceback;
}

constexpr std::size_t maximum_debug_value = 4096;
constexpr std::size_t maximum_debug_variables = 256;
constexpr std::size_t maximum_debug_frames = 64;

std::string bounded_debug_text(std::string text) {
  if (text.size() <= maximum_debug_value) {
    return text;
  }
  const std::string_view notice =
      std::string_view{l10n::text(l10n::Key::PythonRuntimeValueTruncated)}
          .substr(0, maximum_debug_value);
  text.resize(maximum_debug_value - notice.size());
  text.append(notice);
  return text;
}

std::string safe_python_text(const py::handle &value, bool representation) {
  try {
    return bounded_debug_text(py::cast<std::string>(
        representation ? py::repr(value) : py::str(value)));
  } catch (const py::error_already_set &) {
    return l10n::text(l10n::Key::PythonRuntimeValueUnavailable);
  }
}

std::vector<ScriptValue> capture_variables(const py::handle &values,
                                           bool skip_dunder_names) {
  const py::object mapping = py::reinterpret_borrow<py::object>(values);
  std::vector<ScriptValue> result;
  result.reserve(
      std::min<std::size_t>(py::len(mapping), maximum_debug_variables));
  for (const py::handle item : mapping.attr("items")()) {
    if (result.size() == maximum_debug_variables) {
      break;
    }
    const py::tuple pair = py::reinterpret_borrow<py::tuple>(item);
    const py::handle key = pair[0];
    const py::handle value = pair[1];
    const std::string name = safe_python_text(key, false);
    if (skip_dunder_names && name.starts_with("__") && name.ends_with("__")) {
      continue;
    }
    std::string type;
    try {
      type = py::cast<std::string>(py::type::of(value).attr("__name__"));
    } catch (const py::error_already_set &) {
      type = l10n::text(l10n::Key::PythonRuntimeTypeUnknown);
    }
    result.push_back(ScriptValue{.name = name,
                                 .type = std::move(type),
                                 .value = safe_python_text(value, true)});
  }
  std::ranges::sort(result, {}, &ScriptValue::name);
  return result;
}

std::vector<ScriptFrame> capture_frames(const py::handle &top) {
  std::vector<ScriptFrame> result;
  py::object frame = py::reinterpret_borrow<py::object>(top);
  while (!frame.is_none() && result.size() < maximum_debug_frames) {
    const py::object code = frame.attr("f_code");
    result.push_back(ScriptFrame{
        .file = py::cast<std::string>(code.attr("co_filename")),
        .function = py::cast<std::string>(code.attr("co_name")),
        .line = py::cast<std::uint32_t>(frame.attr("f_lineno")),
        .locals = capture_variables(frame.attr("f_locals"), false),
    });
    frame = frame.attr("f_back");
  }
  return result;
}

std::uint32_t script_frame_depth(const py::handle &top,
                                 const std::string &script_file) {
  std::uint32_t depth = 0;
  py::object frame = py::reinterpret_borrow<py::object>(top);
  while (!frame.is_none()) {
    const py::object code = frame.attr("f_code");
    if (py::cast<std::string>(code.attr("co_filename")) == script_file) {
      ++depth;
    }
    frame = frame.attr("f_back");
  }
  return depth;
}

} // namespace

const char *to_string(ScriptStatus status) noexcept {
  switch (status) {
  case ScriptStatus::Idle:
    return "idle";
  case ScriptStatus::Queued:
    return "queued";
  case ScriptStatus::Running:
    return "running";
  case ScriptStatus::Cancelling:
    return "cancelling";
  case ScriptStatus::Succeeded:
    return "succeeded";
  case ScriptStatus::Failed:
    return "failed";
  case ScriptStatus::Cancelled:
    return "cancelled";
  case ScriptStatus::ShuttingDown:
    return "shutting down";
  }
  return "unknown";
}

const char *to_string(ScriptDebugState state) noexcept {
  switch (state) {
  case ScriptDebugState::Inactive:
    return "inactive";
  case ScriptDebugState::Running:
    return "running";
  case ScriptDebugState::Paused:
    return "paused";
  }
  return "unknown";
}

PythonRuntime::PythonRuntime(LldbEngine &engine)
    : engine_(engine), worker_([this] { run(); }) {}

PythonRuntime::~PythonRuntime() { shutdown(); }

bool PythonRuntime::run_file(std::string file) {
  return submit_job(std::move(file), {}, {}, false, false);
}

bool PythonRuntime::debug_source(std::string file, std::string source,
                                 std::vector<std::uint32_t> breakpoints,
                                 bool stop_on_entry) {
  return submit_job(std::move(file), std::move(source), std::move(breakpoints),
                    true, stop_on_entry);
}

bool PythonRuntime::submit_job(std::string file, std::string source,
                               std::vector<std::uint32_t> breakpoints,
                               bool debug, bool stop_on_entry) {
  if (file.empty()) {
    return false;
  }
  if (debug) {
    normalize_breakpoints(breakpoints);
  }
  {
    const std::lock_guard lock{mutex_};
    if (shutting_down_ || has_job_ || snapshot_.control_lease) {
      return false;
    }
    cancellation_ = std::make_shared<std::atomic_bool>(false);
    pending_file_ = std::move(file);
    pending_debug_ = debug;
    if (debug) {
      pending_source_ = std::move(source);
      pending_breakpoints_ = std::move(breakpoints);
      pause_requested_ = stop_on_entry;
    } else {
      // File jobs leave the existing breakpoint and pause state untouched.
      pending_source_.clear();
    }
    step_mode_ = StepMode::None;
    step_frame_depth_ = 0;
    has_job_ = true;
    ++snapshot_.job_id;
    ++snapshot_.revision;
    snapshot_.status = ScriptStatus::Queued;
    snapshot_.file = pending_file_;
    snapshot_.output.clear();
    snapshot_.traceback.clear();
    snapshot_.control_lease = true;
    snapshot_.debug_state =
        debug ? ScriptDebugState::Running : ScriptDebugState::Inactive;
    snapshot_.current_line = 0;
    if (debug) {
      snapshot_.breakpoints = pending_breakpoints_;
    }
    snapshot_.frames.clear();
    snapshot_.globals.clear();
  }
  changed_.notify_all();
  wake_.notify_one();
  return true;
}

void PythonRuntime::resume_script(StepMode mode) {
  {
    const std::lock_guard lock{mutex_};
    if (snapshot_.debug_state != ScriptDebugState::Paused) {
      return;
    }
    pause_requested_ = false;
    step_mode_ = mode;
    snapshot_.debug_state = ScriptDebugState::Running;
    ++snapshot_.revision;
  }
  changed_.notify_all();
  debug_wake_.notify_all();
}

void PythonRuntime::continue_script() { resume_script(StepMode::None); }

void PythonRuntime::step_into_script() { resume_script(StepMode::Into); }

void PythonRuntime::step_over_script() { resume_script(StepMode::Over); }

void PythonRuntime::step_out_script() { resume_script(StepMode::Out); }

void PythonRuntime::pause_script() {
  const std::lock_guard lock{mutex_};
  if (snapshot_.control_lease &&
      snapshot_.debug_state == ScriptDebugState::Running) {
    pause_requested_ = true;
  }
}

void PythonRuntime::set_breakpoints(std::vector<std::uint32_t> breakpoints) {
  normalize_breakpoints(breakpoints);
  {
    const std::lock_guard lock{mutex_};
    snapshot_.breakpoints = breakpoints;
    if (has_job_) {
      pending_breakpoints_ = std::move(breakpoints);
    }
    ++snapshot_.revision;
  }
  changed_.notify_all();
}

void PythonRuntime::stop() {
  {
    const std::lock_guard lock{mutex_};
    if (!snapshot_.control_lease || !cancellation_) {
      return;
    }
    cancellation_->store(true);
    snapshot_.status = ScriptStatus::Cancelling;
    ++snapshot_.revision;
  }
  changed_.notify_all();
  wake_.notify_all();
  debug_wake_.notify_all();
}

void PythonRuntime::shutdown() {
  {
    const std::lock_guard lock{mutex_};
    if (shutting_down_) {
      return;
    }
    shutting_down_ = true;
    if (cancellation_) {
      cancellation_->store(true);
    }
  }
  wake_.notify_all();
  debug_wake_.notify_all();
  changed_.notify_all();
  if (worker_.joinable()) {
    worker_.join();
  }
}

ScriptSnapshot PythonRuntime::snapshot() const {
  const std::lock_guard lock{mutex_};
  return snapshot_;
}

bool PythonRuntime::wait_for_completion(
    std::chrono::milliseconds timeout) const {
  std::unique_lock lock{mutex_};
  return changed_.wait_for(lock, timeout,
                           [this] { return finished(snapshot_.status); });
}

void PythonRuntime::append_output(std::string text) {
  if (text.empty()) {
    return;
  }
  {
    const std::lock_guard lock{mutex_};
    if (text.size() >= maximum_script_output) {
      snapshot_.output.assign(
          text.end() - static_cast<std::ptrdiff_t>(maximum_script_output),
          text.end());
    } else {
      const std::size_t combined = snapshot_.output.size() + text.size();
      if (combined > maximum_script_output) {
        snapshot_.output.erase(0, combined - maximum_script_output);
      }
      snapshot_.output.append(text);
    }
    ++snapshot_.revision;
  }
  changed_.notify_all();
}

void PythonRuntime::finish(ScriptStatus status, std::string traceback) {
  {
    const std::lock_guard lock{mutex_};
    snapshot_.status = status;
    snapshot_.traceback = bounded_traceback(std::move(traceback));
    snapshot_.control_lease = false;
    snapshot_.debug_state = ScriptDebugState::Inactive;
    snapshot_.current_line = 0;
    step_mode_ = StepMode::None;
    step_frame_depth_ = 0;
    ++snapshot_.revision;
  }
  changed_.notify_all();
}

void PythonRuntime::run() {
  for (;;) {
    std::string file;
    std::shared_ptr<std::atomic_bool> cancellation;
    std::string source;
    bool debug{};
    {
      std::unique_lock lock{mutex_};
      wake_.wait(lock, [this] { return has_job_ || shutting_down_; });
      if (shutting_down_ && !has_job_) {
        snapshot_.status = ScriptStatus::ShuttingDown;
        snapshot_.control_lease = false;
        ++snapshot_.revision;
        changed_.notify_all();
        return;
      }
      file = std::move(pending_file_);
      cancellation = cancellation_;
      source = std::move(pending_source_);
      debug = pending_debug_;
      pending_debug_ = false;
      has_job_ = false;
      snapshot_.status = cancellation->load() ? ScriptStatus::Cancelling
                                              : ScriptStatus::Running;
      snapshot_.debug_state =
          debug ? ScriptDebugState::Running : ScriptDebugState::Inactive;
      snapshot_.breakpoints = std::move(pending_breakpoints_);
      ++snapshot_.revision;
    }
    changed_.notify_all();

    ScriptStatus result = ScriptStatus::Succeeded;
    std::string traceback;
    try {
      py::gil_scoped_acquire acquire;
      py::module_ sys = py::module_::import("sys");
      py::module_ types = py::module_::import("types");
      py::list path = sys.attr("path");
      const std::filesystem::path script_path = std::filesystem::absolute(file);
      const std::string script_directory = script_path.parent_path().string();
      path.attr("insert")(0, script_directory);

      py::object original_stdout = sys.attr("stdout");
      py::object original_stderr = sys.attr("stderr");
      py::object original_trace = debug ? sys.attr("gettrace")() : py::none();
      py::dict capture_namespace;
      capture_namespace["_append"] = py::cpp_function(
          [this](const std::string &text) { append_output(text); });
      py::exec("class _MyDbgCapture:\n"
               "    encoding = 'utf-8'\n"
               "    def write(self, text):\n"
               "        _append(str(text))\n"
               "        return len(text)\n"
               "    def flush(self):\n"
               "        pass\n"
               "    def isatty(self):\n"
               "        return False\n",
               capture_namespace);
      py::object capture = capture_namespace["_MyDbgCapture"]();
      sys.attr("stdout") = capture;
      sys.attr("stderr") = capture;

      if (debug) {
        capture_namespace["_debug_event"] = py::cpp_function(
            [this, cancellation, script_file = script_path.string()](
                const py::object &frame, const std::string &event) {
              if (event != "line") {
                return;
              }
              const py::object code = frame.attr("f_code");
              if (py::cast<std::string>(code.attr("co_filename")) !=
                  script_file) {
                return;
              }
              const std::uint32_t line =
                  py::cast<std::uint32_t>(frame.attr("f_lineno"));
              const std::uint32_t frame_depth =
                  script_frame_depth(frame, script_file);
              bool should_pause = false;
              {
                const std::lock_guard lock{mutex_};
                if (cancellation->load() || shutting_down_) {
                  throw std::runtime_error(
                      l10n::text(l10n::Key::PythonRuntimeScriptCancelled));
                }
                const bool step_pause = step_mode_ == StepMode::Into ||
                                        (step_mode_ == StepMode::Over &&
                                         frame_depth <= step_frame_depth_) ||
                                        (step_mode_ == StepMode::Out &&
                                         frame_depth < step_frame_depth_);
                should_pause =
                    pause_requested_ || step_pause ||
                    std::ranges::binary_search(snapshot_.breakpoints, line);
                pause_requested_ = false;
                if (should_pause) {
                  step_mode_ = StepMode::None;
                  step_frame_depth_ = frame_depth;
                }
                snapshot_.current_line = line;
                snapshot_.debug_state = ScriptDebugState::Running;
                ++snapshot_.revision;
              }

              if (should_pause) {
                std::vector<ScriptFrame> frames = capture_frames(frame);
                std::vector<ScriptValue> globals =
                    capture_variables(frame.attr("f_globals"), true);
                {
                  const std::lock_guard lock{mutex_};
                  snapshot_.frames = std::move(frames);
                  snapshot_.globals = std::move(globals);
                  snapshot_.debug_state = ScriptDebugState::Paused;
                  ++snapshot_.revision;
                }
              }
              changed_.notify_all();

              if (should_pause) {
                std::unique_lock lock{mutex_};
                {
                  py::gil_scoped_release release;
                  debug_wake_.wait(lock, [this, &cancellation] {
                    return cancellation->load() || shutting_down_ ||
                           snapshot_.debug_state != ScriptDebugState::Paused;
                  });
                }
                if (cancellation->load() || shutting_down_) {
                  throw std::runtime_error(
                      l10n::text(l10n::Key::PythonRuntimeScriptCancelled));
                }
              }
            });
        py::exec("def _mydbg_trace(frame, event, arg):\n"
                 "    _debug_event(frame, event)\n"
                 "    return _mydbg_trace\n",
                 capture_namespace);
        sys.attr("settrace")(capture_namespace["_mydbg_trace"]);
      }

      const auto restore_python_state = [&] {
        if (debug) {
          sys.attr("settrace")(original_trace);
        }
        sys.attr("stdout") = original_stdout;
        sys.attr("stderr") = original_stderr;
        if (py::len(path) > 0 &&
            py::cast<std::string>(path[0]) == script_directory) {
          path.attr("pop")(0);
        } else {
          try {
            path.attr("remove")(script_directory);
          } catch (const py::error_already_set &) {
            PyErr_Clear();
          }
        }
      };

      try {
        if (cancellation->load()) {
          throw std::runtime_error(
              l10n::text(l10n::Key::PythonRuntimeScriptCancelled));
        }
        const std::string module_name =
            "__mydbg_script_" + std::to_string(snapshot().job_id);
        py::object module = types.attr("ModuleType")(module_name);
        py::dict globals = module.attr("__dict__");
        globals["__file__"] = script_path.string();
        globals["__name__"] = module_name;
        globals["__builtins__"] = py::module_::import("builtins");
        if (debug) {
          py::object code =
              py::module_::import("builtins")
                  .attr("compile")(source, script_path.string(), "exec");
          py::module_::import("builtins").attr("exec")(code, globals, globals);
        } else {
          py::eval_file(script_path.string(), globals, globals);
        }
        if (!globals.contains("run") ||
            !PyCallable_Check(globals["run"].ptr())) {
          throw std::runtime_error(
              l10n::text(l10n::Key::PythonRuntimeRunCallableRequired));
        }
        py::object debugger = make_python_debugger(engine_, cancellation);
        globals["run"](debugger);
        if (cancellation->load()) {
          result = ScriptStatus::Cancelled;
        }
      } catch (const std::exception &error) {
        traceback = error.what();
        result = cancellation->load() ? ScriptStatus::Cancelled
                                      : ScriptStatus::Failed;
      }
      restore_python_state();
    } catch (const std::exception &error) {
      traceback = error.what();
      result =
          cancellation->load() ? ScriptStatus::Cancelled : ScriptStatus::Failed;
    }

    finish(result, std::move(traceback));
  }
}

} // namespace debugger::scripting
