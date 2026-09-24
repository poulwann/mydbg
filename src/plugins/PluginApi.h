#pragma once

#include "backend/lldb/LldbEngine.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace debugger::plugins {

inline constexpr std::uint32_t plugin_abi_version = 2;

enum class Event {
    SnapshotUpdated,
    TargetLoaded,
    ProcessStarted,
    ProcessStopped,
    ProcessContinued,
    ProcessExited,
    ThreadSelected,
    FrameSelected,
};

enum class Surface {
    DockPanel,
    Sidebar,
    Widget,
    Menu,
};

using CommandCallback =
    std::function<std::string(std::string_view, const SessionSnapshot&)>;
using RenderCallback =
    std::function<void(const SessionSnapshot&, LldbEngine&)>;
using EventCallback =
    std::function<void(Event, const SessionSnapshot&)>;

struct CommandRegistration {
    std::string name;
    std::string help;
    CommandCallback callback;
};

struct SurfaceRegistration {
    std::string name;
    Surface surface{Surface::DockPanel};
    RenderCallback callback;
};

class PluginRegistry final {
public:
    static PluginRegistry& instance();

    bool register_command(std::string name, std::string help,
                          CommandCallback callback);
    bool register_surface(std::string name, Surface surface,
                          RenderCallback callback);
    void subscribe(EventCallback callback);

    [[nodiscard]] std::optional<std::string>
    execute(std::string_view name, std::string_view arguments,
            const SessionSnapshot &snapshot, bool &failed) const;
    [[nodiscard]] std::vector<CommandRegistration> commands() const;
    [[nodiscard]] std::vector<SurfaceRegistration> surfaces() const;
    void dispatch(Event event, const SessionSnapshot& snapshot) const;

private:
    mutable std::mutex mutex_;
    std::vector<CommandRegistration> commands_;
    std::vector<SurfaceRegistration> surfaces_;
    std::vector<EventCallback> subscribers_;
};

class PluginLoader final {
public:
    PluginLoader() = default;
    PluginLoader(const PluginLoader&) = delete;
    PluginLoader& operator=(const PluginLoader&) = delete;
    ~PluginLoader();

    bool load(const std::filesystem::path& path);
    void load_directory(const std::filesystem::path& directory);

    [[nodiscard]] const std::vector<std::string>& errors() const noexcept;
    [[nodiscard]] const std::vector<std::filesystem::path>&
    loaded_plugins() const noexcept;

private:
    std::vector<std::filesystem::path> loaded_plugins_;
    std::vector<std::string> errors_;
};

using InitializePlugin =
    bool (*)(PluginRegistry* registry, std::uint32_t abi_version);

} // namespace debugger::plugins

extern "C" bool mydbg_plugin_init(
    debugger::plugins::PluginRegistry* registry,
    std::uint32_t abi_version);
