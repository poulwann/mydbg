#include "plugins/PluginApi.h"
#include "localization/Localization.h"

#include <algorithm>
#include <dlfcn.h>
#include <exception>

namespace debugger::plugins {
namespace {

bool valid_name(std::string_view name) {
    return !name.empty() &&
           std::ranges::all_of(name, [](unsigned char value) {
               return value > 32 && value < 127;
           });
}

} // namespace

PluginRegistry& PluginRegistry::instance() {
    static PluginRegistry registry;
    return registry;
}

bool PluginRegistry::register_command(std::string name, std::string help,
                                      CommandCallback callback) {
    if (!valid_name(name) || !callback) {
        return false;
    }
    const std::lock_guard lock{mutex_};
    if (std::ranges::find(commands_, name, &CommandRegistration::name) !=
        commands_.end()) {
        return false;
    }
    commands_.push_back(CommandRegistration{
        .name = std::move(name),
        .help = std::move(help),
        .callback = std::move(callback),
    });
    return true;
}

bool PluginRegistry::register_surface(std::string name, Surface surface,
                                      RenderCallback callback) {
    if (!valid_name(name) || !callback) {
        return false;
    }
    const std::lock_guard lock{mutex_};
    if (std::ranges::any_of(surfaces_, [&name, surface](const auto& registration) {
            return registration.name == name &&
                   registration.surface == surface;
        })) {
        return false;
    }
    surfaces_.push_back(SurfaceRegistration{
        .name = std::move(name),
        .surface = surface,
        .callback = std::move(callback),
    });
    return true;
}

void PluginRegistry::subscribe(EventCallback callback) {
    if (!callback) {
        return;
    }
    const std::lock_guard lock{mutex_};
    subscribers_.push_back(std::move(callback));
}

std::optional<std::string>
PluginRegistry::execute(std::string_view name, std::string_view arguments,
                        const SessionSnapshot &snapshot, bool &failed) const {
  failed = false;
  CommandCallback callback;
  {
    const std::lock_guard lock{mutex_};
    const auto command =
        std::ranges::find(commands_, name, &CommandRegistration::name);
    if (command == commands_.end()) {
      return std::nullopt;
    }
    callback = command->callback;
  }
  try {
    return callback(arguments, snapshot);
  } catch (const std::exception &error) {
    failed = true;
    return l10n::format(l10n::Key::PluginCommandFailed, error.what());
  } catch (...) {
    failed = true;
    return std::string{l10n::text(l10n::Key::PluginCommandUnknownException)};
  }
}

std::vector<CommandRegistration> PluginRegistry::commands() const {
    const std::lock_guard lock{mutex_};
    return commands_;
}

std::vector<SurfaceRegistration> PluginRegistry::surfaces() const {
    const std::lock_guard lock{mutex_};
    return surfaces_;
}

void PluginRegistry::dispatch(Event event,
                              const SessionSnapshot& snapshot) const {
    std::vector<EventCallback> subscribers;
    {
        const std::lock_guard lock{mutex_};
        subscribers = subscribers_;
    }
    for (const EventCallback& callback : subscribers) {
        try {
            callback(event, snapshot);
        } catch (...) {
            // A plugin must not interrupt debugger event delivery.
        }
    }
}

PluginLoader::~PluginLoader() = default;

bool PluginLoader::load(const std::filesystem::path& path) {
    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (handle == nullptr) {
        errors_.push_back(path.string() + ": " + dlerror());
        return false;
    }
    dlerror();
    void* symbol = dlsym(handle, "mydbg_plugin_init");
    if (const char* error = dlerror(); error != nullptr) {
        errors_.push_back(path.string() + ": " + error);
        dlclose(handle);
        return false;
    }
    const auto initialize =
        reinterpret_cast<InitializePlugin>(symbol);
    bool loaded = false;
    const std::size_t previous_error_count = errors_.size();
    try {
        loaded = initialize(&PluginRegistry::instance(),
                            plugin_abi_version);
    } catch (const std::exception& error) {
        errors_.push_back(path.string() + ": " + error.what());
    } catch (...) {
      errors_.push_back(
          l10n::format(l10n::Key::PluginInitializationUnknownException,
                       path.string().c_str()));
    }
    if (!loaded) {
      if (errors_.size() == previous_error_count) {
        errors_.push_back(l10n::format(l10n::Key::PluginInitializationRejected,
                                       path.string().c_str()));
      }
        return false;
    }
    loaded_plugins_.push_back(path);
    return true;
}

void PluginLoader::load_directory(const std::filesystem::path& directory) {
    std::error_code error;
    if (!std::filesystem::is_directory(directory, error)) {
        return;
    }
    std::vector<std::filesystem::path> candidates;
    for (const std::filesystem::directory_entry& entry :
         std::filesystem::directory_iterator(directory, error)) {
        if (entry.is_regular_file() &&
            entry.path().extension() == ".so") {
            candidates.push_back(entry.path());
        }
    }
    std::ranges::sort(candidates);
    for (const std::filesystem::path& candidate : candidates) {
        load(candidate);
    }
}

const std::vector<std::string>& PluginLoader::errors() const noexcept {
    return errors_;
}

const std::vector<std::filesystem::path>&
PluginLoader::loaded_plugins() const noexcept {
    return loaded_plugins_;
}

} // namespace debugger::plugins
