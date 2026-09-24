#include "plugins/PluginApi.h"

#include <string>

extern "C" bool mydbg_plugin_init(
    debugger::plugins::PluginRegistry* registry,
    std::uint32_t abi_version) {
    if (registry == nullptr ||
        abi_version != debugger::plugins::plugin_abi_version) {
        return false;
    }
    return registry->register_command(
        "plugin-ping", "Verify native plugin command dispatch",
        [](std::string_view arguments,
           const debugger::SessionSnapshot& snapshot) {
            return std::string{"plugin-pong state="} +
                   debugger::to_string(snapshot.state) +
                   " arguments=" + std::string{arguments};
        });
}
