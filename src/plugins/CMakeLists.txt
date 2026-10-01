add_library(debugger_plugins STATIC PluginApi.cpp)
target_include_directories(debugger_plugins PUBLIC "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(debugger_plugins PUBLIC localization PRIVATE ${CMAKE_DL_LIBS})
mydbg_enable_warnings(debugger_plugins)
