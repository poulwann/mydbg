set(MYDBG_MANUAL_FILES
  01-getting-started.md
  02-workspace.md
  03-execution.md
  04-breakpoints.md
  05-memory-and-analysis.md
  06-command-reference.md
  07-troubleshooting.md
  08-python-automation.md
  09-settings.md
  10-plugins.md
  11-symbolic-execution.md
)
set(MYDBG_MANUAL_CHAPTERS "")
foreach(CHAPTER_FILE IN LISTS MYDBG_MANUAL_FILES)
  set(CHAPTER_PATH "${CMAKE_CURRENT_SOURCE_DIR}/docs/manual/${CHAPTER_FILE}")
  set_property(DIRECTORY APPEND PROPERTY
    CMAKE_CONFIGURE_DEPENDS "${CHAPTER_PATH}")
  file(READ "${CHAPTER_PATH}" CHAPTER_MARKDOWN)
  string(APPEND MYDBG_MANUAL_CHAPTERS
    "      {\"${CHAPTER_FILE}\", R\"ELFMAN(${CHAPTER_MARKDOWN})ELFMAN\"},\n")
endforeach()
list(LENGTH MYDBG_MANUAL_FILES MYDBG_MANUAL_CHAPTER_COUNT)
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(
  src/app/ManualContent.h.in
  "${CMAKE_CURRENT_BINARY_DIR}/generated/ManualContent.h"
  @ONLY
)
set_property(DIRECTORY APPEND PROPERTY
  CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/mydbg_default.ini")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/mydbg_default.ini" MYDBG_DEFAULT_LAYOUT)
configure_file(
  src/app/DefaultLayout.h.in
  "${CMAKE_CURRENT_BINARY_DIR}/generated/DefaultLayout.h"
  @ONLY
)

