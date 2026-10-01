file(GLOB MYDBG_ENGLISH_CATALOGS CONFIGURE_DEPENDS
  "${PROJECT_SOURCE_DIR}/locales/en/*.ini")
set(MYDBG_LOCALIZATION_HEADERS
  "${PROJECT_BINARY_DIR}/generated/LocalizationKeys.h"
  "${PROJECT_BINARY_DIR}/generated/LocalizationData.h")
add_custom_command(
  OUTPUT ${MYDBG_LOCALIZATION_HEADERS}
  COMMAND "${Python_EXECUTABLE}"
    "${PROJECT_SOURCE_DIR}/scripts/generate-localization.py"
    --output-dir "${PROJECT_BINARY_DIR}/generated"
    ${MYDBG_ENGLISH_CATALOGS}
  DEPENDS ${MYDBG_ENGLISH_CATALOGS}
    "${PROJECT_SOURCE_DIR}/scripts/generate-localization.py"
  VERBATIM)

add_library(localization STATIC Localization.cpp ${MYDBG_LOCALIZATION_HEADERS})
target_include_directories(localization PUBLIC
  "${PROJECT_SOURCE_DIR}/src" "${PROJECT_BINARY_DIR}/generated")
mydbg_enable_warnings(localization)
