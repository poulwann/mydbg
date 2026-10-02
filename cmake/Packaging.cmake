set(MYDBG_INSTALL_PREFIX "/opt/mydbg" CACHE STRING "Absolute runtime prefix used by packaged builds")

if(EXISTS "${MYDBG_DEPS_PREFIX}/lib")
  install(DIRECTORY "${MYDBG_DEPS_PREFIX}/lib/"
    DESTINATION opt/mydbg/deps/lib
    USE_SOURCE_PERMISSIONS
    PATTERN "cmake" EXCLUDE
    PATTERN "pkgconfig" EXCLUDE)
endif()

if(EXISTS "${MYDBG_DEPS_PREFIX}/lib64")
  install(DIRECTORY "${MYDBG_DEPS_PREFIX}/lib64/"
    DESTINATION opt/mydbg/deps/lib64
    USE_SOURCE_PERMISSIONS
    PATTERN "cmake" EXCLUDE
    PATTERN "pkgconfig" EXCLUDE)
endif()

if(EXISTS "${MYDBG_DEPS_PREFIX}/share/rizin")
  install(DIRECTORY "${MYDBG_DEPS_PREFIX}/share/rizin"
    DESTINATION opt/mydbg/deps/share
    USE_SOURCE_PERMISSIONS)
endif()

install(CODE "
  file(MAKE_DIRECTORY \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/usr/bin\")
  execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
    \"${MYDBG_INSTALL_PREFIX}/mydbg\"
    \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/usr/bin/mydbg\")
")

set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME "mydbg")
set(CPACK_PACKAGE_VENDOR "mydbg")
set(CPACK_PACKAGE_CONTACT "poulwann")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Linux reverse-engineering debugger workbench")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/poulwann/mydbg")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PACKAGING_INSTALL_PREFIX "/")
set(CPACK_SET_DESTDIR ON)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SECTION "devel")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6, libstdc++6, python3, lldb, libgl1, libpng16-16, libbz2-1.0")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
include(CPack)
