add_executable(crackme EXCLUDE_FROM_ALL crackme.cpp)
mydbg_enable_warnings(crackme -g -O0 -fno-omit-frame-pointer)

add_executable(ctf_challenge ctf_challenge.cpp)
mydbg_enable_warnings(ctf_challenge -g -O0 -fno-omit-frame-pointer)
