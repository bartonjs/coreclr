
project(System.Security.Cryptography.Native)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
  add_definitions(-D_TARGET_MAC64)
endif(CMAKE_SYSTEM_NAME STREQUAL Darwin)

if(CMAKE_SYSTEM_NAME STREQUAL Linux)
  add_definitions(-D__LINUX__=1)
endif(CMAKE_SYSTEM_NAME STREQUAL Linux)

add_definitions(-DPLATFORM_UNIX=1)
add_definitions(-DLP64COMPATIBLE=1)
add_definitions(-DPIC=1)
add_definitions(-DBIT64=1)

add_compile_options(-fPIC)

set(NATIVECRYPTO_SOURCES
    openssl.c
)

add_library(System.Security.Cryptography.Native
    SHARED
    ${NATIVECRYPTO_SOURCES}
)

# Disable the "lib" prefix.
set_target_properties(System.Security.Cryptography.Native PROPERTIES PREFIX "")

target_link_libraries(System.Security.Cryptography.Native
  crypto
)

install (TARGETS System.Security.Cryptography.Native DESTINATION .)
