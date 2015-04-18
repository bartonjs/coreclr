
project(System.Security.Cryptography.Native)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

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
