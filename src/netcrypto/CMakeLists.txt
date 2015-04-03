
project(netcrypto)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
  add_definitions(-D_TARGET_MAC64)
endif(CMAKE_SYSTEM_NAME STREQUAL Darwin)

if(CMAKE_SYSTEM_NAME STREQUAL Linux)
  add_definitions(-D__LINUX__=1)
endif(CMAKE_SYSTEM_NAME STREQUAL Linux)

add_definitions(-DPLATFORM_UNIX=1)
add_definitions(-DLP64COMPATIBLE=1)
#add_definitions(-DFEATURE_PAL=1)
#add_definitions(-DCORECLR=1)
add_definitions(-DPIC=1)
add_definitions(-DBIT64=1)
#add_definitions(-D_WIN64=1)

#add_compile_options(-fno-builtin)
add_compile_options(-fPIC)

include_directories(../pal/inc)
include_directories(../pal/src/include)

set(NETCRYPTO_SOURCES
    openssl.c
)

set(WITH_X509_INCLUDES "" CACHE PATH "Path to openssl headers")

add_library(netcrypto
    SHARED
    ${NETCRYPTO_SOURCES}
)

target_link_libraries(netcrypto
  crypto
)

install (TARGETS netcrypto DESTINATION .)
