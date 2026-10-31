cmake_minimum_required(VERSION 3.14)
project(8nomorp C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
option(WITH_UNICORN "Build automatic offline context generation" ON)

add_executable(8nomorp
    src/main.c
    src/lbts.c
    src/promon.c
    src/attestation.c
)
target_include_directories(8nomorp PRIVATE src)

target_link_libraries(8nomorp m)
if(WITH_UNICORN)
    set(_saved_library_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${_saved_library_suffixes})
    find_package(ZLIB REQUIRED)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${_saved_library_suffixes})
    include(FetchContent)
    set(UNICORN_ARCH "aarch64;arm" CACHE STRING "Emulated architectures" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "Static emulator" FORCE)
    set(UNICORN_BUILD_TESTS OFF CACHE BOOL "Emulator tests" FORCE)
    FetchContent_Declare(unicorn
        GIT_REPOSITORY https://github.com/unicorn-engine/unicorn.git
        GIT_TAG 2.1.4
        GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(unicorn)
    target_sources(8nomorp PRIVATE src/ctxgen.c src/apk.c)
    target_compile_definitions(8nomorp PRIVATE WITH_UNICORN)
    target_link_libraries(8nomorp unicorn ZLIB::ZLIB)
endif()
