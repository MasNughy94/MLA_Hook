cmake_minimum_required(VERSION 3.18)
project(mla_hook VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(mla_hook SHARED
    src/main.cpp
)

target_include_directories(mla_hook PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/Dobby/include
)

set(DOBBY_PREBUILT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/prebuilt/${ANDROID_ABI})

add_library(Dobby STATIC IMPORTED)
set_target_properties(Dobby PROPERTIES
    IMPORTED_LOCATION ${DOBBY_PREBUILT_DIR}/libDobby.a
)

target_link_libraries(mla_hook
    -Wl,--whole-archive Dobby -Wl,--no-whole-archive
    log
    dl
)

target_compile_definitions(mla_hook PRIVATE
    $<$<CONFIG:Debug>:DEBUG=1>
)
