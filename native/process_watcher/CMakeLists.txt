cmake_minimum_required(VERSION 3.20)

project(process_watcher LANGUAGES CXX)

add_library(process_watcher SHARED
  src/process_watcher.cpp
  src/process_watcher.h
)

target_compile_features(process_watcher PRIVATE cxx_std_17)

if (MSVC)
  target_compile_options(process_watcher PRIVATE /W4 /EHsc)
endif()

target_link_libraries(process_watcher PRIVATE wintrust crypt32 advapi32)

target_include_directories(process_watcher PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
