cmake_minimum_required(VERSION 3.20)

project(etw_bridge LANGUAGES CXX)

add_library(etw_bridge SHARED
  src/etw_bridge.cpp
  src/etw_bridge.h
)

target_compile_features(etw_bridge PRIVATE cxx_std_17)

if (MSVC)
  target_compile_options(etw_bridge PRIVATE /W4 /EHsc)
endif()

target_link_libraries(etw_bridge PRIVATE advapi32 ole32)

target_include_directories(etw_bridge PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)