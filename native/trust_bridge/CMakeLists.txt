cmake_minimum_required(VERSION 3.20)

project(trust_bridge LANGUAGES CXX)

add_library(trust_bridge SHARED
  src/trust_bridge.cpp
  src/trust_bridge.h
)

target_compile_features(trust_bridge PRIVATE cxx_std_17)

if (MSVC)
  target_compile_options(trust_bridge PRIVATE /W4 /EHsc)
endif()

target_link_libraries(trust_bridge PRIVATE wintrust crypt32 ole32 bcrypt)

target_include_directories(trust_bridge PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

enable_testing()

add_executable(trust_bridge_tests
  tests/trust_bridge_tests.cpp
  src/trust_bridge.cpp
)
target_compile_features(trust_bridge_tests PRIVATE cxx_std_17)
if (MSVC)
  target_compile_options(trust_bridge_tests PRIVATE /W4 /EHsc)
endif()
target_link_libraries(trust_bridge_tests PRIVATE wintrust crypt32 ole32 bcrypt)
target_include_directories(trust_bridge_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_test(NAME trust_bridge_tests COMMAND trust_bridge_tests)

