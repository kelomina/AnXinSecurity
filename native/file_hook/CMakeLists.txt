cmake_minimum_required(VERSION 3.20)

# NOTE: 当使用 Visual Studio 18 Insiders 环境时，需要指定 v144 工具集：
#   cmake -S . -B build-x64 -G "Visual Studio 17 2022" -A x64 -T v144 -DBUILD_PEB_PROBE=ON -DBUILD_REFLECTIVE_PROBE=ON
#   cmake --build build-x64 --config Release

project(file_hook LANGUAGES CXX)

set(DETOURS_ROOT "" CACHE PATH "Detours root directory")

set(DETOURS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/Detours")
set(DETOURS_BUILD_FROM_SOURCE ON)

if (DETOURS_ROOT)
  if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(DETOURS_LIB_DIR "lib.X64")
  else()
    set(DETOURS_LIB_DIR "lib.X86")
  endif()

  find_path(DETOURS_INCLUDE_DIR
    NAMES detours.h
    HINTS
      ${DETOURS_ROOT}/include
  )

  find_library(DETOURS_LIBRARY
    NAMES detours
    HINTS
      ${DETOURS_ROOT}/${DETOURS_LIB_DIR}
      ${DETOURS_ROOT}/lib
  )

  if (DETOURS_INCLUDE_DIR AND DETOURS_LIBRARY)
    set(DETOURS_BUILD_FROM_SOURCE OFF)
  endif()
endif()

if (DETOURS_BUILD_FROM_SOURCE)
  add_library(detours STATIC
    ${DETOURS_SOURCE_DIR}/creatwth.cpp
    ${DETOURS_SOURCE_DIR}/detours.cpp
    ${DETOURS_SOURCE_DIR}/disasm.cpp
    ${DETOURS_SOURCE_DIR}/disolarm.cpp
    ${DETOURS_SOURCE_DIR}/disolarm64.cpp
    ${DETOURS_SOURCE_DIR}/disolia64.cpp
    ${DETOURS_SOURCE_DIR}/disolx64.cpp
    ${DETOURS_SOURCE_DIR}/disolx86.cpp
    ${DETOURS_SOURCE_DIR}/image.cpp
    ${DETOURS_SOURCE_DIR}/modules.cpp
  )
  target_compile_features(detours PRIVATE cxx_std_17)
  target_include_directories(detours PUBLIC ${DETOURS_SOURCE_DIR})
  if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(detours PRIVATE _AMD64_)
  else()
    target_compile_definitions(detours PRIVATE _X86_)
  endif()
  if (MSVC)
    target_compile_options(detours PRIVATE /W4 /EHsc)
  endif()
else()
  add_library(detours STATIC IMPORTED)
  set_target_properties(detours PROPERTIES IMPORTED_LOCATION ${DETOURS_LIBRARY})
  target_include_directories(detours INTERFACE ${DETOURS_INCLUDE_DIR})
endif()

add_library(file_hook_detours SHARED
  src/file_hook_dll.cpp
)
target_compile_features(file_hook_detours PRIVATE cxx_std_17)
target_link_libraries(file_hook_detours PRIVATE detours)
set_target_properties(file_hook_detours PROPERTIES OUTPUT_NAME "file_hook_detours")
if (MSVC)
  target_compile_options(file_hook_detours PRIVATE /W4 /EHsc)
endif()

option(BUILD_CALC_PROBE "Build the calculator injection probe DLL" OFF)
if (BUILD_CALC_PROBE)
  add_library(calc_probe_payload SHARED
    src/calc_probe_dll.cpp
  )
  target_compile_features(calc_probe_payload PRIVATE cxx_std_17)
  set_target_properties(calc_probe_payload PROPERTIES OUTPUT_NAME "calc_probe_payload")
  if (MSVC)
    target_compile_options(calc_probe_payload PRIVATE /W4 /EHsc /utf-8)
  endif()
endif()

option(BUILD_PEB_PROBE "Build the PEB unlink detection probe DLL" OFF)
if (BUILD_PEB_PROBE)
  add_library(peb_unlink_probe_payload SHARED
    src/peb_unlink_probe_dll.cpp
  )
  target_compile_features(peb_unlink_probe_payload PRIVATE cxx_std_17)
  set_target_properties(peb_unlink_probe_payload PROPERTIES OUTPUT_NAME "peb_unlink_probe_payload")
  if (MSVC)
    target_compile_options(peb_unlink_probe_payload PRIVATE /W4 /EHsc /utf-8)
  endif()
endif()

option(BUILD_REFLECTIVE_PROBE "Build the reflective DLL load detection probe DLL" OFF)
if (BUILD_REFLECTIVE_PROBE)
  add_library(reflective_load_probe_payload SHARED
    src/reflective_load_probe_dll.cpp
  )
  target_compile_features(reflective_load_probe_payload PRIVATE cxx_std_17)
  set_target_properties(reflective_load_probe_payload PROPERTIES OUTPUT_NAME "reflective_load_probe_payload")
  if (MSVC)
    target_compile_options(reflective_load_probe_payload PRIVATE /W4 /EHsc /utf-8)
  endif()
endif()

option(BUILD_PEB_REAL_PROBE "Build the real PEB unlinking probe DLL (actual PEB manipulation)" OFF)
if (BUILD_PEB_REAL_PROBE)
  add_library(peb_unlink_real_payload SHARED
    src/peb_unlink_real_dll.cpp
  )
  target_compile_features(peb_unlink_real_payload PRIVATE cxx_std_17)
  target_include_directories(peb_unlink_real_payload PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  set_target_properties(peb_unlink_real_payload PROPERTIES OUTPUT_NAME "peb_unlink_real_payload")
  if (MSVC)
    target_compile_options(peb_unlink_real_payload PRIVATE /W4 /EHsc /utf-8)
  endif()
endif()

option(BUILD_REFLECTIVE_REAL_PROBE "Build the real reflective DLL load probe DLL (actual manual mapping)" OFF)
if (BUILD_REFLECTIVE_REAL_PROBE)
  add_library(reflective_load_real_payload SHARED
    src/reflective_load_real_dll.cpp
  )
  target_compile_features(reflective_load_real_payload PRIVATE cxx_std_17)
  target_include_directories(reflective_load_real_payload PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  set_target_properties(reflective_load_real_payload PROPERTIES OUTPUT_NAME "reflective_load_real_payload")
  if (MSVC)
    target_compile_options(reflective_load_real_payload PRIVATE /W4 /EHsc /utf-8)
  endif()
endif()

add_executable(file_hook_injector
  src/file_hook_injector.cpp
)
target_compile_features(file_hook_injector PRIVATE cxx_std_17)
if (MSVC)
  target_compile_options(file_hook_injector PRIVATE /W4 /EHsc /utf-8)
endif()
