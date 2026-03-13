cmake_minimum_required(VERSION 3.20)

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

add_executable(file_hook_injector
  src/file_hook_injector.cpp
)
target_compile_features(file_hook_injector PRIVATE cxx_std_17)
if (MSVC)
  target_compile_options(file_hook_injector PRIVATE /W4 /EHsc)
endif()
