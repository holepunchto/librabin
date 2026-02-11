cmake_minimum_required(VERSION 4.0)

project(rabin C)

add_library(rabin OBJECT)

set_target_properties(
  rabin
  PROPERTIES
  C_STANDARD 99
  POSITION_INDEPENDENT_CODE ON
)

target_sources(
  rabin
  INTERFACE
    include/rabin.h
  PRIVATE
    src/rabin.c
)

target_include_directories(
  rabin
  INTERFACE
    include
)

add_library(rabin_shared SHARED)

set_target_properties(
  rabin_shared
  PROPERTIES
  OUTPUT_NAME rabin
  WINDOWS_EXPORT_ALL_SYMBOLS ON
)

target_link_libraries(
  rabin_shared
  PUBLIC
    rabin
)

add_library(rabin_static STATIC)

set_target_properties(
  rabin_static
  PROPERTIES
  OUTPUT_NAME rabin
  PREFIX lib
)

target_link_libraries(
  rabin_static
  PUBLIC
    rabin
)

install(TARGETS rabin_shared rabin_static)

install(FILES include/rabin.h DESTINATION include)

if(PROJECT_IS_TOP_LEVEL)
  enable_testing()

  add_subdirectory(test)
endif()
