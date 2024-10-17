cmake_minimum_required (VERSION 3.0)

if(APPLE)
    set(CMAKE_C_COMPILER "/usr/local/bin/gcc-9")
    set(CMAKE_CXX_COMPILER "/usr/local/bin/g++-9")
endif()

project (OCEAN)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(NOT CMAKE_BUILD_TYPE)
   set(CMAKE_BUILD_TYPE Release)
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_FLAGS "-pthread -Wall -march=native -maes -mrdseed -faligned-new -std=c++17 -w")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -ggdb")

add_subdirectory(src)

add_subdirectory(tests)

