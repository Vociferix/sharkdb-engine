cmake_minimum_required(VERSION 3.0.2)

project(sharkdb-engine
    LANGUAGES C CXX
    VERSION 0.1.0
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(third_party EXCLUDE_FROM_ALL)
include(third_party/capnproto/c++/cmake/CapnProtoMacros.cmake)

add_subdirectory(src)

include(cmake/clang-format.cmake)
clang_format(format include src)
