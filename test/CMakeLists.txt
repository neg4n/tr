cmake_minimum_required(VERSION 3.10)
project(trtest)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


include_directories("${CMAKE_SOURCE_DIR}/../include/")

add_executable(trtest "src/main.cpp")
set_target_properties(trtest PROPERTIES CXX_STANDARD 17)