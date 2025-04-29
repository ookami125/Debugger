cmake_minimum_required(VERSION 3.10)

project(Debugger)

set (CMAKE_CXX_STANDARD 20)

add_executable(Debugger
  src/main.cpp
  src/file.cpp
)
