cmake_minimum_required(VERSION 3.10)

project(MyProject)

set(CMAKE_BUILD_TYPE Debug)

include_directories(/usr/local/oqs-openssl/include)
link_directories(/usr/local/lib)

add_executable(my_program main.c)  # your program's source file

target_link_libraries(my_program ssl crypto)
