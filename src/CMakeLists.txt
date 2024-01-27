cmake_minimum_required(VERSION 2.8.12.2)
project(km_src C)

set(CMAKE_C_STANDARD 99)
include_directories(${CMAKE_SOURCE_DIR}/include)
#include_directories(./)

add_library(km_src SHARED key_manage.c)
