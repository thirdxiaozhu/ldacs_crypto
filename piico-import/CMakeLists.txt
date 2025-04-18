cmake_minimum_required(VERSION 3.20)
project(piico-import C)

set(CMAKE_C_STANDARD 99)

add_executable(${PROJECT_NAME} piico-import.c)
add_executable(cli::test_client ALIAS ${PROJECT_NAME})
target_link_libraries(${PROJECT_NAME} LINK_PUBLIC piico_ccmu)
INSTALL(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION /usr/local/bin)
