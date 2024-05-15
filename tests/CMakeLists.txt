cmake_minimum_required(VERSION 2.8.12.2)
project(km_test C)

set(CMAKE_C_STANDARD 99)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(tests
        keygen
        rkey_export
        key_distribute
)

enable_testing()
foreach (name ${tests})
    add_test(NAME ${name} COMMAND ${name}test)
    add_executable(${name}test ${name}_test.c)
    target_link_libraries(${name}test LINK_PUBLIC km_src sdf pthread uuid)

endforeach ()

