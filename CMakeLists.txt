cmake_minimum_required(VERSION 3.20)
set(CMAKE_C_STANDARD 99)

project(key_management C)

# 内存泄露检测
# cmake_host_system_information(RESULT PRETTY_NAME QUERY DISTRIB_PRETTY_NAME)
# message("PRETTY_NAME: ${PRETTY_NAME}")
# IF (${PRETTY_NAME} MATCHES "CentOS")
#     set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -g") # 启用 AddressSanitizer 并生成调试信息
#     #    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=leak -g") # 启用 LeakSanitizer，用于检测内存泄漏问题
# ENDIF ()


add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(piico-import)


