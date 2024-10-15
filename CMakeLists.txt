cmake_minimum_required(VERSION  2.8.12.2)
set(CMAKE_C_STANDARD 99)

project(key_management C)

# 内存泄露检测
# cmake_host_system_information(RESULT PRETTY_NAME QUERY DISTRIB_PRETTY_NAME)
# message("PRETTY_NAME: ${PRETTY_NAME}")
# IF (${PRETTY_NAME} MATCHES "CentOS")
#     set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -g") # 启用 AddressSanitizer 并生成调试信息
#     #    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=leak -g") # 启用 LeakSanitizer，用于检测内存泄漏问题
# ENDIF ()

include_directories(${CMAKE_SOURCE_DIR}/include)

add_subdirectory(src)
add_subdirectory(tests)

#add_executable(key_management key_distribute_test.c)
# guangdian pice 
#target_link_libraries(${PROJECT_NAME} LINK_PUBLIC km_src sdf pthread uuid)
# paike pcie
# target_link_libraries(${PROJECT_NAME} LINK_PUBLIC km_src piico_ccmu uuid)

INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION include/km)
# paike pcie
# target_link_libraries(${PROJECT_NAME} LINK_PUBLIC km_src piico_ccmu uuid)


