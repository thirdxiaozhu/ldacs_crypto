cmake_minimum_required(VERSION  3.18)
set(CMAKE_C_STANDARD 99)

project(key_management C)

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


