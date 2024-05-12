cmake_minimum_required(VERSION 3.22)
project(km_src C)

set(CMAKE_C_STANDARD 99)
include_directories(${CMAKE_SOURCE_DIR}/include)

add_library(km_src SHARED key_manage.c )

# 光电密码卡
target_link_libraries(${PROJECT_NAME} LINK_PUBLIC sdf pthread uuid)
# 派科密码卡
# target_link_libraries(${PROJECT_NAME} LINK_PUBLIC piico_ccmu pthread uuid)


# 设置安装路径
install(TARGETS km_src DESTINATION ${CMAKE_SOURCE_DIR}/build) #指定安装共享库的目标路径
# install(FILES keymanage.h DESTINATION /) #将头文件安装到指定路径
INSTALL(TARGETS km_src ARCHIVE DESTINATION lib LIBRARY DESTINATION lib RUNTIME DESTINATION bin)
INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION include/km)
