cmake_minimum_required(VERSION 3.18)
project(km_src C)

set(CMAKE_C_STANDARD 99)
include_directories(${CMAKE_SOURCE_DIR}/include)


# 选择适配的密码卡
cmake_host_system_information(RESULT HOST_NAME QUERY HOSTNAME)
IF (${HOST_NAME} MATCHES "gateway" OR ${HOST_NAME} MATCHES "gsc")
    add_compile_definitions(USE_SDF)
    set(IS_USE_SDF ON)
ELSEIF (${HOST_NAME} MATCHES "gs" OR ${HOST_NAME} MATCHES "as")
    add_compile_definitions(USE_PIICO)
    set(IS_USE_PIICO ON)
ELSE ()
    add_compile_definitions(USE_GMSSL)
    set(IS_USE_GMSSL ON)
ENDIF ()

set(SOURCES
        key_manage.c
        kmdb.c
)

# 创建库
add_library(km_src SHARED ${SOURCES})   # 生成共享库
add_library(km_src_static STATIC ${SOURCES})  # 生成静态库
add_library(km_src_static_test STATIC ${SOURCES})  # 生成静态库

# 包含和链接目录
target_include_directories(km_src PUBLIC /usr/local/include/ldacs)
target_link_directories(km_src PUBLIC /usr/local/lib/ldacs)
target_link_libraries(km_src LINK_PUBLIC ldacsutilcore)

target_link_libraries(${PROJECT_NAME} LINK_PUBLIC pthread uuid sqlite3)

IF (${IS_USE_SDF})
    target_link_libraries(${PROJECT_NAME} LINK_PUBLIC sdf sqlite3 ldacsutilcore)
ENDIF ()
IF (${IS_USE_PIICO})
    target_link_libraries(${PROJECT_NAME} LINK_PUBLIC piico_ccu sqlite3)
ENDIF ()
IF (${IS_USE_GMSSL})
    target_link_libraries(${PROJECT_NAME} LINK_PUBLIC gmssl sqlite3)
ENDIF ()

# 设置安装路径
# install(TARGETS km_src DESTINATION ${CMAKE_SOURCE_DIR}/build) #指定安装共享库的目标路径
INSTALL(TARGETS km_src ARCHIVE DESTINATION lib LIBRARY DESTINATION lib RUNTIME DESTINATION bin)
INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION include/km)

