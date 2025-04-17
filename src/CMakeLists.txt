cmake_minimum_required(VERSION 3.18)
project(ldacscrypto VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)

if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/usr/local/ldacs-cauc" CACHE PATH "Default install path" FORCE)
endif ()


# 创建库
add_library(${PROJECT_NAME} STATIC key_manage.c kmdb.c)   # 生成共享库

target_link_libraries(${PROJECT_NAME} LINK_PUBLIC uuid sqlite3)


target_include_directories(${PROJECT_NAME}
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include/crypto>
)


option(SGW_DEVICE "SGW Device Option" OFF)
option(AS_DEVICE "AS Device Option" OFF)
option(GS_DEVICE "GS Device Option" OFF)
#option(GMSSL_DEVICE "GMSSL Device Option" OFF)


IF (SGW_DEVICE)
    MESSAGE(STATUS "SGW Device Compiling...")
    target_link_libraries(${PROJECT_NAME} LINK_PUBLIC sdf)
    option(USE_SDF "Enable SDF" ON)
    #    add_executable(gen-rootkey gen_rootkey.c)
    #    target_link_libraries(gen-rootkey LINK_PUBLIC uuid sqlite3 sdf)
ELSEIF (AS_DEVICE OR GS_DEVICE)
    MESSAGE(STATUS "AS/GS Device Compiling...")
    target_link_libraries(${PROJECT_NAME} LINK_PUBLIC piico_ccmu)
    option(USE_PIICO "Enable PIICO" ON)
ELSE ()
    MESSAGE(STATUS "Using GMSSL...")
    target_link_libraries(${PROJECT_NAME} LINK_PUBLIC gmssl)
    option(USE_GMSSL "Enable GMSSL" ON)
ENDIF ()


configure_file(
        "${CMAKE_SOURCE_DIR}/config/km.h.in"
        "${CMAKE_SOURCE_DIR}/include/km.h"
)

# 设置安装路径
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES output_name "ldacscrypto")
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
INSTALL(TARGETS ${PROJECT_NAME} EXPORT LdacscryptoTargets ARCHIVE DESTINATION lib LIBRARY DESTINATION lib)
INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION include/crypto)

INSTALL(EXPORT LdacscryptoTargets
        FILE LdacscryptoTargets.cmake
        NAMESPACE ldacscrypto::
        DESTINATION /usr/local/lib/cmake/ldacscrypto
)

# 生成并安装 Config 文件
include(CMakePackageConfigHelpers)

# 生成 aaaConfigVersion.cmake
write_basic_package_version_file(
        ${CMAKE_SOURCE_DIR}/cmake/LdacscryptoConfigVersion.cmake
        VERSION ${Ldacscrypto_VERSION}
        COMPATIBILITY SameMajorVersion
)

# 生成 aaaConfig.cmake
configure_package_config_file(
        ${CMAKE_SOURCE_DIR}/cmake/LdacscryptoConfig.cmake.in
        ${CMAKE_SOURCE_DIR}/cmake/LdacscryptoConfig.cmake
        INSTALL_DESTINATION /usr/local/lib/cmake/ldacscrypto
)

# 安装 Config 和 Targets 文件
install(
        FILES
        ${CMAKE_SOURCE_DIR}/cmake/LdacscryptoConfig.cmake
        ${CMAKE_SOURCE_DIR}/cmake/LdacscryptoConfigVersion.cmake
        DESTINATION /usr/local/lib/cmake/ldacscrypto
)


#set(SO_PATH /usr/local/ldacs/lib)
#set(SO_CONFIG_DIR /etc/ld.so.conf.d)
#
#INSTALL(CODE "execute_process(COMMAND sudo sh -c \"echo ${SO_PATH} > ${SO_CONFIG_DIR}/ldacs-cauc.conf\" COMMAND sudo ldconfig )")