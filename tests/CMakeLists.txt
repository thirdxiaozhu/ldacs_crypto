cmake_minimum_required(VERSION 2.8.12.2)
project(km_test C)

set(CMAKE_C_STANDARD 99)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(tests
        # kdistribute
        # db         # 密钥库增删改查相关
        # sql_insert
        # sql_dyn_insert
        # queryid
        # query_subid
        # query_keytype
        
        # hex_conv
        # rand
        # importk_with_kek
        krevoke
        # newpkg
        # kinstall
        # prehandle
        # kderive
        # query_key
        # kenable
        rkey_gen #根密钥预置和激活
        rkey_to_ccard
        rkey_import
        kenable
        kestablish_sgw # 多级密钥派生 
        kestablish_as 
        kestablish_gs
        kget_gs # 测试密钥对比
        kget_as
        kupdate # 密钥更新 包括AS GS SGW主密钥和会话密钥的更新和撤销

)
cmake_host_system_information(RESULT HOST_NAME QUERY HOSTNAME)

enable_testing()
foreach (name ${tests})
    add_test(NAME ${name} COMMAND ${name}test)
    add_executable(${name}test ${name}_test.c)
    target_link_libraries(${name}test LINK_PUBLIC km_src pthread uuid sqlite3)

    IF (${HOST_NAME} MATCHES "gateway" OR ${HOST_NAME} MATCHES "gsc")
        target_link_libraries(${name}test LINK_PUBLIC sdf)
    ELSE ()
        target_link_libraries(${name}test LINK_PUBLIC piico_ccu)
    ENDIF ()

endforeach ()

