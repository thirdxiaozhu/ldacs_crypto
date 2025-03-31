cmake_minimum_required(VERSION 3.18)
project(km_test C)

set(CMAKE_C_STANDARD 99)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(tests
        # kdistribute
        # db         # 密钥库增删改查相关
        # sql_insert
        # sql_dyn_insert

        # hex_conv
        # rand
        # importk_with_kek
        # newpkg
        # kinstall
        # prehandle
        # kderive
        query_key_by_owner


        # query_id
        query_key
        # query_kekhandle
        # query_subid
        # query_keytype
        # query_keystate
        # query_owner
        # get_handle
        # query_for_update

        # kderive
        kderive_time
        krevoke
        krevoke_time
        rkey_gen #根密钥预置和激活
        rkey_to_ccard
        rkey_import
        kenable
        kestablish_sgw # 多级密钥派生
        kestablish_as
        kestablish_gs
        # kget_gs 
        # kget_as
        # kcom # 测试密钥对比
        kcom_based_id
        kupdate # 密钥更新 包括AS GS SGW主密钥和会话密钥的更新和撤销
        # kupdate_2
        # kupdate_3 # 新增sgw的密钥更新接口
        # xor # 抑或测试
        # enc_dec
        sm3_hmac
        km_hmac
        # asan
        rand
        rand_db # 测试 密钥库随机数存取
#        delete_keyvalue
        # hex_conv # 字符数组转字符串
        gkey_gen_exp # 组密钥生成和导出
        gkey_to_ccard # 组密钥导入密码卡
        gkey_import # 组密钥导入
        gethandle

)
cmake_host_system_information(RESULT HOST_NAME QUERY HOSTNAME)

IF (${HOST_NAME} MATCHES "gateway" OR ${HOST_NAME} MATCHES "gsc" OR ${HOST_NAME} MATCHES "as")

enable_testing()
foreach (name ${tests})
    add_test(NAME ${name} COMMAND ${name}test)
    add_executable(${name}test ${name}_test.c)
    target_link_libraries(${name}test LINK_PUBLIC km_src pthread uuid sqlite3)

    IF (${HOST_NAME} MATCHES "gateway" OR ${HOST_NAME} MATCHES "gsc")
        target_link_libraries(${name}test LINK_PUBLIC sdf)
    ELSEIF (${HOST_NAME} MATCHES "as")
        target_link_libraries(${name}test LINK_PUBLIC piico_ccmu)
    ELSE ()
        target_link_libraries(${name}test LINK_PUBLIC gmssl)
    ENDIF ()

endforeach ()

ENDIF ()



