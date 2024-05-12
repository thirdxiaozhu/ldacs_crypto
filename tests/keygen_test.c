//
// Created by wencheng on 5/12/24.
//
// 20240227 by wencheng
#include <stdio.h>
#include <string.h>
#include "key_manage.h"

int main()
{
    // 密钥id生成测试
    // struct uuid_t uu[4] ;
    // uuid_generate(uu);

    // 变量初始化
    void *DeviceHandle, *pSessionHandle, *phKeyHandle;
    unsigned iv_len = 16;
    uint8_t iv_mac[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint8_t iv_enc[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint8_t iv_dec[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint8_t data[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                        0x29, 0xbe, 0xe1, 0xd6, 0x52, 0x49, 0xf1, 0xe9, 0xb3, 0xdb, 0x87, 0x3e, 0x24, 0x0d, 0x06, 0x47};
    unsigned int data_len = 32;
    unsigned int alg_id = SGD_SM4_CFB;
    uint8_t cipher_data[32];
    unsigned int cipher_data_len;
    uint8_t plain_data[32];
    unsigned int plain_data_len;
    int ret;

    // 打开设备
    SDF_OpenDevice(&DeviceHandle);
    SDF_OpenSession(DeviceHandle, &pSessionHandle);

    /*
        // pbkdf2 接口测试 20240301 通过测试
        printf("pbkdf2 test1====================================================\n");
        uint8_t *salt = "0123456789abcdef";
        uint32_t salt_len = strlen(salt);
        uint32_t derived_key_len = 32; // 需求中的派生密钥长度
        uint8_t derived_key[derived_key_len];
        ret = pbkdf2(key_cipher, key_len, salt, salt_len, 1024, derived_key_len, derived_key);
        if (ret == LD_KM_OK)
        {
            printbuff("pbkdf2 Derived Key", derived_key, derived_key_len);
        }
        printf("pbkdf2 test2====================================================\n");
        uint32_t derived_keylen2 = 16;
        uint8_t derived_key2[derived_keylen2];
        ret = pbkdf2(key_cipher, key_len, salt, salt_len, 1024, derived_keylen2, derived_key2);
        if (ret == LD_KM_OK)
        {
            printbuff("pbkdf2 Derived Key2", derived_key2, derived_keylen2);
        }
    */
    /*
        // 网关端根密钥生成和导出
        unsigned int rootkey_len = 16;
        struct KeyMetaData root_keyinfo = {
            // 指定该密钥的信息 封装成结构体keypkg
            .length = rootkey_len,
            .owner_1 = "AS1",     // 管理员指定
            .owner_2 = "Sec-GW1", // 管理员指定
            .state = PRE_ACTIVATION,
            .type = ROOT_KEY,
            .update_cycle = 365,
        };
        struct KeyPkg keypkg;
        // struct KeyPkg *keypkg = malloc(sizeof(struct KeyPkg));
        ret = export_rootkey(&root_keyinfo, &keypkg); // 根密钥存入文件
        if (ret != LD_KM_OK)
        {
            printf("export_rootkey WRONG\n");
        }
        else
        {
            printf("[**SGW**]export rootkey OK=======================\n");
            print_key_pkg(&keypkg);
        }
    */
    /*
            // 网关端使用根密钥
            void *rootkey_handle1;
            ret = get_keyhandle(keypkg, &rootkey_handle1);
            if (ret != LD_KM_OK)
            {
                printf("get rootkey handle error\n");
            }
            else
            {
                printf("get rootkey handle OK,handle %p\n", rootkey_handle1);
            }
*/

    //  AS端根密钥导入
    void *rootkey_handle;
    // struct KeyPkg *root_pkg = malloc(sizeof(struct KeyPkg));
    struct KeyPkg root_pkg;
    ret = import_rootkey(&root_pkg, &rootkey_handle); // AS预置根密钥：存储于AS端密码卡
    if (ret != LD_KM_OK){
        printf("rootkey has NOT been stored in pcie\n");
    }
    else
    {
        printf("[**AS**]import OK,rootkey has been stored in pcie. handle %p\n", rootkey_handle);
        // print_key_pkg(&root_pkg);
    }
    /*
        // AS端使用根密钥
        printf("test get_rootkey_handle============\n");
        void *rootkey_handle;
        ret = get_rootkey_handle(&rootkey_handle);
        if (ret != LD_KM_OK)
        {
            printf("get rootkey handle error\n");
        }
        else
        {
            printf("get rootkey handle OK,handle %p\n", rootkey_handle);
        }
    */

    // derive_key 接口测试 20240228 通过测试
    // 主密钥派生
    uint32_t key_asswg_len = 16;
    uint8_t *shared_info = "shareinfo_hashshareinfo_hash";
    uint8_t *owner1 = "AS1";
    uint8_t *owner2 = "SGW1";
    uint8_t shared_info_len = strlen(shared_info);
    void *masterkey_handle;
    // struct KeyPkg *pkg = malloc(sizeof(struct KeyPkg));
    struct KeyPkg pkg;
    // ret = derive_key(rootkey_handle, MASTER_KEY_AS_SGW, key_asswg_len, owner1, owner2, shared_info, shared_info_len, &masterkey_handle, pkg);
    ret = derive_key(rootkey_handle, MASTER_KEY_AS_SGW, key_asswg_len, owner1, owner2, shared_info, shared_info_len, &masterkey_handle, &pkg);
    if (ret == LD_KM_OK)
    {
        printf("Key as-sgw syccessfully derived!---------------\n");
        printf("key handle %p\n", masterkey_handle);
        // print_key_pkg(pkg);
        print_key_pkg(&pkg);
    }
    else
    {
        printf("Key derivation failed.\n");
    }

    /*
            // 主密钥使用
            void *masterkey_handle1;
            ret = get_keyhandle(pkg, &masterkey_handle1);
            if (ret != LD_KM_OK)
            {
                printf("get_keyhandle failed!\n");
            }
            else
            {
                printf("get masterkey handle success! handle %p\n", masterkey_handle1);
            }

            // derive_session_key 接口测试会话加密密钥
            uint32_t sessionkey_len = 16;
            uint8_t rand[16];
            uint8_t rand_len = 16;
            generate_random(rand_len, rand);
            void *sessionkey_handle = (void *)malloc(sizeof(void *));
            struct KeyPkg *session_for_enc_pkg = malloc(sizeof(struct KeyPkg));
            int result = derive_key(masterkey_handle, SESSION_KEY_USR_ENC, 16, owner1, owner2, rand, rand_len, sessionkey_handle, session_for_enc_pkg);
            if (result == LD_KM_OK)
            {
                printf("session Key syccessfully derived!the Handle is %p\n", sessionkey_handle);
                // print_key_pkg(session_for_enc_pkg);
            }
            else
            {
                printf("Key derivation failed.ret %d\n", result);
            }

            // 会话密钥使用
            void *session_for_enc_handle;
            get_keyhandle(session_for_enc_pkg, &session_for_enc_handle);
            if (ret != LD_KM_OK)
            {
                printf("get_keyhandle failed!\n");
            }
            else
            {
                printf("get session key handle success! handle %p\n", session_for_enc_handle);
            }
        */
    /*
        // 会话完整性密钥
        uint8_t rand2[16];
        uint8_t rand2_len = 16;
        generate_random(rand2_len, rand2);
        void *sessionkey_int_handle = (void *)malloc(sizeof(void *));
        struct KeyMetaData *sessionkey_int_info = malloc(sizeof(struct KeyMetaData));
        result = derive_session_key(masterkey_handle, SESSION_KEY_USR_INT, rand2, rand2_len, sessionkey_int_handle, sessionkey_info);
        if (result == LD_KM_OK)
        {
            printf("session Key syccessfully derived!the Handle is %p\n", sessionkey_handle);
            printf("metadata is as followed:\n");
            print_key_metadata(sessionkey_info);
        }
        else
        {
            printf("Key derivation failed.ret %d\n", result);
        }
    */
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle); // 关闭设备

    return 0;
}