// 20240509 by wencheng SGW密钥派生和使用
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include <uuid/uuid.h>

int main()
{
    // 变量初始化
    void *DeviceHandle, *pSessionHandle, *phKeyHandle;
    int ret;

    // 打开设备
    SDF_OpenDevice(&DeviceHandle);
    SDF_OpenSession(DeviceHandle, &pSessionHandle);

    // AS端获取根密钥
    void *rootkey_handle;
    ret = get_rootkey_handle(&rootkey_handle);
    if (ret != LD_KM_OK)
    {
        printf("[**get rootkey handle error**]\n");
    }
    else
    {
        printf("[**get rootkey handle OK**]\n");
    }

    // 主密钥派生 指定所有者 shareinfo 密钥类型 派生主密钥
    uint32_t key_asswg_len = 16;
    uint8_t *sharedinfo = "shareinfo_hashshareinfo_hash";
    uint8_t *owner1 = "Berry";
    uint8_t *owner2 = "SGW";
    uint8_t shared_info_len = strlen(sharedinfo);
    void *masterkey_handle;
    enum KEY_TYPE key_type = MASTER_KEY_AS_SGW;
    struct KeyPkg pkg;
    ret = derive_key(rootkey_handle, key_type, key_asswg_len, owner1, owner2, sharedinfo, shared_info_len, &masterkey_handle, &pkg);
    if (ret == LD_KM_OK)
    {
        printf("[**Key as-sgw syccessfully derived**]==================\n");
        printf("key handle %p\n", masterkey_handle);
        // print_key_pkg(&pkg); // 打印主密钥完整信息
        print_key_metadata(pkg.meta_data);
    }
    else
    {
        printf("Key derivation failed.\n");
    }

/*
    // 主密钥使用 从密钥包中恢复句柄
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
*/

    // derive_session_key 接口测试派生会话加密密钥
    uint32_t sessionkey_len = 16;
    uint8_t rand[16];
    uint8_t rand_len = 16;
    generate_random(rand_len, rand);
    void *sessionkey_handle = (void *)malloc(sizeof(void *));
    struct KeyPkg *session_for_enc_pkg = malloc(sizeof(struct KeyPkg));
    int result = derive_key(masterkey_handle, SESSION_KEY_USR_ENC, 16, owner1, owner2, rand, rand_len, sessionkey_handle, session_for_enc_pkg);
    if (result == LD_KM_OK)
    {
        printf("[**session Key syccessfully derived**]=================\n");
        print_key_metadata(session_for_enc_pkg->meta_data); // 输出密钥描述信息
        // print_key_pkg(session_for_enc_pkg);
    }
    else
    {
        printf("Key derivation failed.ret %d\n", result);
    }
    /*
        // 从数据包恢复会话密钥句柄
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

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle); // 关闭设备

    return 0;
}