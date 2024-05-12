//
// Created by wencheng on 5/12/24.
//

#include "key_manage.h"
int main(){
    // 变量初始化
    void *DeviceHandle, *pSessionHandle, *phKeyHandle;
    int ret;

    // 打开设备
    SDF_OpenDevice(&DeviceHandle);
    SDF_OpenSession(DeviceHandle, &pSessionHandle);

    // 网关端根密钥生成和导出
    unsigned int rootkey_len = 16;
    struct KeyMetaData root_keyinfo = {
            // 指定该密钥的信息 封装成结构体keypkg
            .length = rootkey_len,
            .owner_1 = "Berry", // 管理员指定
            .owner_2 = "SGW",   // 管理员指定
            .state = ACTIVE,
            .key_type = ROOT_KEY,
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
        // print_key_pkg(&keypkg);
        print_key_metadata(keypkg.meta_data);
    }

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle); // 关闭设备

    return 0;
}