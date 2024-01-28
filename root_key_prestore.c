#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include <piico_pc/api.h>
#include <piico_pc/piico_define.h>
#include <piico_pc/piico_error.h>

int main(void)
{
    void *DeviceHandle, *pSessionHandle, *phKeyHandle;
    uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t iv_enc[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint8_t iv_dec[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    int key_len = 16;
    uint8_t data[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                        0x29, 0xbe, 0xe1, 0xd6, 0x52, 0x49, 0xf1, 0xe9, 0xb3, 0xdb, 0x87, 0x3e, 0x24, 0x0d, 0x06, 0x47};
    unsigned int data_len = 32;
    unsigned int alg_id = SGD_SM4_CFB;
    uint8_t cipher_data[32];
    unsigned int cipher_data_len;
    uint8_t plain_data[32];
    unsigned int plain_data_len;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != SDR_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
    }
    ret = SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    if (ret != SDR_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
    }

    // 密码卡使用工具生成非对称密钥对

    // 密码卡导出1号ECC加密公钥到文件
    unsigned int pkindex = 1; // 非对称密钥存储位置索引
    ECCrefPublicKey pk; // 非对称密钥
    ret = SDF_ExportEncPublicKey_ECC(pSessionHandle, pkindex, &pk);
    if (ret != SR_SUCCESSFULLY)
    {
        printf("SDF_ExportEncPublicKey_ECC error!return is %08x %08x\n", ret, SPII_GetErrorInfo(pSessionHandle));
    }
    else
    {
        printf("SDF_ExportEncPublicKey_ECC  succeed!\n");
        // printf("bits:%d\n", pk.bits);
        // printbuff("x", pk.x, ECCref_MAX_LEN);
        // printbuff("y", pk.y, ECCref_MAX_LEN);
    }
    uint8_t *filename = "public_key.txt"; 
    writePublicKeyToFile(&pk, filename); // 将公钥输出到文件

    // 网关导入密码卡公钥 使用公钥加密导出根密钥
    int rootkey_len = 128; // 只支持128bit
    ECCrefPublicKey pk_pcie; 
    readPublicKeyFromFile(&pk_pcie, filename);
    ret = compareECCrefPublicKey(&pk, &pk_pcie);
    if (ret == 0)
    {
        printf("compareECCrefPublicKey is the same\n");
    }
    ECCCipher *rootkey = malloc(sizeof(ECCCipher));
    void *rootkey_handle_in_sgw;
    ret = SDF_GenerateKeyWithEPK_ECC(pSessionHandle, rootkey_len, SGD_SM2_3, &pk_pcie, rootkey, &rootkey_handle_in_sgw);
    if (ret != SDR_OK)
    {
        printf("SDF_GenerateKeyWithEPK_ECC error,return 0x%08x\n", ret);
    }
    else
    {
        printf("SDF_GenerateKeyWithEPK_ECC OK, the Handle is %p\n", rootkey_handle_in_sgw);
    }
    uint8_t *root_key_file = "rootkey.txt"; // Example filename
    writeCipherToFile(rootkey, root_key_file);

    // 密码卡读取文件导入根密钥
    ECCCipher *rootkey_from_secgw = malloc(sizeof(ECCCipher));
    readCipherFromFile(rootkey_from_secgw, root_key_file);
    ret = compareECCCipher(rootkey, rootkey_from_secgw);
    if (ret == 0)
    {
        printf("ECCCipher is the same\n");
    }
    uint8_t *pin = "e304e304!";
    unsigned int pin_len = strlen(pin);
    ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, pkindex, pin, pin_len); // 获取私钥使用权限
    if (ret != SDR_OK)
    {
        printf("SDF_GetPrivateKeyAccessRight error,return 0x%08x\n", ret);
    }
    else
    {
        printf("SDF_GetPrivateKeyAccessRight OK\n");
    }
    void *rootkey_handle_in_pcie;
    ret = SDF_ImportKeyWithISK_ECC(pSessionHandle, pkindex, rootkey, &rootkey_handle_in_pcie); // 使用私钥解密根密钥 导入密码卡
    if (ret != SDR_OK)
    {
        printf("SDF_ImportKeyWithISK_ECC error,return 0x%08x\n", ret);
    }
    else
    {
        printf("SDF_ImportKeyWithISK_ECC OK, the Handle is %p\n", rootkey_handle_in_pcie);
    }
   
}