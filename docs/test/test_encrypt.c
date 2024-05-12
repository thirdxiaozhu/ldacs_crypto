// 20240307 by wencheng
#include <stdio.h>
#include <string.h>
#include "key_manage.h"

int main()
{
    void *DeviceHandle, *pSessionHandle, *phKeyHandle;
    uint8_t key_cipher[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned iv_len = 16;
    uint8_t iv_mac[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint8_t iv_enc[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint8_t iv_dec[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint8_t data[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                        0x29, 0xbe, 0xe1, 0xd6, 0x52, 0x49, 0xf1, 0xe9, 0xb3, 0xdb, 0x87, 0x3e, 0x24, 0x0d, 0x06, 0x47};
    unsigned int data_len = 32;

    uint8_t cipher_data[32];
    unsigned int cipher_data_len;
    uint8_t plain_data[32];
    unsigned int plain_data_len;
    int ret;

    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄

    // 导入密钥
    printf(" import_key test====================================================\n");
    uint32_t key_len = 32;
    ret = import_key(key_cipher, key_len, &phKeyHandle);
    if (ret != SDR_OK)
    {
        printf("import key_cipher error!return 08x% 08x(%s)\n", ret, strerror(ret));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }
    else
    {
        printf("import key_cipher success!the Handle is %p\n", phKeyHandle);
    }

    // 加密
    printf("encrypt test====================================================\n");
    unsigned int alg_id = SGD_SM4_ECB;
    int encrypt_result = SDF_Encrypt(pSessionHandle, phKeyHandle, alg_id, iv_enc, data, data_len, cipher_data, &cipher_data_len);
    if (encrypt_result == 0)
    {
        // 加密成功，cipher_data 中存放着加密后的数据
        // cipher_data_len 中存放着加密后数据的长度
        printbuff("raw data", data, data_len);
        printbuff("iv_enc", iv_enc, 16);
        printbuff("key_cipher", key_cipher, key_len);
        printf("key_cipher handle %p\n", phKeyHandle);
        printbuff("encrypted data", cipher_data, cipher_data_len);
        printf("Encryption successful!\n");
    }
    else
    {
        // 加密失败，根据错误代码进行处理
        printf("Encryption failed with error code: %d\n", encrypt_result);
        return -1;
    }

    // 解密
    printf("decrypt test====================================================\n");
    int decrypt_result = SDF_Decrypt(pSessionHandle, phKeyHandle, alg_id, iv_dec, cipher_data, cipher_data_len, plain_data, &plain_data_len);
    printbuff("key_cipher", key_cipher, key_len);
    printbuff("iv_dec", iv_dec, 16);
    printf("key_cipher handle %p\n", phKeyHandle);
    printf("plain data len:%d \n", plain_data_len);
    printbuff("decrypted data", plain_data, plain_data_len);
    if (decrypt_result == 0 && memcmp(data, plain_data, data_len) == 0) // 比对原始数据和解密结果
    {
        printf("Decryption successful!\n");
    }
    else
    {
        // 解密失败，根据错误代码进行处理
        printf("Decryption failed with error code: %d\n", decrypt_result);
        return -1;
    }

    // 销毁内存中的密钥 关闭会话
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
}