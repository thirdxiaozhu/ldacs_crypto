/**
 * 20240513 by wencheng 测试光电密码卡支持的非国密算法
 * 测试结果：支持AES128ECB/CBC/CFB/OFB SHA-256
*/
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

/*    
    // 导入密钥
    uint32_t key_len = 16;
    ret = import_key(key_cipher, key_len, &phKeyHandle);
    if (ret != SDR_OK)
    {
        log_warn("import key_cipher error!return 08x% 08x(%s)\n", ret, strerror(ret));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }

    unsigned int alg_id = SGD_AES128_OFB;
    log_warn("algorithm :%08x\n", alg_id);
    // 加密
    int encrypt_result = SDF_Encrypt(pSessionHandle, phKeyHandle, alg_id, iv_enc, data, data_len, cipher_data, &cipher_data_len);
    if (encrypt_result == 0)
    {
        // 加密成功，cipher_data 中存放着加密后的数据
        log_warn("Encrytion OK\n");
    }
    else
    {
        // 加密失败，根据错误代码进行处理
        log_warn("Encryption failed with error code: %d\n", encrypt_result);
        return -1;
    }

    // 解密
    int decrypt_result = SDF_Decrypt(pSessionHandle, phKeyHandle, alg_id, iv_dec, cipher_data, cipher_data_len, plain_data, &plain_data_len);
    if (decrypt_result == 0 && memcmp(data, plain_data, data_len) == 0) // 比对原始数据和解密结果
    {
        log_warn("Decryption verify successful!\n");
    }
    else
    {
        // 解密失败，根据错误代码进行处理
        log_warn("Decryption failed with error code: %d\n", decrypt_result);
        return -1;
    }
*/
    // hash
    uint32_t hash_alg = SGD_HMAC_SHA256;
    uint8_t hash_value[32];
    int hash_ret = hash(hash_alg, data, data_len, hash_value);
    if (hash_ret == LD_KM_OK) // 比对原始数据和解密结果
    {
        log_warn("algo %08x ,hash calc successful!\n",hash_alg);
        printbuff("hash value",hash_value,32);
    }
    else
    {
        // 解密失败，根据错误代码进行处理
        log_warn("Hash failed with error code: %08x\n", hash_ret);
        return -1;
    }

    // 销毁内存中的密钥 关闭会话
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
}