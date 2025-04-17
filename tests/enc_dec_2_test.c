/**
 * @author wencheng
 * @version 2025/4/14
 * @brief 测试非16字节倍数的数据加解密
 */

#include "../include/key_manage.h"
#include "../include/kmdb.h"

int main() {
    uint16_t key_len = 16;
    void *key_handle;
    bool check_padding = TRUE;

    uint8_t key[key_len];
    l_km_err result = km_generate_random(key, key_len);
    if (result != LD_KM_OK) {
        fprintf(stderr, "Failed to generate random key. Error code: %d\n", result);
        return -1;
    } else {
        printf("generate random key OK\n");
    }

    result = km_import_key(key, key_len, &key_handle);
    if (result != LD_KM_OK) {
        fprintf(stderr, "Failed to import key. Error code: %d\n", result);
        return -1;
    } else {
        printf("import key OK, handle %p\n", key_handle);
    }

    uint32_t alg_id = ALGO_ENC_AND_DEC;
    uint8_t iv_dec[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
                          0x20};
    uint8_t iv_enc[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
                          0x20};

    uint8_t data[] = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";               // 待加密的数据
    uint32_t data_length = sizeof(data);        // 数据长度
    uint8_t *cipher_data = (uint8_t *) malloc(1024); // 分配加密后数据的空间
    if (cipher_data == NULL) {
        fprintf(stderr, "Memory allocation failed for cipher_data.\n");
        return -1;
    }
    uint32_t cipher_data_len;
    uint8_t plain_data[1024]; // 确保 plain_data 足够大
    uint32_t plain_data_len = 0;

    // 加密操作
//    result = km_encrypt(key_handle, alg_id, iv_enc, data, data_length, cipher_data, &cipher_data_len, check_padding);
//    if (result != LD_KM_OK) {
//        fprintf(stderr, "Encryption failed. Error code: %d\n", result);
//        free(cipher_data);
//        return -1;
//    }
//
//    printf("Encryption successful. Cipher data length: %u\n", cipher_data_len);
//
//    // 解密操作
//    result = km_decrypt(key_handle, alg_id, iv_dec, cipher_data, cipher_data_len, plain_data, &plain_data_len,
//                        check_padding);
//    if (result != LD_KM_OK) {
//        fprintf(stderr, "Decryption failed. Error code: %d\n", result);
//        free(cipher_data);
//        return -1;
//    }
//
//    printf("Decryption successful. Plain data length: %u\n", plain_data_len);
//
//    plain_data[plain_data_len] = '\0';
//    printf("%s\n", plain_data);
//
//    // 验证解密结果
//    if (strncmp((char *) data, (char *) plain_data, data_length) == 0) {
//        printf("OK!!!!.\n");
//    } else {
//        printf("Failed ===.\n");
//    }
//
    km_encrypt(key_handle, ALGO_ENC_AND_DEC, iv_enc, data, strlen(data), cipher_data, &cipher_data_len, TRUE);

    uint8_t pdata[128] = {0};
    uint32_t sz = 0;
    km_decrypt(key_handle, ALGO_ENC_AND_DEC, iv_dec, cipher_data, cipher_data_len, pdata, &sz, TRUE);

    printf("%s", pdata);

    // 释放内存
    free(cipher_data);

    return 0;
}