/**
 * @author wencheng
 * @version 2024/08/28
 * @brief data handle and database test
 */

#include "../include/key_manage.h"
#include "../include/kmdb.h"

int main() {
    uint8_t *db_name = "keystore.db";
    uint8_t *primary_key = "id";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";

    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs_s = "GS1";
    uint8_t *sac_gs_t = "GSt";
    uint8_t *sac_as = "Berry";

    // 查询根密钥id
    QueryResult_for_queryid *qr_mk = query_id(db_name, sgw_tablename, sac_as, sac_sgw, ROOT_KEY, ACTIVE);
    if (qr_mk->count != 1) {
        printf("Query rkid failed.\n");
        return LD_ERR_KM_QUERY;
    }

    uint32_t alg_id = ALGO_ENC_AND_DEC; // 假设 0 对应 SM4_ECB 算法
    uint8_t iv_dec[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
                          0x20};
    uint8_t iv_enc[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
                          0x20};

    uint8_t data[] = "Hello World!";
    uint32_t data_length = sizeof(data);
    uint8_t cipher_data[1024]; // 确保 cipher_data 足够大
    uint32_t cipher_data_len = sizeof(cipher_data);
    uint8_t plain_data[1024]; // 确保 plain_data 足够大
    uint32_t plain_data_len = sizeof(plain_data);

    // 调用加密接口
    l_km_err encrypt_err = km_sym_encrypt(db_name, sgw_tablename, qr_mk->ids[0], alg_id, iv_enc, data, data_length,
                                          cipher_data, &cipher_data_len);
    if (encrypt_err != LD_KM_OK) {
        printf("Encryption failed with error code: %d\n", encrypt_err);
        return 1;
    }

    // 调用解密接口
    l_km_err decrypt_err = km_sym_decrypt(db_name, sgw_tablename, qr_mk->ids[0], alg_id, iv_dec, cipher_data,
                                          cipher_data_len, plain_data, &plain_data_len);
    if (decrypt_err != LD_KM_OK) {
        printf("Decryption failed with error code: %d\n", decrypt_err);
        return 1;
    }

    // 输出解密后的数据
    printf("Decrypted data: %.*s\n", plain_data_len, plain_data);

    // 检查解密后的数据是否与原始数据相同
    if (data_length == plain_data_len && memcmp(data, plain_data, data_length) == 0) {
        printf("Encryption and decryption succeeded.\n");
    } else {
        printf("Decryption did not produce the original data.\n");
    }

    return 0;
}