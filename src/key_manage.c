// 调用密码卡生成密钥
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "key_manage.h"
#include <time.h>
#include "kmdb.h"
#include "km_field.h"

#define DATA_SIZE 16
#define SM3_DIGEST_LENGTH 32
#define SESSION_KEY_EXPIRE_TIME 365 // 会话密钥超时时间

#ifndef USE_GMSSL
// 用于创建随机数种子索引表时的描述
static km_field_desc km_create_randseeds_table_fields[] = {
        // 密钥结构体字段描述
        {ft_uint32t,        0, "seeds_id", NULL},
        {ft_uuid,           0, "key_id",   NULL},
        {ft_uint16t,        0, "rand_len", NULL},
        {ft_uint8t_pointer, 0, "rand",     NULL},
        {ft_end,            0, NULL,       NULL},
};

// 用于创建密钥表时的域描述
static km_field_desc km_create_table_fields[] = {
        // 密钥结构体字段描述
        {ft_uuid,           0, "id",           NULL},
        {ft_enum,           0, "key_type",     NULL},
        {ft_uint8t_pointer, 0, "owner1",       NULL},
        {ft_uint8t_pointer, 0, "owner2",       NULL},
        {ft_uint8t_pointer, 0, "key_cipher",   NULL},
        {ft_uint32t,        0, "key_len",      NULL},
        {ft_enum,           0, "key_state",    NULL},
        {ft_timet,          0, "creatime",     NULL},
        {ft_uint16t,        0, "updatecycle",  NULL},
        {ft_uint32t,        0, "kek_len",      NULL},
        {ft_uint8t_pointer, 0, "kek_cipher",   NULL},
        {ft_uint8t_pointer, 0, "iv",           NULL},
        {ft_uint16t,        0, "iv_len",       NULL},
        {ft_enum,           0, "chck_algo",    NULL},
        {ft_uint16t,        0, "check_len",    NULL},
        {ft_uint8t_pointer, 0, "chck_value",   NULL},
        {ft_uint16t,        0, "update_count", NULL},
        {ft_end,            0, NULL,           NULL},
};

// 用于将数据包插入表时的域描述
static km_field_desc km_insert_table_fields[] = {
        // 密钥结构体字段描述
        {ft_uuid,           0, "id",           NULL},
        {ft_enum,           0, "key_type",     NULL},
        {ft_uint8t_pointer, 0, "owner1",       NULL},
        {ft_uint8t_pointer, 0, "owner2",       NULL},
        {ft_uint8t_pointer, 0, "key_cipher",   NULL},
        {ft_uint32t,        0, "key_len",      NULL},
        {ft_enum,           0, "key_state",    NULL},
        {ft_timet,          0, "creatime",     NULL},
        {ft_uint16t,        0, "updatecycle",  NULL},
        {ft_uint32t,        0, "kek_len",      NULL},
        {ft_uint8t_pointer, 0, "kek_cipher",   NULL},
        {ft_uint8t_pointer, 0, "iv",           NULL},
        {ft_uint16t,        0, "iv_len",       NULL},
        {ft_enum,           0, "chck_algo",    NULL},
        {ft_uint16t,        0, "check_len",    NULL},
        {ft_uint8t_pointer, 0, "chck_value",   NULL},
        {ft_uint16t,        0, "update_count", NULL},
        {ft_end,            0, NULL,           NULL},
};

struct_desc static km_table_desc = {"km_table", km_create_table_fields};

struct_desc static km_pkg_desc = {"km_pkg", km_insert_table_fields};

void key_meta_data_free(km_keymetadata_t *meta_data);

/*********************************************************
 *                     基础密码运算功能                  *
 ********************************************************/

// 生成随机数
l_km_err km_generate_random(uint8_t *random_data, int len) {
    void *DeviceHandle, *pSessionHandle;
    int ret;

    if (SDF_OpenDevice(&DeviceHandle)) {
        log_warn("SDF_OpenDevice error!\n");
        return LD_ERR_KM_OPEN_DEVICE;
    }

    if (SDF_OpenSession(DeviceHandle, &pSessionHandle)) {
        log_warn("SDF_OpenSession error!\n");
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    if (SDF_GenerateRandom(pSessionHandle, len, random_data)) {
        log_warn("SDF_GenerateRandom Function failure!, ret %08x\n",
                 SDF_GenerateRandom(pSessionHandle, len, random_data));
        return LD_ERR_KM_GENERATE_RANDOM;
    }
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_KM_OK;
}

l_km_err km_encrypt(void *key_handle, uint32_t alg_id, uint8_t *iv, uint8_t *data, uint32_t data_length,
                    uint8_t *cipher_data, uint32_t *cipher_data_len) {
    void *DeviceHandle, *pSessionHandle;
    void *phKeyHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_KM_OK) {
        log_warn("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }

    ret = SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    if (ret != LD_KM_OK) {
        log_warn("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    // 调用SDF_Encrypt函数
    int result = SDF_Encrypt(pSessionHandle, key_handle, alg_id, iv, data, data_length, cipher_data, cipher_data_len);
    if (result != LD_KM_OK) {
        log_warn("SDF_Encrypt with phKeyHandle error!ret is %08x \n", result);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_ENCRYPT;
    }
    return LD_KM_OK;
}

// 国密算法加密接口
l_km_err km_sym_encrypt(const char *db_name, const char *table_name, const char *key_id, uint32_t alg_id, uint8_t *iv,
                        uint8_t *data, uint32_t data_length,
                        uint8_t *cipher_data, uint32_t *cipher_data_len) {
    // 检查密钥状态
    if (query_state(db_name, table_name, key_id) != ACTIVE) {
        log_warn("key state mismatch\n");
        return LD_ERR_KM_KEY_STATE;
    }

    // 获取密钥句柄
    void *key_handle;
    if (get_handle_from_db(db_name, table_name, key_id, &key_handle) != LD_KM_OK) {
        log_warn("get key handle failed\n");
        return LD_ERR_KM_GET_HANDLE;
    }

    // 加密
    return km_encrypt(key_handle, alg_id, iv, data, data_length, cipher_data, cipher_data_len);
}

l_km_err km_decrypt(void *key_handle, uint32_t alg_id, uint8_t *iv, uint8_t *cipher_data, uint32_t cipher_data_len,
                    uint8_t *plain_data, uint32_t *plain_data_len) {
    void *DeviceHandle, *pSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄

    // 调用SDF_Dncrypt函数

    int result = SDF_Decrypt(pSessionHandle, key_handle, alg_id, iv, cipher_data, cipher_data_len, plain_data,
                             plain_data_len);
    if (result != LD_KM_OK) {
        log_warn("SDF_Decrypt with phKeyHandle error!ret is %08x \n", result);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_DECRYPT;
    }
    return LD_KM_OK;
}

// 对称解密
l_km_err km_sym_decrypt(const char *db_name, const char *table_name, const char *key_id, uint32_t alg_id, uint8_t *iv,
                        uint8_t *cipher_data, uint32_t cipher_data_len, uint8_t *plain_data, uint32_t *plain_data_len) {
    // 检查密钥状态
    if (query_state(db_name, table_name, key_id) != ACTIVE) {
        log_warn("key state mismatch\n");
        return LD_ERR_KM_KEY_STATE;
    }

    // 获取密钥句柄
    void *key_handle;
    if (get_handle_from_db(db_name, table_name, key_id, &key_handle) != LD_KM_OK) {
        log_warn("get key handle failed\n");
        return LD_ERR_KM_GET_HANDLE;
    }

    // 解密
    return km_decrypt(key_handle, alg_id, iv, cipher_data, cipher_data_len, plain_data, plain_data_len);
}

// hash算法
l_km_err km_hash(uint32_t alg_id, uint8_t *data, size_t data_len, uint8_t *output) {
    void *DeviceHandle, *pSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_KM_OK) {
        log_warn("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    if (ret != LD_KM_OK) {
        log_warn("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    uint8_t hashResult[32];
    uint32_t hashResultLen = 32;

    ret = SDF_HashInit(pSessionHandle, alg_id, NULL, NULL, 0);
    if (ret != LD_KM_OK) {
        log_warn("SDF_HashInit Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_HashInit;
    }

    ret = SDF_HashUpdate(pSessionHandle, data, data_len);
    if (ret != LD_KM_OK) {
        log_warn("SDF_HashUpdate Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_HashUpdate;
    }

    ret = SDF_HashFinal(pSessionHandle, hashResult, &hashResultLen);
    if (ret != LD_KM_OK) {
        log_warn("SDF_HashFinish Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_HashFinal;
    }
    // //printbuff("data", data, len);
    // //printbuff("hashResult", hashResult, hashResultLen);
    memcpy(output, hashResult, 32);

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_KM_OK;
}

// MAC运算 SM4_CFB
l_km_err
km_mac(void *key_handle, uint32_t alg_id, uint8_t *iv, uint8_t *data, uint32_t data_length, uint8_t *mac,
       uint32_t *mac_length) {
    void *DeviceHandle, *hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    int ret = SDF_CalculateMAC(hSessionHandle, key_handle, alg_id, iv, data, data_length, mac, mac_length);
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    if (ret != LD_KM_OK) {
        log_warn("SDF_CalculateMACZ with phKeyHandle error!ret is %08x \n", ret);
        return LD_ERR_KM_MAC;
    }

    return LD_KM_OK;
}

// 通用sm3 hmac ，key长度要求为32byte
l_km_err
km_hmac(uint8_t *key, uint32_t key_len, uint8_t *data, uint32_t data_len, uint8_t *hmac_value, uint32_t *hmac_len) {
    void *DeviceHandle, *pSessionHandle;
    uint32_t hash_result_len;
    uint8_t hash[64] = {0};
    uint8_t ipad_[HMAC_HASH_BLOCK_SIZE] = {0};
    uint8_t opad_[HMAC_HASH_BLOCK_SIZE] = {0};
    int ret;

    // 参数非空检查
    if (!key || key_len > 64 || !data || !data_len) {
        log_warn("km_hmac LD_ERR_KM_PARAMETERS_ERR\n");
        return LD_ERR_KM_PARAMETERS_ERR;
    }

    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_KM_OK) {
        log_warn("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }

    ret = SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话
    if (ret != LD_KM_OK) {
        log_warn("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    bool fail_tag = FALSE;
    do {
        // prepare key
        memcpy(ipad_, key, (sizeof(uint8_t) * key_len));
        memcpy(opad_, key, sizeof(uint8_t) * key_len);

        // prepare for ipad and opad
        for (uint32_t i = 0; i < HMAC_HASH_BLOCK_SIZE; i++) {
            ipad_[i] ^= 0x36;
            opad_[i] ^= 0x5c;
        }

        // digest ipad and data
        ret = SDF_HashInit(pSessionHandle, SGD_SM3, NULL, NULL, 0);
        if (ret != LD_KM_OK) {
            log_warn("SDF_HashInit Function failure! %08x \n", ret);
            fail_tag = TRUE;
            break;
        }

        ret = SDF_HashUpdate(pSessionHandle, ipad_, HMAC_HASH_BLOCK_SIZE);
        if (ret != LD_KM_OK) {
            log_warn("SDF_HashUpdate Function failure! %08x \n", ret);
            fail_tag = TRUE;
            break;
        }

        if (data_len < 8) // 自动填充 data 到 8 字节
        {
            uint8_t padded_data[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // 填充到 8 字节，全1填充
            memcpy(padded_data, data, data_len);
            ret = SDF_HashUpdate(pSessionHandle, padded_data, 8);
            if (ret != LD_KM_OK) {
                log_warn("SDF_HashUpdate Function failure! %08x \n", ret);
                fail_tag = TRUE;
                break;
            }
        } else {
            ret = SDF_HashUpdate(pSessionHandle, data, data_len);
            if (ret != LD_KM_OK) {
                log_warn("SDF_HashUpdate Function failure! %08x \n", ret);
                fail_tag = TRUE;
                break;
            }
        }

        ret = SDF_HashFinal(pSessionHandle, hash, &hash_result_len);
        if (ret != LD_KM_OK) {
            log_warn("SDF_HashFinish Function failure! %08x \n", ret);
            fail_tag = TRUE;
            break;
        }
        // //printbuff("km_hmac check point :digest ipad and data", km_hash, hash_result_len);

        // digest opad and km_hash
        ret = SDF_HashInit(pSessionHandle, SGD_SM3, NULL, NULL, 0);
        if (ret != LD_KM_OK) {
            log_warn("SDF_HashInit Function failure! %08x \n", ret);
            fail_tag = TRUE;
            break;
        }

        ret = SDF_HashUpdate(pSessionHandle, opad_, HMAC_HASH_BLOCK_SIZE);
        if (ret != LD_KM_OK) {
            log_warn("SDF_HashUpdate Function failure! %08x \n", ret);
            fail_tag = TRUE;
            break;
        }

        ret = SDF_HashUpdate(pSessionHandle, hash, 32);
        if (ret != LD_KM_OK) {
            log_warn("SDF_HashUpdate Function failure! %08x \n", ret);
            fail_tag = TRUE;
            break;
        }
        ret = SDF_HashFinal(pSessionHandle, hmac_value, hmac_len);
        if (ret != LD_KM_OK) {
            log_warn("SDF_HashFinal Function failure! %08x \n", ret);
            fail_tag = TRUE;
            break;
        } // //printbuff("km_hmac check point: digest opad and km_hash", hmac_value, *hmac_len);
    } while (0);

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_KM_OK;
}

// 使用句柄完成hmac
l_km_err
km_hmac_with_keyhandle(void *handle, uint8_t *data, uint32_t data_len, uint8_t *hmac_value, uint32_t *hmac_len) {
    void *DeviceHandle, *hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    uint8_t rand[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint8_t iv[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint8_t key[16];
    uint32_t key_len;
    // log_buf(LOG_INFO, "iv", iv, 16);
    // log_buf(LOG_INFO, "rand", rand, 16);

    int ret = SDF_Encrypt(hSessionHandle, handle, ALGO_ENC_AND_DEC, iv, rand, 16, key, &key_len);
    if (ret != LD_KM_OK) {
        log_warn("km_hmac_with_keyhandle  error!ret is %08x \n", ret);
        return LD_ERR_KM_HMAC;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    // log_buf(LOG_INFO, "key", key, key_len);
    // log_buf(LOG_INFO, "data", data, data_len);

    return km_hmac(key, key_len, data, data_len, hmac_value, hmac_len);
}

l_km_err km_sm3_hmac(const char *db_name, const char *table_name, const char *key_id, uint8_t *data, uint32_t data_len,
                     uint8_t *hmac_value, uint32_t *hmac_len) {
    // 检查密钥状态
    if (query_state(db_name, table_name, key_id) != ACTIVE) {
        log_warn("key state mismatch\n");
        return LD_ERR_KM_KEY_STATE;
    }

    // 获取密钥句柄
    void *key_handle;
    if (get_handle_from_db(db_name, table_name, key_id, &key_handle) != LD_KM_OK) {
        log_warn("get key handle failed\n");
        return LD_ERR_KM_GET_HANDLE;
    }

    // 执行hmac操作
    return km_hmac_with_keyhandle(key_handle, data, data_len, hmac_value, hmac_len);
}

// 打印字符串
l_km_err printbuff(const char *printtitle, uint8_t *buff, int len) {
    if (buff == NULL) {
        log_warn("error: printbuff NULL pamameter\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    }
    int i;
    log_warn("%s:\n", printtitle);
    for (i = 0; i < len; i++) {
        // log_warn("%02X ", buff[i]);
        log_warn("%02x ", buff[i]);
        if ((i + 1) % 16 == 0)
            // log_warn("\n");
            log_warn("\n");
    }

    if ((i % 16) == 0) {
        log_warn("-----------------------------\n");
    } else {
        log_warn("\n-----------------------------\n");
    }
    return LD_KM_OK;
}

/*********************************************************
 *                     基础密钥管理功能                  *
 ********************************************************/

// 导入明文密钥
l_km_err km_import_key(uint8_t *key, uint32_t key_length, void **key_handle) {
    void *DeviceHandle, *hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    int ret = SDF_ImportKey(hSessionHandle, key, key_length, key_handle);
    if (ret != SDR_OK) {
        log_warn("SDF_ImportKey with phKeyHandle error!ret is %08x \n", ret);
        return LD_ERR_KM_IMPORT_KEY;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_KM_OK;
}

/**
 * @brief 使用KEK导入密钥
 * @param[in] key 密钥（密文）
 * @param[in] key_len 密钥长度
 * @param[in] kek_index kek下标
 * @param[out] key_handle
 */
l_km_err km_import_key_with_kek(uint8_t *key, uint32_t key_length, int kek_index, void **key_handle) {
    void *DeviceHandle, *hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    int ret = SDF_ImportKeyWithKEK(hSessionHandle, ALGO_WITH_KEK, kek_index, key, key_length, key_handle);
    if (ret != SDR_OK) {
        log_warn("SDF_ImportKey with phKeyHandle error!ret is %08x \n", ret);
        return LD_ERR_KM_IMPORT_KEY;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_KM_OK;
}

// 销毁密钥
l_km_err km_destroy_key(void *key_handle) {
    void *DeviceHandle, *hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    int ret = SDF_DestroyKey(hSessionHandle, key_handle);
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    if (ret != LD_KM_OK) {
        log_warn("SDF_DestroyKey with phKeyHandle error!ret is %08x \n", ret);
        return LD_ERR_KM_DESTROY_KEY;
    }

    return LD_KM_OK;
}

// 基于口令的密钥派生函数（prf：sm3 hmac）
l_km_err km_pbkdf2(
        uint8_t *password,
        uint32_t password_len,
        uint8_t *salt,
        uint32_t salt_len,
        uint32_t iterations,
        uint32_t derived_key_len,
        uint8_t *derived_key);

// 基于口令的密钥派生（prf：sm3 hmac）
l_km_err km_pbkdf2(uint8_t *password, uint32_t password_len, uint8_t *salt, uint32_t salt_len, uint32_t iterations,
                   uint32_t derived_key_len, uint8_t *derived_key) {
    /* 参数检查 */
    if (password == NULL || salt == NULL) {
        log_warn("km_pbkdf2 fail , password and salt shouldn't be NULL\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    }
    /* 参数检查 盐值长度不能小于4字节*/
    if (salt_len < 4) {
        log_warn("km_pbkdf2 fail , salt len should over 4 byte \n");
        return LD_ERR_KM_PARAMETERS_ERR;
    }
    /* 迭代次数不能小于1024 */
    if (iterations < 1024) {
        log_warn("km_pbkdf2 fail , iterations should over 1024 times\n");
        return LD_ERR_KM_PARAMETERS_ERR;
    }
    /* 派生密钥的长度为128 256 512byte */
    if (derived_key_len != 16 && derived_key_len != 32 && derived_key_len != 64) {
        log_warn("km_pbkdf2 fail for illegal key len, 16/32/48/64 bytes are permitted\n");
        return LD_ERR_KM_PARAMETERS_ERR;
    }

    uint32_t dkLen = derived_key_len;                           // 所需的派生密钥长度
    uint32_t block_size = 32;                                   // 按照32byte将数据分块
    uint32_t block_num = (dkLen + block_size - 1) / block_size; // ceil(dkLen/block_size) 块数
    uint8_t *t = malloc(block_size * sizeof(uint8_t));
    uint8_t *u = malloc((salt_len + 4) * sizeof(uint8_t));
    uint8_t *xorsum = malloc((dkLen < 32 ? 32 : dkLen) * sizeof(uint8_t)); // 注意dklen<32时的空间分配
    // 动态分配内存检查
    if (t == NULL || u == NULL || xorsum == NULL) {
        perror("Memory allocation failed");
        free(t);
        free(u);
        free(xorsum);
        return LD_ERR_KM_MEMORY_ALLOCATION_IN_PBKDF2;
    }

    for (uint32_t i = 1; i <= block_num; i++) // 迭代计算每块
    {
        // Compute U_1 = PRF(password, salt || INT(i))
        memcpy(u, salt, salt_len);
        u[salt_len + 0] = (i >> 24) & 0xFF;
        u[salt_len + 1] = (i >> 16) & 0xFF;
        u[salt_len + 2] = (i >> 8) & 0xFF;
        u[salt_len + 3] = i & 0xFF;

        if (km_hmac(password, password_len, u, salt_len + 4, t, &block_size) != LD_KM_OK)
            // if (SDFE_Hmac(hSessionHandle, password, password_len, u, salt_len + 4, t, &block_size) != LD_OK)
        {
            perror("km_pbkdf2 SM3-HMAC computation failed\n");
            free(t);
            free(u);
            free(xorsum);
            return LD_ERR_KM_PBKDF2;
        }
        // U_2 = U_1, U_3 = U_2, ..., U_l = U_{block_num-1}
        memcpy(xorsum, t, block_size);

        for (uint32_t j = 2; j <= iterations; j++) {
            if (km_hmac(password, password_len, t, block_size, t, &block_size) != LD_KM_OK)
                // if (SDFE_Hmac(hSessionHandle, password, password_len, t, block_size, t, &block_size) != LD_OK)
            {
                perror("km_pbkdf2 SM3-HMAC iteration2 computation failed\n");
                free(t);
                free(u);
                free(xorsum);
                return LD_ERR_KM_PBKDF2;
            }

            // U_2 xor U_3 xor ... xor U_l
            for (uint32_t k = 0; k < block_size; k++) {
                xorsum[k] ^= t[k];
            }
        }

        // Copy the derived key block to the output
        uint32_t copy_len = (i == block_num && dkLen % block_size != 0) ? (dkLen % block_size) : block_size;
        // log_warn("copy len %d ,(i - 1) * block_size:(%d -1) * %d\n", copy_len, i, block_size);
        memcpy(derived_key + (i - 1) * block_size, xorsum, copy_len);
        // log_warn("copy_len:%d,i:%d, hlen%d",copy_len,i,block_size);

        // //printbuff("km_pbkdf2 output", derived_key, derived_key_len);
    }

    free(t);
    free(u);
    free(xorsum);

    return LD_KM_OK;
}

// 将文件存入密码卡文件区 指定输入文件的路径 存入密码卡时的文件名
l_km_err km_writefile_to_cryptocard(uint8_t *filepath, uint8_t *filename) {
    void *DeviceHandle, *hSessionHandle;
    FILE *file;
    uint32_t file_size;
    uint16_t result;
    uint8_t *buffer = NULL; // 初始化指针为 NULL

    // 打开设备
    if (SDF_OpenDevice(&DeviceHandle) != SDR_OK) {
        log_warn("Error opening device.\n");
        return LD_ERR_KM_OPEN_DEVICE;
    }

    // 打开会话句柄
    if (SDF_OpenSession(DeviceHandle, &hSessionHandle) != SDR_OK) {
        log_warn("Error opening session.\n");
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    // 打开文件
    file = fopen(filepath, "rb");
    if (file == NULL) {
        log_warn("Error opening file %s.\n", filepath);
        SDF_CloseSession(hSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_FILE;
    }

    // 定位文件末尾以获取文件大小
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    rewind(file);

    // 分配内存以存储文件内容
    buffer = (uint8_t *) malloc(file_size * sizeof(uint8_t));
    if (buffer == NULL) {
        log_warn("Memory allocation error.\n");
        fclose(file);
        SDF_CloseSession(hSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_WRITE_FILE;
    }

    // 将文件内容读入缓冲区
    result = fread(buffer, sizeof(uint8_t), file_size, file);
    if (result != file_size) {
        log_warn("Error reading file.\n");
        fclose(file);
        free(buffer); // 确保释放分配的内存
        SDF_CloseSession(hSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_WRITE_FILE;
    }

    // 文件内容写入密码卡
    int writeFileResult = SDF_WriteFile(hSessionHandle, filename, strlen((char *) filename), 0, file_size, buffer);
    if (writeFileResult != SDR_OK) {
        log_warn("Error writing to cryptocard file %s, return %08x\n", filename, writeFileResult);
        fclose(file);
        free(buffer); // 确保释放分配的内存
        SDF_CloseSession(hSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_WRITE_FILE;
    }

    // 关闭文件
    fclose(file);
    // 释放内存
    free(buffer);
    // 关闭会话和设备
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_KM_OK;
}

// 密码卡内删除文件
l_km_err km_delete_ccard_file(const char *filename) {
    void *DeviceHandle, *pSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄

    // 调用实际的文件创建函数
    int deteteFileResult = SDF_DeleteFile(pSessionHandle, (unsigned char *) filename, strlen(filename));

    // 检查函数调用结果
    if (deteteFileResult != SDR_OK) {
        log_warn("Error in creating cryptocard file %s, return %08x\n", filename, deteteFileResult);
        return LD_ERR_KM_DELETE_FILE; // 返回定义的错误代码
    }

    SDF_CloseSession(pSessionHandle); // 关闭会话
    SDF_CloseDevice(DeviceHandle);    // 关闭设备

    return LD_KM_OK;
}

// 密码卡内创建文件
l_km_err km_create_ccard_file(const char *filename, size_t file_size) {
    void *DeviceHandle, *pSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄

    // 调用实际的文件创建函数
    int createFileResult = SDF_CreateFile(pSessionHandle, (unsigned char *) filename, strlen(filename), file_size);

    // 检查函数调用结果
    if (createFileResult != SDR_OK) {
        log_warn("Error in creating cryptocard file %s, return %08x\n", filename, createFileResult);
        return LD_ERR_KM_CREATE_FILE; // 返回定义的错误代码
    }

    SDF_CloseSession(pSessionHandle); // 关闭会话
    SDF_CloseDevice(DeviceHandle);    // 关闭设备

    return LD_KM_OK;
}

// 从密码卡读取文件 放到指定位置
l_km_err km_readfile_from_cryptocard(const char *filename, const char *filepath) {
    void *DeviceHandle, *pSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    uint32_t ret;

    // 从文件区读取根密钥
    struct KeyPkg restored_pkg;
    uint32_t readLength = 268; // 根密钥文件的长度
    uint8_t restored_byteBuffer[readLength * 2];

    int readFileResult = SDF_ReadFile(pSessionHandle, (unsigned char *) filename, strlen(filename), 0, &readLength,
                                      restored_byteBuffer);
    if (readFileResult != 0) {
        log_warn("Error reading from file\n");
        return LD_ERR_KM_READ_FILE;
    }

    // 将根密钥结构体写入指定文件位置
    FILE *file;
    file = fopen(filepath, "wb");
    if (file == NULL) {
        log_warn("Error opening file.\n");
        return LD_ERR_KM_OPEN_FILE;
    }
    fwrite(restored_byteBuffer, readLength, 1, file);
    fclose(file);

    SDF_CloseSession(pSessionHandle); // 关闭会话
    SDF_CloseDevice(DeviceHandle);    // 关闭设备

    return LD_KM_OK;
}
/*********************************************************
 *                     业务逻辑接口                      *
 ********************************************************/
/****************
 * 密钥生成派生 *
 ***************/
// 指定KEK索引和密钥元数据（密钥类型，密钥所有者，密钥长度，启用日期，更新周期），初始化元数据并生成密钥、密钥id，输出密钥句柄、使用KEK加密的密钥密文、和密钥元数据结构体。
l_km_err km_generate_key_with_kek(int kek_index, uint32_t kek_len, void **key_handle, uint8_t *cipher_key,
                                  int *cipher_len) {
    void *DeviceHandle, *pSessionHandle;
    int ret; // iterate with crypto-device

    SDF_OpenDevice(&DeviceHandle);
    SDF_OpenSession(DeviceHandle, &pSessionHandle);

    // GenerateKeyWithKEK 128bit SM4-ECB 产生根密钥并用KEK加密导出 此处接口密钥长度单位为bit！！！
    do {
        ret = SDF_GenerateKeyWithKEK(pSessionHandle, kek_len * 8, ALGO_WITH_KEK, kek_index, cipher_key, cipher_len,
                                     key_handle);
        if (ret != SDR_OK) {
            log_warn("SDF_GenerateKeyKEK error!return is %08x\n", ret);
            free(cipher_key);
            break;
        }
        return LD_KM_OK;

    } while (0);

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_ERR_KM_GENERATE_KEY_WITH_KEK;
}

/**
 * @brief 密钥生成、保存和导出
 * */
l_km_err km_key_gen_export(const char *owner1, const char *owner2, enum KEY_TYPE key_type, uint32_t key_len,
                           uint32_t validity_period, const char *dbname, const char *tablename,
                           const char *export_file_path) {

    km_keypkg_t *rawpkg = NULL;
    km_keypkg_t *keypkg = NULL;
    km_keymetadata_t *key_data = NULL;
    l_km_err result = LD_KM_OK;


    do {
        // 生成密钥
        key_data = km_key_metadata_new(owner1, owner2, key_type, key_len, validity_period);
        if (key_data == NULL) {
            log_warn("Failed to create key metadata\n");
            result = LD_ERR_KM_MALLOC; // 或其他适当的错误码
            break;
        }

        uint8_t key[key_len];
        km_generate_random(key, key_len);
//        log_buf(LOG_INFO, "generate key plaintext: ", key, key_len);

        rawpkg = km_key_pkg_new(key_data, key, FALSE); // 明文
        if (rawpkg == NULL) {
            log_warn("Failed to create key package for raw key\n");
            result = LD_ERR_KM_MALLOC; // 或其他适当的错误码
            break;
        }

        // 导出根密钥到文件
        // delete_file(export_file_path); // 清除已有文件
        if (write_keypkg_to_file(export_file_path, rawpkg) != LD_KM_OK) {
            log_warn("write key to file failed\n");
            result = LD_ERR_KM_WRITE_FILE; // 或其他适当的错误码
            break;
        }
//        print_key_pkg(rawpkg);

        // 存储根密钥
        keypkg = km_key_pkg_new(key_data, key, TRUE);
        if (keypkg == NULL) {
            log_warn("Failed to create key package for storage\n");
            result = LD_ERR_KM_MALLOC; // 或其他适当的错误码
            break;
        }
//        print_key_pkg(keypkg);

        uint8_t *primary_key = "id";
        if (create_table_if_not_exist(&km_table_desc, dbname, tablename, primary_key, NULL, NULL, FALSE) !=
            LD_KM_OK) {
            log_warn("create table failed\n");
            result = LD_ERR_KM_CREATE_DB; // 或其他适当的错误码
            break;
        }
        if (store_key(dbname, tablename, keypkg, &km_pkg_desc) != LD_KM_OK) {
            log_warn("store key failed\n");
            result = LD_ERR_KM_EXE_DB; // 或其他适当的错误码
            break;
        }

    } while (0);

    // 释放资源
    if (rawpkg != NULL) {
        key_pkg_free(rawpkg);
    }
    if (keypkg != NULL) {
        key_pkg_free(keypkg);
    }

    return result;
}

/**
 * @brief 根密钥生成、保存和导出
 * */
l_km_err km_rkey_gen_export(const char *as_name, const char *sgw_name, uint32_t key_len, uint32_t validity_period,
                            const char *dbname, const char *tablename, const char *export_file_path) {
    if (km_key_gen_export(as_name, sgw_name, ROOT_KEY, key_len, validity_period, dbname, tablename, export_file_path) ==
        LD_KM_OK) {
        return LD_KM_OK;
    }

    /*
        km_keypkg_t *rk_rawpkg = NULL;
        km_keypkg_t *keypkg = NULL;
        km_keymetadata_t *key_data = NULL;
        l_km_err result = LD_KM_OK;

        do
        {
            // 生成根密钥
            key_data = km_key_metadata_new(as_name, sgw_name, ROOT_KEY, key_len, validity_period);
            if (key_data == NULL)
            {
                log_warn("Failed to create key metadata\n");
                result = LD_ERR_KM_MALLOC; // 或其他适当的错误码
                break;
            }

            uint8_t root_key[key_len];
            km_generate_random(root_key, key_len);
            log_buf(LOG_INFO, "generate key plaintext: ", root_key, key_len);

            rk_rawpkg = km_key_pkg_new(key_data, root_key, FALSE); // 明文
            if (rk_rawpkg == NULL)
            {
                log_warn("Failed to create key package for raw key\n");
                result = LD_ERR_KM_MALLOC; // 或其他适当的错误码
                break;
            }

            // 导出根密钥到文件
            // delete_file(export_file_path); // 清除已有文件
            if (write_keypkg_to_file(export_file_path, rk_rawpkg) != LD_KM_OK)
            {
                log_warn("write key to file failed\n");
                result = LD_ERR_KM_WRITE_FILE; // 或其他适当的错误码
                break;
            }
            // print_key_pkg(rk_rawpkg);

            // 存储根密钥
            keypkg = km_key_pkg_new(key_data, root_key, TRUE);
            if (keypkg == NULL)
            {
                log_warn("Failed to create key package for storage\n");
                result = LD_ERR_KM_MALLOC; // 或其他适当的错误码
                break;
            }
            // print_key_pkg(keypkg);

            uint8_t *primary_key = "id";
            if (create_table_if_not_exist(&km_table_desc, dbname, tablename, primary_key, NULL, NULL, FALSE) !=
                LD_KM_OK)
            {
                log_warn("create table failed\n");
                result = LD_ERR_KM_CREATE_DB; // 或其他适当的错误码
                break;
            }
            if (store_key(dbname, tablename, keypkg, &km_pkg_desc) != LD_KM_OK)
            {
                log_warn("store key failed\n");
                result = LD_ERR_KM_EXE_DB; // 或其他适当的错误码
                break;
            }

        } while (0);

        // 释放资源
        if (rk_rawpkg != NULL)
        {
            key_pkg_free(rk_rawpkg);
        }
        if (keypkg != NULL)
        {
            key_pkg_free(keypkg);
        }

        return result;
        */
}

/**
 * @brief 根密钥导入
 */
l_km_err km_rkey_import(const char *db_name, const char *table_name, const char *rkey_filename_in_ccard) {

    // read root key from ccard
    const char *local_rkdir = "/dev/shm/rootkey.txt";

    do {
        if (km_readfile_from_cryptocard(rkey_filename_in_ccard, local_rkdir) != LD_KM_OK) {
            break;
        }
        km_keypkg_t *raw_pkg = read_keypkg_from_file(local_rkdir);
        remove(local_rkdir);
//        print_key_pkg(raw_pkg);

        // root key store
        km_keypkg_t *keypkg = km_key_pkg_new(raw_pkg->meta_data, raw_pkg->key_cipher, TRUE);
        // keypkg->meta_data->state = ACTIVE; // 激活密钥
//        log_warn("=======================加密之后的密钥======================");
//        print_key_pkg(keypkg);
        if (create_table_if_not_exist(&km_table_desc, db_name, table_name, "id", NULL, NULL, FALSE) != LD_KM_OK) {
            break;
        }
        if (store_key(db_name, table_name, keypkg, &km_pkg_desc) != LD_KM_OK) {
            break;
        }
//        if (key_type == 1 || key_type == 3) {
//            log_warn("%s %s %d", owner1, owner2, key_len);
//            log_buf(LOG_ERROR, "HASH", hash_of_keytype, 32);
//            log_buf(LOG_ERROR, "HASH", hash_of_rand, 32);
//            log_buf(LOG_ERROR, "SALT", salt, salt_len);
//        }
//        log_warn("KEY TYPE:  %d", key_type);
//        log_buf(LOG_ERROR, "KEY", key, 16);

        // 释放变量空间
        key_pkg_free(keypkg);
        keypkg = NULL;
        key_pkg_free(raw_pkg);
        raw_pkg = NULL;

        return LD_KM_OK;

    } while (0);

    return LD_ERR_KM_IMPORT_KEY;
}

/**
 * @brief 密钥导入 适用于所有类型的密钥
 */
l_km_err km_key_import(const char *db_name, const char *table_name, const char *rkey_filename_in_ccard) {
    if (km_rkey_import(db_name, table_name, rkey_filename_in_ccard) == LD_KM_OK) {
        return LD_KM_OK;
    }
    return LD_ERR_KM_IMPORT_KEY;
}

/**
 * @brief 内部接口 单个密钥的派生
 * @param[in] kdk_handle 密钥加密密钥句柄
 * @param[in] key_type 所需的密钥类型
 * @param[in] key_len 所需密钥的长度
 * @param[in] owner1 密钥所有者，如果是本地使用的密钥，此处放本地身份
 * @param[in] owner2 另外一方密钥所有者
 * @param[in] rand 随机数
 * @param[in] rand_len 随机数长度
 * @param[out] key_handle 生成的密钥的句柄
 * @return 返回密钥包结构体
 */
km_keypkg_t *
derive_key(void *kdk_handle, enum KEY_TYPE key_type, uint32_t key_len, const char *owner1, const char *owner2,
           uint8_t *rand, uint32_t rand_len, void **key_handle) {
    void *DeviceHandle, *hSessionHandle;

    if (SDF_OpenDevice(&DeviceHandle) != SDR_OK) {
        log_warn("Error in derive: SDF_OpenDevice failed!\n");
        return NULL;
    }

    if (SDF_OpenSession(DeviceHandle, &hSessionHandle) != SDR_OK) {
        log_warn("Error in derive: SDF_OpenSession failed!\n");
        SDF_CloseDevice(DeviceHandle);
        return NULL;
    }

    key_len = key_len > 16 ? 16 : key_len; // 导入密钥 返回密钥句柄 截断 只取前16字节
    km_keymetadata_t *meta = km_key_metadata_new(owner1, owner2, key_type, key_len, SESSION_KEY_EXPIRE_TIME);
    km_keypkg_t *pkg = km_key_pkg_new(meta, NULL, FALSE);
    if (!pkg) {
        log_warn("Error in derive: km_key_pkg_new failed!\n");
        return NULL;
    }

    // 动态分配内存
    uint8_t *key = (uint8_t *) malloc(64 * sizeof(uint8_t));
    uint8_t *salt = (uint8_t *) malloc(32 * sizeof(uint8_t));
    uint8_t *hash_of_keytype = (uint8_t *) malloc(32 * sizeof(uint8_t));
    uint8_t *hash_of_rand = (uint8_t *) malloc(32 * sizeof(uint8_t));

    // 检查内存分配是否成功
    if (key == NULL || salt == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        key_meta_data_free(meta);
        // 释放已经分配的内存
        free(key);
        free(salt);
        return NULL;
    }
    uint32_t salt_len = 16; // 取前16byte输入pbkdf

    do {


        // 派生密钥
        if (km_hash(ALGO_HASH, (uint8_t *) type_names[key_type], strlen(type_names[key_type]), hash_of_keytype)) {
            log_warn("Error in derive : km_hash failed!\n\n");
            break;
        }
        // //printbuff("hash_of_keytype before pbkdf", hash_of_keytype, 32);

        // keytype的hash_value作为iv 使用上级密钥对rand的hash值加密，取前16byte作为盐值输入pbkdf2
        if (km_hash(ALGO_HASH, rand, rand_len, hash_of_rand)) {
            log_warn("Error in derive : km_hash failed!\n\n");
            break;
        }
        // //printbuff("hash_of_rand before pbkdf", hash_of_rand, 32);

        // //printbuff("salt before SDF_Encrypt", salt, salt_len);
        int ret = SDF_Encrypt(hSessionHandle, kdk_handle, ALGO_ENC_AND_DEC, hash_of_keytype, hash_of_rand, 32, salt,
                              &salt_len);
        if (ret != SDR_OK) {
            log_warn("Error in derive : km_encrypt failed! %08x\n", ret);
            break;
        }
        // //printbuff("salt before pbkdf", salt, salt_len);

        // hash_of_rand作为password，使用主密钥对key_type加密的结果作为iv  输入pbkdf2后派生出密钥
        /* 使用SM3-HMAC作为密钥派生的PRF，迭代次数1024次 */
        if (km_pbkdf2(hash_of_rand, 32, salt, salt_len, 1024, key_len, key)) {
            log_warn("Error in derive : km_pbkdf2 failed!\n");
            break;
        }
        // print_key_metadata(pkg->meta_data);

        /* 生成对主密钥加密的密钥 */
        uint32_t kek_index = 1;
        void *kek_handle;
        uint8_t kek_cipher[16];
        uint32_t kek_len = 16;
        uint32_t kek_cipher_len;
        if (km_generate_key_with_kek(kek_index, kek_len, &kek_handle, pkg->kek_cipher, &pkg->kek_cipher_len) !=
            LD_KM_OK) // TODO: KEK存入密钥包
        {
            log_warn("Error in derive : SDF_GenerateKeyWithKEK failed!\n");
            break;
        }

        pkg->iv_len = 16;
        uint8_t iv_mac[16];
        uint8_t iv_enc[16];
        if (km_generate_random(pkg->iv, pkg->iv_len) != LD_KM_OK) {
            break;
        }

        // SDF_GenerateRandom(hSessionHandle, 16, iv_enc);
        memcpy(iv_mac, pkg->iv, pkg->iv_len); // 加密和Mac使用同一个密钥
        memcpy(iv_enc, pkg->iv, pkg->iv_len);

        uint32_t cipher_len;

        /* 主密钥加密 */
        if (SDF_Encrypt(hSessionHandle, kek_handle, ALGO_ENC_AND_DEC, iv_enc, key, key_len, pkg->key_cipher,
                        &cipher_len)) {
            log_warn("Error in derive : SDF_Encrypt failed!\n");
            break;
        }


        /* test */
//        char iv[16] = {0};
//        char data[16] = {0};
//        char res[256] = {0};
//        uint32_t res_len = 0;
//        km_encrypt(key, ALGO_ENC_AND_DEC, iv, data, 16, res, (uint32_t *) &res_len);
//        log_buf(LOG_ERROR, "TEST RES", res, res_len);

        /* 计算明文校验值 */
        if (km_mac(kek_handle, ALGO_MAC, iv_mac, key, key_len, pkg->chck_value, &(pkg->chck_len))) {
            log_warn("Error in derive : SDF_CalculateMAC failed!\n");
            break;
        }
        pkg->chck_alg = ALGO_MAC;
        pkg->meta_data->state = ACTIVE;

        if (key_handle != NULL && SDF_ImportKey(hSessionHandle, key, key_len, key_handle)) {
            log_warn("Error in derive : SDF_ImportKey\n");
            break;
        }
    } while (0);

    // 释放内存
    key_meta_data_free(meta);
    free(key);
    free(salt);
    free(hash_of_keytype);
    free(hash_of_rand);

    // 销毁内存中的密钥 关闭会话
    if (hSessionHandle != NULL) {
        SDF_CloseSession(hSessionHandle);
    }
    if (DeviceHandle != NULL) {
        SDF_CloseDevice(DeviceHandle);
    }

    return pkg;
}

/**
 * @brief 内部接口：主密钥派生并存储所有会话密钥
 * @param[in] dbname   密钥库名
 * @param[in] tablename 密钥表名
 * @param[in] handle_mk 主密钥句柄
 * @param[in] key_len 所需密钥的长度
 * @param[in] as_name  AS标识
 * @param[in] gs_name GS标识
 * @param[in] rand 随机数
 * @param[in] rand_len 随机数长度
 */
l_km_err km_derive_all_session_key(uint8_t *db_name, uint8_t *table_name, void *handle_mk, uint32_t key_len,
                                   const char *as_name, const char *gs_name, uint8_t *rand, uint32_t rand_len) {
    // 派生会话密钥
    enum KEY_TYPE key_types[4];
    key_types[0] = SESSION_KEY_USR_ENC;
    key_types[1] = SESSION_KEY_USR_INT;
    key_types[2] = SESSION_KEY_CONTROL_ENC;
    key_types[3] = SESSION_KEY_CONTROL_INT;

    km_keypkg_t *pkg;
    uint32_t sessionkey_len = 16;
    for (int i = 0; i <= 3; i++) {

        pkg = derive_key(handle_mk, key_types[i], sessionkey_len, as_name, gs_name, rand, rand_len, NULL);
        if (pkg == NULL) {
            log_warn("dervie key failed\n");
            return LD_ERR_KM_DERIVE_KEY;
        }
        // print_key_pkg(pkg);
        if (store_key(db_name, table_name, pkg, &km_pkg_desc) != LD_KM_OK) {
            log_warn("store_key failed: %d\n");
            return LD_ERR_KM_DERIVE_KEY;
        }

        key_pkg_free(pkg);
        pkg = NULL;
    }
    return LD_KM_OK;
}

/**
 * @brief 内部接口：主密钥KAS-GS的派生和存储
 * @param[in] dbname   密钥库名
 * @param[in] tablename 密钥表名
 * @param[in] handle_kassgw AS和SGW之间主密钥句柄
 * @param[in] key_len 所需密钥的长度
 * @param[in] as_name  AS标识
 * @param[in] gs_name  GS标识
 * @param[in] rand 随机数
 * @param[in] rand_len 随机数长度
 * @param[out] key_handle KAS-GS密钥的句柄
 * @return 返回报错码/成功码LD_KM_OK
 */

l_km_err km_derive_masterkey_asgs(const char *db_name, const char *table_name, void *handle_NH, uint32_t key_len,
                                  const char *as_name, const char *gs_name, uint8_t *rand, uint32_t rand_len,
                                  void **handle_kasgs) {

    uint16_t len_kasgs = 16;
    struct KeyPkg *pkg_kasgs;
    uint8_t *xor_result;

    printf("owner1: %s %p\n", as_name, as_name);
    printf("owner2: %s %p\n", gs_name, gs_name);
    do {
        /* 随机数与gs_name的hash值抑或 */
        uint16_t len_xor_res = rand_len;

        // Allocate memory for the hash result
        uint8_t hash_output[rand_len];
        memset(hash_output, 0, sizeof(hash_output));

        // Calculate the hash of gs_name using km_hash

        l_km_err hash_result = km_hash(ALGO_HASH, (uint8_t *) gs_name, strlen(gs_name), hash_output);

        if (hash_result != LD_KM_OK) {
            fprintf(stderr, "Hash function failed with error code %d\n", hash_result);
            return LD_ERR_KM_HashFinal;
        }
        // printbuff("hash output: ", hash_output, 32);

        // Allocate memory for the XOR result
        xor_result = malloc(sizeof(uint8_t) * rand_len);
        if (xor_result == NULL) {
            fprintf(stderr, "malloc failed\n");
            return LD_ERR_KM_MALLOC;
        }

        // Perform the XOR operation
        for (int i = 0; i < rand_len; i++) {
            xor_result[i] = hash_output[i] ^ rand[i];
        }

        /* 密钥派生 */
        printf("km_derive_masterkey_asgs inside***\n");

        pkg_kasgs = derive_key(handle_NH, MASTER_KEY_AS_GS, len_kasgs, as_name, gs_name, xor_result,
                               len_xor_res, handle_kasgs); // KAS-GS=KDF(NH,gs_name^N3)
        if (pkg_kasgs == NULL) {
            key_pkg_free(pkg_kasgs);
            pkg_kasgs = NULL;
            free(xor_result);
            printf("derive kasgs failed\n");
            return LD_ERR_KM_DERIVE_KEY;
        } else {
            // print_key_pkg(pkg_kasgs);
            store_key(db_name, table_name, pkg_kasgs, &km_pkg_desc); // AS端计算和存储与GS之间的主密钥
        }

    } while (0);

    key_pkg_free(pkg_kasgs);
    pkg_kasgs = NULL;
    free(xor_result);
    return LD_KM_OK;
}

// 外部接口 密钥派生
l_km_err
km_derive_key(uint8_t *db_name, uint8_t *table_name, uint8_t *id, uint32_t key_len, uint8_t *gs_name, uint8_t *rand,
              uint32_t rand_len) {
    struct KeyPkg *pkg = NULL;
    km_keypkg_t *pkg_NH = NULL;
    QueryResult_for_owner *qr_o = NULL;
    void *handle;
    void *handle_NH;
    l_km_err result = LD_ERR_KM_DERIVE_KEY;

    if (query_state(db_name, table_name, id) != ACTIVE) {
        log_warn("key state mismatch");
        return LD_ERR_KM_KEY_STATE;
    }

    if (get_handle_from_db(db_name, table_name, id, &handle) != LD_KM_OK) {
        log_warn("[** get_handle error**]\n");
        return LD_ERR_KM_GET_HANDLE;
    }

    qr_o = query_owner(db_name, table_name, id);
    if (qr_o == NULL || qr_o->owner1 == NULL || qr_o->owner2 == NULL) // 查询结果检查
    {
        log_warn("[** query_owner error**]\n");
        return LD_ERR_KM_QUERY;
    }

    const char *owner1 = qr_o->owner1;
    const char *owner2 = qr_o->owner2;


    switch (query_keytype(db_name, table_name, id)) {
        case ROOT_KEY: {
            do {
                pkg = derive_key(handle, MASTER_KEY_AS_SGW, key_len, owner1, owner2, rand, rand_len, NULL);
                if (pkg == NULL) {
                    log_warn("[**sgw derive_key kas-sgw error**]\n");
                    break;
                }
                // print_key_pkg(pkg);

                if (create_table_if_not_exist(&km_table_desc, db_name, table_name, "id", NULL, NULL, FALSE) !=
                    LD_KM_OK) {
                    break;
                }

                if (store_key(db_name, table_name, pkg, &km_pkg_desc) != LD_KM_OK) {
                    break;
                }

                // 派生中间密钥NH
                uint16_t len_kasgs = 16;
                pkg_NH = derive_key(handle, NH_KEY, len_kasgs, owner1, owner2, rand, rand_len, &handle_NH);
                if (pkg_NH == NULL) {
                    log_warn("[**AS derive_key NH error**]\n");
                    break;
                }

                if (store_key(db_name, table_name, pkg_NH, &km_pkg_desc) != LD_KM_OK) {
                    break;
                }

                // 派生会话密钥KAS-GS
                // log_warn("about to enter derive masterkeyasgs: dbname %s, tablename %s, id %s, asname: %s, gsname %s , handle_NH %p \n", db_name, table_name, id, owner1, (const char *)gs_name, handle_NH);
                if (km_derive_masterkey_asgs(db_name, table_name, handle_NH, key_len, owner1, (const char *) gs_name,
                                             rand, rand_len,
                                             NULL) != LD_KM_OK) {
                    printf("[**AS derive master KAS-GS failed]\n");
                    break;
                }

                // 成功完成所有操作
                result = LD_KM_OK;
            } while (0);

            break;
        }
        case MASTER_KEY_AS_GS:
            do {
                if (km_derive_all_session_key(db_name, table_name, handle, key_len, qr_o->owner1, qr_o->owner2, rand,
                                              rand_len) != LD_KM_OK) {
                    log_warn("session key derive failed\n");
                    break;
                }

                // 成功完成所有操作
                result = LD_KM_OK;
            } while (0);
            break;

        default:
            log_warn("unexpected key type\n");
            break;
    }

    // 确保释放资源
    if (pkg != NULL) {
        key_pkg_free(pkg);
        pkg = NULL;
    }
    if (pkg_NH != NULL) {
        key_pkg_free(pkg_NH);
        pkg_NH = NULL;
    }
    free_owner_result(qr_o);

    return result;
}

// 获取密钥句柄
l_km_err km_get_key_handle(struct KeyPkg *pkg, void **key_handle) {
    void *DeviceHandle, *hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    // 导入密钥加密密钥
    uint32_t kek_index = 1;
    void *kek_handle;
    int ret;
    ret = SDF_ImportKeyWithKEK(hSessionHandle, ALGO_WITH_KEK, kek_index, pkg->kek_cipher, pkg->kek_cipher_len,
                               &kek_handle);
    if (ret != LD_KM_OK) {
        log_warn("get key handle : import kek failed!\n");
        return LD_ERR_KM_IMPORT_KEY_WITH_KEK;
    }

    // 校验完整性
    uint32_t chck_len;      // 校验值长度
    uint8_t chck_value[32]; // 长度为chck_len的校验值
    // //printbuff("iv", pkg->iv, pkg->iv_len);
    uint8_t iv_mac[16];
    uint8_t iv_dec[16];
    memcpy(iv_mac, pkg->iv, 16);
    memcpy(iv_dec, pkg->iv, 16);
    ret = SDF_CalculateMAC(hSessionHandle, kek_handle, ALGO_MAC, iv_mac, pkg->key_cipher, pkg->meta_data->length,
                           chck_value, &chck_len);
    // //printbuff("chck", chck_value,chck_len);
    if (ret != LD_KM_OK) // 计算mac失败
    {
        log_warn("get key handle: calc km_mac failed!\n");
        return LD_ERR_KM_MAC;
    }
    if (memcmp(pkg->chck_value, chck_value, chck_len) != 0) // 密钥校验不通过
    {
        log_warn("get key handle: key verify failed!\n");
        // printbuff("chck_value", chck_value, 32);
        return LD_ERR_KM_MASTERKEY_VERIFY;
    }

    // 解密密钥
    uint8_t key[64];
    uint32_t key_len;
    ret = SDF_Decrypt(hSessionHandle, kek_handle, ALGO_ENC_AND_DEC, iv_dec, pkg->key_cipher, pkg->meta_data->length,
                      key, &key_len);
    if (ret != LD_KM_OK) {
        log_warn("get masterkey handle: km_decrypt failed!\n");
        return LD_ERR_KM_DECRYPT;
    }

    // 导入密钥
    key_len = key_len > 16 ? 16 : key_len;
    ret = SDF_ImportKey(hSessionHandle, key, key_len, key_handle);
    if (ret != LD_KM_OK) {
        log_warn("get masterkey handle: import masterkey failed!\n");
        return LD_ERR_KM_IMPORT_KEY;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_KM_OK;
}

/************
 * 密钥使用 *
 ***********/

/**
 * @brief 获取密钥句柄
 * @param[in] db_name
 * @param[in] table_name
 * @param[in] id 密钥id
 * @param[out] handle 密钥句柄
 * @return 是否执行成功
 */
l_km_err get_handle_from_db(uint8_t *db_name, uint8_t *table_name, uint8_t *id, void **key_handle) {
    // 查询密钥明文
    QueryResult_for_keyvalue *result = query_keyvalue(db_name, table_name, id);
    if (result->key == NULL) {
        log_warn("Key not found or error occurred.\n");
        return LD_ERR_KM_QUERY;
    }

    // 导入密钥，获得句柄
    if (km_import_key(result->key, result->key_len, key_handle) != LD_KM_OK) {
        log_warn("%s\n", km_error_to_string(LD_ERR_KM_IMPORT_KEY));
        return LD_ERR_KM_IMPORT_KEY;
    }

    // 释放空间
    free_keyvalue_result(result);
    return LD_KM_OK;
}

/************
 * 密钥更新 *
 ***********/

/**
 * @brief AS端 SGW更新会话密钥
 */
l_km_err km_update_sessionkey(uint8_t *dbname, uint8_t *tablename, uint8_t *id_mk, uint8_t *as_name, uint8_t *gs_t_name,
                              uint32_t nonce_len, uint8_t *nonce) {
    void *handle_mk;
    // 查询主密钥句柄
    if (get_handle_from_db(dbname, tablename, id_mk, &handle_mk) != LD_KM_OK) {
        log_warn("get_handle_from_db failed\n");
        return LD_ERR_KM_DERIVE_SESSION_KEY;
    }

    // 派生会话密钥
    enum KEY_TYPE key_types[4];
    key_types[0] = SESSION_KEY_USR_ENC;
    key_types[1] = SESSION_KEY_USR_INT;
    key_types[2] = SESSION_KEY_CONTROL_ENC;
    key_types[3] = SESSION_KEY_CONTROL_INT;
    uint32_t sessionkey_len = 16;
    for (int i = 0; i <= 3; i++) {
        do {

            // 生成新密钥
            km_keypkg_t *pkg;
            pkg = derive_key(handle_mk, key_types[i], sessionkey_len, as_name, gs_t_name, nonce,
                             nonce_len, NULL);
            if (pkg == NULL) {
                log_warn("dervie key failed\n");
                break;
            }
            // log_warn("dervie key OK\n");

            // 存储新密钥
            if (store_key(dbname, tablename, pkg, &km_pkg_desc) != LD_KM_OK) {
                log_warn("store_key failed.\n");
                key_pkg_free(pkg); // 释放已分配的内存
                pkg = NULL;
                break;
            }
            // log_warn("store_key OK.\n");

            key_pkg_free(pkg); // 释放变量空间
            pkg = NULL;

        } while (0);
    }

    free(handle_mk);

    return LD_KM_OK;
}

/**
 * @brief 网关和AS端更新主密钥 KAS-GS
 */
l_km_err
km_update_masterkey(uint8_t *dbname, uint8_t *tablename, uint8_t *key_id, uint8_t *sgw_name, uint8_t *gs_s_name,
                    uint8_t *gs_t_name,
                    uint8_t *as_name, uint16_t len_nonce, uint8_t *nonce) {
    bool fail_tag = FALSE;
    QueryResult_for_queryid *qr_NH = NULL;
    QueryResult_for_keyvalue *query_NH = NULL;
    QueryResult_for_queryid *qr_assgw = NULL;
    QueryResult_for_subkey *qr_s = NULL;
    QueryResult_for_queryid *qr_mk = NULL;
    QueryResult_for_queryid *qr_nmk = NULL;
    km_keypkg_t *keypkg_NH; // 更新的NH
    km_keypkg_t *keypkg_Kasgs = NULL;
    void *handle_NH;
    void *handle_asasw;

    uint8_t *rand = malloc(sizeof(uint8_t) * 32);
    uint32_t rand_len;

    do {

        // 如果不存在 则创建表
        uint8_t *primary_key = "id";
        if (create_table_if_not_exist(&km_table_desc, dbname, tablename, primary_key, NULL, NULL, FALSE) !=
            LD_KM_OK) {
            log_warn("create table err\n");
            fail_tag = TRUE;
            break;
        }

        // 查询待更新密钥kas-gs信息
        uint32_t mk_len = query_keylen(dbname, tablename, key_id);
        if (mk_len <= 0) {
            log_warn("Query mk len failed.\n");
            fail_tag = TRUE;
            break;
        }
        // log_warn("Query mk info OK.%d\n", mk_len);

        // 查询NH密钥id
        qr_NH = query_id(dbname, tablename, as_name, sgw_name, NH_KEY, ACTIVE);
        if (qr_NH->count == 0) {
            log_warn("Query id_NH failed, null outcome.\n");
            fail_tag = TRUE;
            break;
        } else if (qr_NH->count > 1) // TODO: check ununique id
        {
            log_warn("Query id_NH failed, duplicate outcome.\n");
            fail_tag = TRUE;
            break;
        }
        // log_warn("Query id_NH OK,id:%s.\n", qr_NH->ids[0]);

        // 查询NH密钥值
        query_NH = query_keyvalue(dbname, tablename, qr_NH->ids[0]);
        if (!query_NH) {
            log_warn("Key NH value not found or error occurred.\n");
            fail_tag = TRUE;
            break;
        }
        // //printbuff("query_NH->key", query_NH->key, query_NH->key_len);
        // log_warn("Query NH info OK.\n");

        // 计算新的NH密钥值 : NH = kdf(kas-sgw,NH')
        /*计算新的NH密钥值 : NH = kdf(kas-sgw,NH')*/

        // 查询主密钥Kas-sgw的id
        qr_assgw = query_id(dbname, tablename, as_name, sgw_name, MASTER_KEY_AS_SGW,
                            ACTIVE); // AS端
        if (qr_assgw == NULL) {
            log_warn("Query kassgw failed.\n");
            fail_tag = TRUE;
            break;
        }
        // log_warn("qr_assgw OK. kid_assgw = %s\n", qr_assgw->ids[0]);

        // 获取主密钥Kas-sgw句柄
        if (get_handle_from_db(dbname, tablename, qr_assgw->ids[0], &handle_asasw) != LD_KM_OK) {
            log_warn("get_handle_from_db failed\n");
            fail_tag = TRUE;
            break;
        }
        // log_warn("get kas-sgw handle_from_db OK\n");

        // 重新计算NH
        keypkg_NH = derive_key(handle_asasw, NH_KEY, query_NH->key_len, as_name, sgw_name, query_NH->key,
                               query_NH->key_len, NULL);
        if (keypkg_NH == NULL) {
            log_warn("derive keypkg_NH failed\n");
            fail_tag = TRUE;
            break;
        }
        // log_warn("derive keypkg_NH OK\n");

        // 存储NH密钥值
        if (store_key(dbname, tablename, keypkg_NH, &km_pkg_desc) != LD_KM_OK) {
            log_warn("store_key failed.\n");
            fail_tag = TRUE;
            break;
        }
        // log_warn("store NH keyvalue OK\n");

        // 撤销原NH密钥
        if (alter_keystate(dbname, tablename, qr_NH->ids[0], SUSPENDED) != LD_KM_OK) {
            log_warn("alter keystate failed\n");
            fail_tag = TRUE;
            break;
        }

        // AS-SGW 更新计数器自增
        if (increase_updatecount(dbname, tablename, qr_assgw->ids[0]) != LD_KM_OK) {
            log_warn("increase update count failed\n");
            fail_tag = TRUE;
            break;
        }
        // log_warn("increase update count OK\n");

        /* 生成 kas-gs = kdf(NH, rand)*/
        if (km_hmac(nonce, len_nonce, gs_t_name, strlen(gs_t_name), rand, &rand_len) !=
            LD_KM_OK) // rand = hmac(sacgs-t,nonce)
        {
            log_warn("km_hmac failed\n");
            fail_tag = TRUE;
            break;
        }
        // log_warn("km hmac OK\n");

        if (get_handle_from_db(dbname, tablename, qr_NH->ids[0], &handle_NH) != LD_KM_OK) {
            log_warn("get keyhandle from db failed\n");
            fail_tag = TRUE;
            break;
        }
        // log_warn("get handle from db OK\n");
        // log_warn("%p \n", handle_NH);

        keypkg_Kasgs = derive_key(handle_NH, MASTER_KEY_AS_GS, mk_len, as_name, gs_t_name, rand,
                                  rand_len,
                                  NULL);
        if (keypkg_Kasgs == NULL) {
            log_warn("kasgs derive failed\n");
            fail_tag = TRUE;
            break;
        }
        // log_warn("kasgs derive OK\n");

        // 存储更新的主密钥kas-gs
        if (store_key(dbname, tablename, keypkg_Kasgs, &km_pkg_desc) != LD_KM_OK) {
            log_warn("store_key failed.\n");
            fail_tag = TRUE;
            break;
        }
        // log_warn("store master key OK.\n");

        // 将原密钥的状态改为已经撤销
        if (km_revoke_key(dbname, tablename, key_id) != LD_KM_OK) {
            log_warn("km_revoke_key failed\n");
            fail_tag = TRUE;
            break;
        }

        // 查询新的kAS-GS id
        qr_nmk = query_id(dbname, tablename, as_name, gs_t_name, MASTER_KEY_AS_GS, ACTIVE);
        if (qr_nmk->count == 0) {
            log_warn("Query new mkid failed, null kas-gs id.\n");
            fail_tag = TRUE;
            break;
        } else if (qr_nmk->count > 1) // TODO: check ununique id
        {
            log_warn("Query new mkid failed,kas-gs id is not unique.\n");
            fail_tag = TRUE;
            break;
        }
        // log_warn("Query mkid OK,id:%s.\n", qr_nmk->ids[0]);

        // 如果有子会话密钥
        qr_s = query_subkey(dbname, tablename, key_id);
        if (qr_s->count == 4) {
            // 会话密钥更新
            if (km_update_sessionkey(dbname, tablename, qr_nmk->ids[0], as_name, gs_t_name, len_nonce, nonce) !=
                LD_KM_OK) {
                log_warn("update masterkey %s's sessionkey failed\n", qr_nmk->ids[0]);
                fail_tag = TRUE;
                break;
            }
            // log_warn("update masterkey %s's sessionkey OK\n", qr_nmk->ids[0]);
        }

    } while (0);

    // 释放动态分配的内存
    free_queryid_result(qr_mk);
    free_queryid_result(qr_nmk);
    free_queryid_result(qr_NH);
    free_keyvalue_result(query_NH);
    free_queryid_result(qr_assgw);
    key_pkg_free(keypkg_NH);
    key_pkg_free(keypkg_Kasgs);
    keypkg_Kasgs = NULL;
    free(handle_NH);
    free(handle_asasw);
    free(rand);
    free_query_result_for_subkey(qr_s);

    return LD_KM_OK;
}

/** @brief 外部接口：网关端更新主密钥 KAS-GS */
l_km_err
sgw_update_master_key(uint8_t *dbname, uint8_t *tablename, uint8_t *key_id, uint8_t *sgw_name, uint8_t *gs_t_name,
                      uint16_t len_nonce, uint8_t *nonce) {
    // 根据id 查询sgw name 和 as_name
    QueryResult_for_owner *qo = NULL;
    bool fail_tag = FALSE;
    do {
        qo = query_owner(dbname, tablename, key_id);
        if (qo->owner1 == NULL || qo->owner2 == NULL) {
            log_warn("query_owner failed\n");
            fail_tag = TRUE;
            break;
        }
        // log_warn("owner1: %s, owner2: %s\n", qo->owner1, qo->owner2);

        if (km_update_masterkey(dbname, tablename, key_id, sgw_name, qo->owner2, gs_t_name, qo->owner1, len_nonce,
                                nonce) !=
            LD_KM_OK) {
            fail_tag = TRUE;
            break;
        }
    } while (0);

    // 释放变量空间
    free_owner_result(qo);
    qo = NULL;

    // 返回执行情况
    return fail_tag == FALSE ? LD_KM_OK : LD_ERR_KM_SGW_MK_UPDATE;
}

/**
 * @brief 撤销密钥及其派生密钥
 */
l_km_err km_revoke_key(uint8_t *dbname, uint8_t *tablename, uint8_t *id) {
    bool fail_tag = FALSE;
    QueryResult_for_subkey *result = NULL;

    do {
        // 检查密钥状态
        enum STATE state = query_state(dbname, tablename, id);
        // log_warn("dbname %s tablename %s key-id %s state: %s \n", dbname, tablename, id, kstate_str(state));
        if (state != ACTIVE && state != PRE_ACTIVATION) {
            log_warn("key state mismatch\n");
            fail_tag = TRUE;
            break;
        }

        // 查询子密钥
        result = query_subkey(dbname, tablename, id);
        if (result != NULL) {
            for (int i = 0; i < result->count; ++i) // 撤销子密钥
            {
                if (alter_keystate(dbname, tablename, result->subkey_ids[i], SUSPENDED) != LD_KM_OK) // 修改密钥状态
                {
                    log_warn("revoke subkey %s fail\n", result->subkey_ids[i]);
                    fail_tag = TRUE;
                    break;
                }
                // log_warn("revoke key %s succeeded.\n", result->subkey_ids[i]);

                // 删除密钥值
                if (alter_keyvalue(dbname, tablename, result->subkey_ids[i], 0, NULL) != LD_KM_OK) {
                    log_warn("revoke key %s Failed. \n", result->subkey_ids[i]);
                    fail_tag = TRUE;
                    break;
                }
            }
        }

        // 撤销密钥
        if (alter_keystate(dbname, tablename, id, SUSPENDED) != LD_KM_OK) {
            log_warn("revoke key %s fail\n", id);
            fail_tag = TRUE;
            break;
        }
        // log_warn("revoke key %s succeeded.\n", id_mk);

        // 删除密钥值
        if (alter_keyvalue(dbname, tablename, id, 0, NULL) != LD_KM_OK) {
            log_warn("revoke key %s Failed. \n", id);
            fail_tag = TRUE;
            break;
        }

        // 将密钥加入密钥撤销列表

    } while (0);

    // 释放查询结果
    free_query_result_for_subkey(result);
    result = NULL;

    if (fail_tag == FALSE) // 修改这里为相等比较
    {
        return LD_KM_OK;
    } else {
        return LD_ERR_REVOKE_KEY;
    }
}

/**
 * @brief GS端安装主密钥 派生会话密钥
 */
l_km_err
km_install_key(uint8_t *dbname, uint8_t *tablename, uint32_t key_len, uint8_t *key, uint8_t *as_name, uint8_t *gs_name,
               uint32_t nonce_len, uint8_t *nonce) {
    bool fail_tag = FALSE;
    km_keymetadata_t *md = NULL;
    km_keypkg_t *pkg = NULL;
    QueryResult_for_queryid *qr_mk = NULL;
    do {
        // 如果不存在，先创建密钥表
        uint8_t *primary_key = "id";
        if (create_table_if_not_exist(&km_table_desc, dbname, tablename, primary_key, NULL, NULL, FALSE) !=
            LD_KM_OK) {
            log_warn("create table err\n");
            fail_tag = TRUE;
            break;
        }

        // 生成密钥描述信息
        uint32_t update_cycle = 365;
        md = km_key_metadata_new(as_name, gs_name, MASTER_KEY_AS_GS, key_len,
                                 update_cycle); // TODO: 更新周期待确定
        pkg = km_key_pkg_new(md, key, TRUE);
        pkg->meta_data->state = ACTIVE;

        // 存入数据库
        if (store_key(dbname, tablename, pkg, &km_pkg_desc) != LD_KM_OK) {
            log_warn("store_key failed: %d\n");
            fail_tag = TRUE;

            break;
        }

        // 查询主密钥id
        qr_mk = query_id(dbname, tablename, as_name, gs_name, MASTER_KEY_AS_GS, ACTIVE);
        if (qr_mk == NULL) {
            log_warn("NULL Query.\n");
            fail_tag = TRUE;

            break;
        }
        // log_warn("kas-gs id %s\n", qr_mk->ids[0]);

        // 查询主密钥句柄
        void *handle_mk;
        if (get_handle_from_db(dbname, tablename, qr_mk->ids[0], &handle_mk) != LD_KM_OK) {
            log_warn("get_handle_from_db failed\n");
            fail_tag = TRUE;

            break;
        }

        // 测试主密钥句柄是否相同

        // //printbuff("GS INSTALL：hmac test mkhandle", hmac_value, hmac_len);

        // 派生会话密钥
        enum KEY_TYPE key_types[4];
        key_types[0] = SESSION_KEY_USR_ENC;
        key_types[1] = SESSION_KEY_USR_INT;
        key_types[2] = SESSION_KEY_CONTROL_ENC;
        key_types[3] = SESSION_KEY_CONTROL_INT;

        uint32_t sessionkey_len = 16;
        for (int i = 0; i <= 3; i++) {
            // 在新分配之前释放旧的 pkg
            if (pkg != NULL) {
                key_pkg_free(pkg); // 释放之前的 pkg
                pkg = NULL;        // 设置为 NULL，避免悬空指针
            }

            pkg = derive_key(handle_mk, key_types[i], sessionkey_len, as_name, gs_name, nonce, nonce_len, NULL);
            if (pkg == NULL) {
                log_warn("dervie key failed\n");
                fail_tag = TRUE;
                break;
            }
            if (store_key(dbname, tablename, pkg, &km_pkg_desc) != LD_KM_OK) {
                log_warn("store_key failed: %d\n");
                fail_tag = TRUE;
                break;
            }
        }

    } while (0);

    // 释放变量空间
    key_meta_data_free(md);
    if (pkg != NULL) {
        key_pkg_free(pkg);
        pkg = NULL;
    }
    if (qr_mk != NULL) {
        free_queryid_result(qr_mk);
        qr_mk = NULL;
    }

    return (fail_tag == FALSE) ? LD_KM_OK : LD_ERR_KM_INSTALL_KEY;
}

/************
 * 密钥存储 *
 ************/

// 将keypkg写入文件
l_km_err write_keypkg_to_file(const char *filename, km_keypkg_t *pkg) {
    do {
        FILE *file = fopen(filename, "w");
        if (file == NULL) {
            log_warn("open file %s failed.\n", filename);
            return LD_ERR_KM_WRITE_FILE;
        }

        // Write metadata
        if (fwrite(pkg->meta_data, sizeof(km_keymetadata_t), 1, file) != 1) {
            log_warn("write metadata failed.\n");
            fclose(file);
            return LD_ERR_KM_PARAMETERS_NULL;
        }

        fwrite(pkg->kek_cipher, sizeof(uint8_t), MAX_KEK_CIPHER_LEN, file); // write kek
        fwrite(&pkg->kek_cipher_len, sizeof(uint32_t), 1, file);
        fwrite(pkg->key_cipher, sizeof(uint8_t), MAX_KEY_CIPHER_LEN, file); // Write key
        // write iv
        fwrite(&pkg->iv_len, sizeof(uint16_t), 1, file);
        fwrite(pkg->iv, sizeof(uint8_t), MAX_IV_LEN, file);
        // write chck
        fwrite(&pkg->chck_alg, sizeof(uint16_t), 1, file);
        fwrite(&pkg->chck_len, sizeof(uint32_t), 1, file);
        fwrite(pkg->chck_value, sizeof(uint8_t), MAX_CHCK_LEN, file);

        fclose(file);

        return LD_KM_OK;

    } while (0);
}

// 从文件读取出keypkg
km_keypkg_t *read_keypkg_from_file(const char *filename) {
    // 参数检查
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        return NULL;
    }

    // Read metadata
    km_keymetadata_t *meta_data = malloc(sizeof(km_keymetadata_t));
    if (meta_data == NULL) {
        fclose(file);
        return NULL;
    }
    if (fread(meta_data, sizeof(km_keymetadata_t), 1, file) != 1) {
        free(meta_data);
        fclose(file);
        return NULL;
    }

    km_keypkg_t *pkg = km_key_pkg_new(meta_data, NULL, FALSE);
    // Check if km_key_pkg_new succeeded
    if (pkg == NULL) {
        free(meta_data);
        fclose(file);
        return NULL;
    }

    fread(pkg->kek_cipher, sizeof(uint8_t), MAX_KEK_CIPHER_LEN, file); // read kek
    fread(&pkg->kek_cipher_len, sizeof(uint32_t), 1, file);
    fread(pkg->key_cipher, sizeof(uint8_t), MAX_KEY_CIPHER_LEN, file); // Read key
    // Read iv
    fread(&pkg->iv_len, sizeof(uint16_t), 1, file);
    fread(pkg->iv, sizeof(uint8_t), MAX_IV_LEN, file);
    // Read chck
    fread(&pkg->chck_alg, sizeof(uint16_t), 1, file);
    fread(&pkg->chck_len, sizeof(uint32_t), 1, file);
    fread(pkg->chck_value, sizeof(uint8_t), MAX_CHCK_LEN, file);

    // 校验密钥
    // if (km_checkvalue_is_same(pkg->chck_alg, pkg->chck_value, pkg->chck_len,NULL,  pkg->key_cipher, pkg->meta_data->length) != TRUE)
    // {
    //     log_warn("integrity check failed!\n");
    //     free(pkg);
    //     free(meta_data);
    //     return NULL;
    // }

    // 关闭文件
    fclose(file);
    free(meta_data);

    // Note: Depending on the implementation of km_key_pkg_new,
    // you might need to free meta_data in the error case only
    return pkg;
}

/*********************************************************
 *                     输出格式控制                      *
 ********************************************************/
// Function to convert error code to string
const char *km_error_to_string(l_km_err err_code) {
    switch (err_code) {
        case LD_KM_OK:
            return "No error";
        case LD_ERR_KM_OPEN_DEVICE:
            return "Failed to open password device";
        case LD_ERR_KM_OPEN_SESSION:
            return "Failed to establish session with device";
        case LD_ERR_KM_OPEN_DB:
            return "Failed to open database";
        case LD_ERR_KM_EXE_DB:
            return "Failed to execute SQL statement";
        case LD_ERR_KM_MALLOC:
            return "Memory allocation failed";
        case LD_ERR_KM_GENERATE_RANDOM:
            return "Failed to generate random number";
        case LD_ERR_KM_HashInit:
            return "Failed to initialize hash";
        case LD_ERR_KM_HashUpdate:
            return "Failed to update hash";
        case LD_ERR_KM_HashFinal:
            return "Failed to finalize hash";
        case LD_ERR_KM_MAC:
            return "MAC interface failed to run";
        case LD_ERR_KM_ENCRYPT:
            return "Encryption failed";
        case LD_ERR_KM_DECRYPT:
            return "Decryption failed";
        case LD_ERR_KM_HMAC:
            return "HMAC failed";
        case LD_ERR_KM_PARAMETERS_ERR:
            return "PBKDF2 parameter error";
        case LD_ERR_KM_PARAMETERS_NULL:
            return "Interface parameter is NULL";
        case LD_ERR_KM_MEMORY_ALLOCATION_IN_PBKDF2:
            return "Memory allocation error in PBKDF2";
        case LD_ERR_KM_GENERATE_KEY_WITH_KEK:
            return "Failed to generate key with KEK encryption";
        case LD_ERR_KM_GENERATE_KEK:
            return "Failed to generate KEK";
        case LD_ERR_KM_EXPORT_KEK:
            return "Failed to export KEK";
        case LD_ERR_KM_IMPORT_KEY_WITH_KEK:
            return "Failed to import ciphertext key with KEK";
        case LD_ERR_KM_IMPORT_KEY:
            return "Failed to import plaintext key";
        case LD_ERR_KM_DESTROY_KEY:
            return "Failed to destroy key";
        case LD_ERR_KM_PBKDF2:
            return "Error executing PBKDF2";
        case LD_ERR_KM_EXTERNAL_IMPORT_KEK:
            return "External KEK import error";
        case LD_ERR_KM_WRITE_FILE:
            return "Error writing KEKPKG to file";
        case LD_ERR_KM_READ_FILE:
            return "Error reading KEKPKG from file";
        case LD_ERR_KM_OPEN_FILE:
            return "Error opening file";
        case LD_ERR_KM_CREATE_FILE:
            return "Error creating file";
        case LD_ERR_KM_DELETE_FILE:
            return "Error deleting file";
        case LD_ERR_KM_KEY_VERIFY:
            return "key verification error";
        case LD_ERR_KM_MASTERKEY_VERIFY:
            return "Master key verification error";
        case LD_ERR_KM_DERIVE_KEY:
            return "Key derivation error";
        case LD_ERR_KM_DERIVE_SESSION_KEY:
            return "Session key derivation error";
        case LD_ERR_KM_CREATE_DB:
            return "Error creating database or table";
        case LD_ERR_KM_QUERY:
            return "Database query error";
        case LD_ERR_KM_ALTERDB:
            return "Database modification error";
        case LD_ERR_KM_GET_HANDLE:
            return "Error obtaining key handle";
        case LD_ERR_KM_UPDATE_SESSIONKEY:
            return "Error updating session key";
        case LD_ERR_KM_INSTALL_KEY:
            return "Error installing key";
        default:
            return "Unknown error code";
    }
}

// 逐行打印密钥信息结构体
l_km_err print_key_metadata(struct KeyMetaData *key_info) {
    char str[128];
    uuid_unparse(key_info->id, str);
    // 使用 snprintf 格式化输出
    char str_buffer[1024]; // 预留足够的空间，包括格式字符串和 ID 的内容
    snprintf(str_buffer, sizeof(str_buffer), "ID:%s\n", str);
    log_warn("%s", str_buffer); // 输出结果

    log_warn("Type: ");

    switch (key_info->key_type) {
        case ROOT_KEY:
            log_warn("ROOT_KEY (KAS)\n");
            break;
        case MASTER_KEY_AS_SGW:
            log_warn("MASTER_KEY_AS_SGW (KASSGW)\n");
            break;
        case MASTER_KEY_AS_GS:
            log_warn("MASTER_KEY_AS_GS (KASGS)\n");
            break;
        case SESSION_KEY_USR_ENC:
            log_warn("SESSION_KEY_USR_ENC (KUENC)\n");
            break;
        case SESSION_KEY_USR_INT:
            log_warn("SESSION_KEY_USR_INT (KUINT)\n");
            break;
            //    case SESSION_KEY_CONTROL_ENC:
            //        log_warn("SESSION_KEY_CONTROL_ENC (KCENC)\n");
            //        break;
            //    case SESSION_KEY_CONTROL_INT:
            //        log_warn("SESSION_KEY_CONTROL_INT (KCINT)\n");
            //        break;
        case GROUP_KEY_BC:
            log_warn("GROUP_KEY_BC (KBC)\n");
            break;
        case GROUP_KEY_CC:
            log_warn("GROUP_KEY_CC (KCC)\n");
            break;
        case NH_KEY:
            log_warn("NextHop KEY\n");
            break;
        default:
            log_warn("Unknown KEY_TYPE\n");
    }

    uint8_t emptyArray[MAX_OWENER_LEN] = {0};
    if (memcmp(key_info->owner_1, emptyArray, MAX_OWENER_LEN) == 0) {
        log_warn("Owner 1 : nil (Unspecified)\n");
    } else {
        log_warn("Owner 1: %s\n", key_info->owner_1);
    }
    if (memcmp(key_info->owner_2, emptyArray, MAX_OWENER_LEN) == 0) {
        log_warn("Owner 2 : nil (Unspecified)\n");
    } else {
        log_warn("Owner 2: %s\n", key_info->owner_2);
    }
    log_warn("Length: %u BYTES\n", key_info->length);

    log_warn("State: ");
    switch (key_info->state) {
        case PRE_ACTIVATION:
            log_warn("PRE_ACTIVATION\n");
            break;
        case ACTIVE:
            log_warn("ACTIVE\n");
            break;
        case SUSPENDED:
            log_warn("SUSPENDED\n");
            break;
        case DEACTIVATED:
            log_warn("DEACTIVATED\n");
            break;
        case COMPROMISED:
            log_warn("COMPROMISED\n");
            break;
        case DESTROYED:
            log_warn("DESTROYED\n");
            break;
        default:
            log_warn("Unknown\n");
    }
    struct tm *timeinfo = localtime(&key_info->creation_time);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    log_warn("Effectuation Time: %s\n", buffer);
    log_warn("Update Cycle: %lld days \n", (long long) key_info->update_cycle);

    return LD_KM_OK;
}

// 逐行打印key_pkg结构体
l_km_err print_key_pkg(struct KeyPkg *key_pkg) {
    if (key_pkg == NULL) {
        // 处理错误，输入参数为空或者关键结构体为空
        log_warn("NULL key_pkg  for //print_key_pkg function.\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    } else if (key_pkg->meta_data == NULL) {
        // 处理错误，输入参数为空或者关键结构体为空
        log_warn("NULL meta_data for //print_key_pkg function.\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    }

//    print_key_metadata(key_pkg->meta_data);
    uint8_t emptyArray[64] = {0};
    if (memcmp(key_pkg->kek_cipher, emptyArray, 16) == 0) {
        log_warn("KEK: nil (Unspecified)\n");
    } else {
        log_buf(LOG_WARN, "KEK (cipher)", key_pkg->kek_cipher, 16);
    }
    log_buf(LOG_WARN, "Key ", key_pkg->key_cipher, key_pkg->meta_data->length);
    log_warn("Check Algorithm: %s\n", chck_algo_str(key_pkg->chck_alg));
    log_buf(LOG_WARN, "IV", key_pkg->iv, key_pkg->iv_len);
    log_buf(LOG_WARN, "Check value", key_pkg->chck_value, key_pkg->chck_len);

    return LD_KM_OK;
}

/**
 * 输入枚举类型的密钥类型 返回对应的字符串
 * @param[in] type 密钥类型
 * @return 密钥类型对应的字符串
 */
uint8_t *ktype_str(enum KEY_TYPE type) {
    switch (type) // 判断结构体中密钥类型
    {
        case ROOT_KEY:
            return ("ROOT_KEY");
            break;
        case MASTER_KEY_AS_SGW:
            return ("MASTER_KEY_AS_SGW");
            break;
        case MASTER_KEY_AS_GS:
            return ("MASTER_KEY_AS_GS");
            break;
        case SESSION_KEY_USR_ENC:
            return ("SESSION_KEY_USR_ENC");
            break;
        case SESSION_KEY_USR_INT:
            return ("SESSION_KEY_USR_INT");
            break;
        case SESSION_KEY_CONTROL_ENC:
            return ("SESSION_KEY_CONTROL_ENC");
            break;
        case SESSION_KEY_CONTROL_INT:
            return ("SESSION_KEY_CONTROL_INT");
            break;
        case GROUP_KEY_BC:
            return ("GROUP_KEY_KBC");
            break;
        case GROUP_KEY_CC:
            return ("GROUP_KEY_KCC");
            break;
        case NH_KEY:
            return ("NH KEY");
            break;
        default:
            return ("Unknown KEY_TYPE");
    }
}

// 字符串转key_type
enum KEY_TYPE str_to_ktype(const char *str) {
    if (strcmp(str, "ROOT_KEY") == 0) {
        return ROOT_KEY;
    } else if (strcmp(str, "MASTER_KEY_AS_SGW") == 0) {
        return MASTER_KEY_AS_SGW;
    } else if (strcmp(str, "MASTER_KEY_AS_GS") == 0) {
        return MASTER_KEY_AS_GS;
    } else if (strcmp(str, "SESSION_KEY_USR_ENC") == 0) {
        return SESSION_KEY_USR_ENC;
    } else if (strcmp(str, "SESSION_KEY_USR_INT") == 0) {
        return SESSION_KEY_USR_INT;
    } else if (strcmp(str, "SESSION_KEY_CONTROL_ENC") == 0) {
        return SESSION_KEY_CONTROL_ENC;
    } else if (strcmp(str, "SESSION_KEY_CONTROL_INT") == 0) {
        return SESSION_KEY_CONTROL_INT;
    } else if (strcmp(str, "GROUP_KEY_KBC") == 0) {
        return GROUP_KEY_BC;
    } else if (strcmp(str, "GROUP_KEY_KCC") == 0) {
        return GROUP_KEY_CC;
    } else if (strcmp(str, "NH KEY") == 0) {
        return NH_KEY;
    }
}

/**
 * @brief 返回密钥状态 枚举转字符串
 * @param[in] state 密钥状态 枚举类型
 * @return 密钥状态字符串
 */
uint8_t *kstate_str(enum STATE state) {
    switch (state) {
        case PRE_ACTIVATION:
            return ("PRE_ACTIVATION");
            break;
        case ACTIVE:
            return ("ACTIVE");
            break;
        case SUSPENDED:
            return ("SUSPENDED");
            break;
        case DEACTIVATED:
            return ("DEACTIVATED");
            break;
        case COMPROMISED:
            return ("COMPROMISED");
            break;
        case DESTROYED:
            return ("DESTROYED");
            break;
        default:
            return ("Unknownn");
    }
}

// 将字符串转换为枚举类型的函数
enum STATE str_kstate(const uint8_t *state_str) {
    if (strcmp((const char *) state_str, "PRE_ACTIVATION") == 0) {
        return PRE_ACTIVATION;
    } else if (strcmp((const char *) state_str, "ACTIVE") == 0) {
        return ACTIVE;
    } else if (strcmp((const char *) state_str, "SUSPENDED") == 0) {
        return SUSPENDED;
    } else if (strcmp((const char *) state_str, "DEACTIVATED") == 0) {
        return DEACTIVATED;
    } else if (strcmp((const char *) state_str, "COMPROMISED") == 0) {
        return COMPROMISED;
    } else if (strcmp((const char *) state_str, "DESTROYED") == 0) {
        return DESTROYED;
    } else {
        return -1;
    }
}

/**
 * @brief 校验算法解析
 * @param[in] chck_algo 校验算法(int类型)
 * @return 校验算法
 */
uint8_t *chck_algo_str(uint16_t chck_algo) {
    switch (chck_algo) {
        case ALGO_ENC_AND_DEC:
            return ("SGD_SM4_CBC");
            break;
        case ALGO_MAC:
            return ("SGD_SM4_MAC");
            break;
        case ALGO_WITH_KEK:
            return ("SGD_SM4_ECB");
            break;
        case ALGO_HASH:
            return ("SGD_SM3");
            break;
        default:
            return ("unknown");
            break;
    }
}

static const char *algos[] = {
        "SGD_SM4_CFB",
};

/**
 * @brief 校验算法解析（逆功能）
 * @param[in] algo_str 校验算法字符串
 * @return 校验算法枚举类型
 */
int str_to_chck_algo(const char *algo_str) {
    if (strcmp(algo_str, "SGD_SM4_CFB") == 0) {
        return ALGO_ENC_AND_DEC;
    } else if (strcmp(algo_str, "SGD_SM4_MAC") == 0) {
        return ALGO_MAC;
    } else if (strcmp(algo_str, "SGD_SM4_ECB") == 0) {
        return ALGO_WITH_KEK;
    } else if (strcmp(algo_str, "SGD_SM3") == 0) {
        return ALGO_HASH;
    } else {
        return -1;
    }
}

/**
 * @brief 十六进制字符串转换回字节序列
 * @param[in] hex_str
 * @return 字节序列
 */
uint8_t *hex_to_bytes(const char *hex_str) {

    size_t len = strlen(hex_str);
    uint8_t *bytes = malloc(sizeof(uint8_t) * len / 2); // 原始字节数据的长度是字符串长度的一半
    for (size_t i = 0; i < len; i += 2) {
        sscanf(hex_str + i, "%2hhX", &bytes[i / 2]);
    }
    return bytes;
}

/**
 * @brief 字节序列转换为十六进制字符串
 * @param[in] bytes_len
 * @param[in] bytes
 * @return 十六进制串
 */
uint8_t *bytes_to_hex(uint16_t bytes_len, uint8_t *bytes) {
    if (!bytes) {
        return NULL;
    }

    uint8_t *hex_str;
    hex_str = malloc(sizeof(uint8_t) * (bytes_len * 2 + 1));
    if (!hex_str) {
        return NULL; // Handle malloc failure
    }

    for (int i = 0; i < bytes_len; i++) {
        snprintf((char *) (hex_str + i * 2), 3, "%02X", bytes[i]); // Use snprintf to prevent overflow
    }
    hex_str[bytes_len * 2] = '\0'; // Null terminate the string
    return hex_str;
}

/**结构体初始化和销毁释放*/

// 外部接口
km_keymetadata_t *
km_key_metadata_new(const char *owner_1, const char *owner_2, enum KEY_TYPE key_type, uint32_t key_len,
                    uint16_t update_day) {
    km_keymetadata_t *keydata = malloc(sizeof(km_keymetadata_t)); // 初始化分配空间
    if (keydata == NULL) {
        // 内存分配失败，返回 NULL
        return NULL;
    }

    uint8_t null_array[MAX_OWENER_LEN] = {0};
    memcpy(keydata->owner_1, null_array, MAX_OWENER_LEN);
    memcpy(keydata->owner_2, null_array, MAX_OWENER_LEN);

    uuid_t uuid;
    uuid_generate(uuid);
    uuid_copy(keydata->id, uuid);

    // 确保 owner_1 和 owner_2 不会超出缓冲区
    if (strlen(owner_1) >= MAX_OWENER_LEN || strlen(owner_2) >= MAX_OWENER_LEN) {
        free(keydata); // 释放已分配的内存
        return NULL;
    }

    strncpy(keydata->owner_1, owner_1, MAX_OWENER_LEN - 1);
    keydata->owner_1[MAX_OWENER_LEN - 1] = '\0'; // 确保字符串终止符
    strncpy(keydata->owner_2, owner_2, MAX_OWENER_LEN - 1);
    keydata->owner_2[MAX_OWENER_LEN - 1] = '\0'; // 确保字符串终止符

    keydata->key_type = key_type;
    keydata->length = key_len;
    keydata->state = PRE_ACTIVATION;
    keydata->update_cycle = update_day;
    time(&keydata->creation_time);

    return keydata;
}

void key_meta_data_free(km_keymetadata_t *meta_data) {
    // 如果 meta_data 为 NULL，则无需处理
    if (meta_data != NULL) {
        // 释放内存
        free(meta_data);
    }
}

// 外部接口
km_keypkg_t *km_key_pkg_new(km_keymetadata_t *meta, uint8_t *key, bool is_encrypt) {
    // 分配 km_keypkg_t 结构体的内存
    km_keypkg_t *keypkg = malloc(sizeof(km_keypkg_t));
    if (keypkg == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    memset(keypkg, '\0', sizeof(km_keypkg_t));

    // 分配并复制 meta 的副本
    keypkg->meta_data = (km_keymetadata_t *) malloc(sizeof(km_keymetadata_t));
    if (keypkg->meta_data == NULL) {
        free(keypkg); // 释放已经分配的内存
        fprintf(stderr, "Memory allocation for meta_data failed\n");
        return NULL;
    }
    memcpy(keypkg->meta_data, meta, sizeof(km_keymetadata_t));

    // 使用错误处理策略
    bool error_occurred = FALSE;

    if (key != NULL) { // 如果传入明文密钥，对其加密存储并存入控制信息
        if (is_encrypt) {
            uint32_t kek_index = 1;
            void *kek_handle;

            // 生成 KEK 存储kek
            if (km_generate_key_with_kek(kek_index, 16, &kek_handle, keypkg->kek_cipher, &keypkg->kek_cipher_len) !=
                LD_KM_OK) {
                fprintf(stderr, "Error in derive : SDF_GenerateKeyWithKEK failed!\n");
                error_occurred = TRUE;
            } else {
                // 生成和存储 IV
                keypkg->iv_len = 16;
                uint8_t iv_mac[16];
                uint8_t iv_enc[16];
                if (km_generate_random(keypkg->iv, keypkg->iv_len)) {
                    fprintf(stderr, "Error in generate IV!\n");
                    error_occurred = TRUE;
                } else {
                    memcpy(iv_mac, keypkg->iv, keypkg->iv_len);
                    memcpy(iv_enc, keypkg->iv, keypkg->iv_len);

                    // 密钥加密存储
                    uint32_t cipher_len;
                    if (km_encrypt(kek_handle, ALGO_ENC_AND_DEC, iv_enc, key, meta->length, keypkg->key_cipher,
                                   &cipher_len)) {
                        fprintf(stderr, "Error in derive : SDF_Encrypt failed!\n");
                        error_occurred = TRUE;
                    } else {
                        // 对明文密钥生成校验值
                        if (km_mac(kek_handle, ALGO_MAC, iv_mac, key, meta->length, keypkg->chck_value,
                                   &keypkg->chck_len)) {
                            fprintf(stderr, "Error in derive : SDF_CalculateMAC failed!\n");
                            error_occurred = TRUE;
                        } else // 存储校验算法
                        {
                            keypkg->chck_alg = ALGO_MAC;
                        }
                    }
                }
            }
        } else {
            uint32_t kek_index = 1;
            void *kek_handle;
            memset(keypkg->kek_cipher, 0, 16);
            keypkg->kek_cipher_len = 0;

            // 生成和存储 IV
            keypkg->iv_len = 16;
            uint8_t iv_mac[16];
            uint8_t iv_enc[16];
            if (km_generate_random(keypkg->iv, keypkg->iv_len)) {
                fprintf(stderr, "Error in generate IV!\n");
                error_occurred = TRUE;
            } else {
                memcpy(iv_mac, keypkg->iv, keypkg->iv_len);
                memcpy(iv_enc, keypkg->iv, keypkg->iv_len);

                // 存储密钥密文
                memcpy(keypkg->key_cipher, key, keypkg->meta_data->length);

                // 生成校验值
                if (km_hash(ALGO_HASH, keypkg->key_cipher, keypkg->meta_data->length, keypkg->chck_value)) {
                    fprintf(stderr, "Error in derive : SDF_CalculateHash failed!\n");
                    error_occurred = TRUE;
                } else {
                    keypkg->chck_alg = ALGO_HASH;
                    keypkg->chck_len = 32;
                }
            }
        }
    }

    // 错误处理
    if (error_occurred) {
        key_meta_data_free(keypkg->meta_data); // 释放 meta_data 内存
        key_pkg_free(keypkg);                  // 释放 keypkg 内存
        return NULL;
    }
    // 打印kek key明文 iv mac

    return keypkg;
}

// 外部接口
void key_pkg_free(km_keypkg_t *pkg) {
    if (pkg != NULL) {
        // 释放 KeyMetaData 结构体及其内存
        if (pkg->meta_data != NULL) {
            key_meta_data_free(pkg->meta_data);
            pkg->meta_data = NULL; // 防止重复释放
        }

        // 清理 km_keypkg_t 结构体的其他成员
        // 由于其他数组成员（如 kek_cipher, key_cipher, iv, chck_value）是静态分配的，
        // 因此我们只需将它们重置为默认值或NULL，而无需释放它们。
        pkg->kek_cipher_len = 0;
        pkg->iv_len = 0;
        pkg->chck_len = 0;
        pkg->chck_alg = 0;

        // 释放 km_keypkg_t 结构体本身
        free(pkg);
    }
}

/**
 * @brief 将字节数组转换为十六进制字符串
 * @param[in] buff 输入的字节数组
 * @param[in] len 字节数组的长度
 * @param[out] hex_str 输出的十六进制字符串
 * @param[in] hex_str_len 十六进制字符串的长度
 * @return 转换是否成功
 */
int bytes_to_hex_str(uint8_t *buff, uint16_t len, char *hex_str, uint16_t hex_str_len) {
    // 检查输入参数
    if (hex_str_len < len * 2 + 1) {
        return -1; // 如果目标字符串长度不足，返回错误
    }

    for (int i = 0; i < len; i++) {
        // 每个字节转换为两个十六进制字符
        snprintf(hex_str + i * 2, 3, "%02X", buff[i]); // 使用 3 来确保不会越界
    }
    hex_str[len * 2] = '\0'; // 确保字符串以 '\0' 结尾

    return 0; // 成功
}

#endif

/*
//
//  * @brief 对比对数据做的校验值是否与给定MAC相同
//  * @param[in] 校验算法
//  * @param[in] mac 对比的MAC值
//  * @param[in] mac_length
//  * @param[in] iv
//  * @param[in] iv_len
//  * @param[in] data
//  * @param[in] data_len
//  * @return 对比通过返回TRUE，否则返回FALSE
//
bool km_checkvalue_is_same(
    uint32_t alg_id,
    uint8_t *mac,
    uint32_t mac_length,
    uint8_t *iv,
    uint8_t *data,
    uint32_t data_len);

bool km_checkvalue_is_same(uint32_t alg_id, uint8_t *mac, uint32_t mac_length, uint8_t *iv, uint8_t *data, uint32_t data_len)
{
    // 检查输入参数的有效性
    if (mac == NULL || data == NULL || mac_length == 0 || data_len == 0)
    {
        return FALSE;
    }

    uint32_t computed_mac_length;
    uint8_t computed_mac[computed_mac_length]; // 假设计算得到的校验值存储在这里

    // 根据 alg_id 使用特定的校验算法来计算数据的校验值，然后与传入的 MAC 进行比较
    if (alg_id == ALGO_HASH)
    {
        do
        {
            if (km_hash(alg_id, data, data_len, computed_mac) != LD_KM_OK)
            {
                return FALSE;
            }
            computed_mac_length = 32;
        } while (0);
    }
    else if (alg_id = ALGO_MAC)
    {
        // km_mac()
    }

    // 在这里根据 alg_id 使用对应的校验算法计算 computed_mac

    // 模拟比较计算出的 MAC 和传入的 MAC 是否相同
    if (memcmp(computed_mac, mac, mac_length) == 0)
    {
        return TRUE; // 校验成功
    }
    else
    {
        return FALSE; // MAC 不匹配
    }
}

static l_km_err output_enc_key(void * hSessionHandle, km_keypkg_t *keypkg, const char *export_raw_path)
{
    // 使用本地密钥加密和完整性保护存储
    uint32_t kek_index = 1;
    void * kek_handle;
    SDF_GenerateKeyWithKEK(hSessionHandle, 128, ALGO_WITH_KEK,
                           kek_index, keypkg->kek_cipher, &keypkg->kek_cipher_len,
                           &kek_handle); // 生成对密钥加密的密钥
    uint8_t iv_enc[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
                          0x20};
    keypkg->iv_len = 16;
    keypkg->chck_alg = ALGO_MAC;
    memcpy(keypkg->iv, iv_enc, keypkg->iv_len); // 替换iv ivenc和mac相同
    SDF_Encrypt(hSessionHandle, kek_handle, ALGO_ENC_AND_DEC, iv_enc, keypkg->key_cipher, keypkg->meta_data->length,
                keypkg->key_cipher, &keypkg->meta_data->length); // 使用kek加密根密钥 并生成pkg

    // 存入kek密文 替换验证码
    uint8_t iv_mac[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
                          0x20};
    SDF_CalculateMAC(hSessionHandle, kek_handle, keypkg->chck_alg,
                     iv_mac, keypkg->key_cipher, keypkg->meta_data->length,
                     keypkg->chck_value,
                     &keypkg->chck_len); // 使用kek对根密钥计算消息验证码memcpy(pkg->kek_cipher, cipher_kek, cipherkek_len);

    // 本地存储根密钥
    write_keypkg_to_file(export_raw_path, keypkg); // 导出到文件

    return LD_KM_OK;
}

//   @brief AS从密码卡中文件导入根密钥 验证文件中的根密钥 加密后输出
//   @param[out] rootkey_handle
//   @param[in] import_bin_path 从网关获取的根密钥文件
//   @param[in] import_raw_path 使用本地密码卡加密后输出的根密钥文件

km_keypkg_t *km_import_rootkey(void * *rootkey_handle, const char *import_bin_path, const char *import_raw_path)
{
    // 输出参数赋予空间
    void * DeviceHandle, *hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    // AS密码卡：从文件导入根密钥结构体
    km_keypkg_t *pkg = read_keypkg_from_file(import_bin_path);

    do
    {
        if (pkg == NULL)
            return NULL;
        // 删除根密钥文件
        //    FILE *file = fopen(rootkey_file, "rb");
        //    if (remove(rootkey_file) != 0) {
        //        perror("rootkey.bin删除失败");
        //    }

        // 校验明文根密钥完整性
        uint8_t hashed_rootkey[32] = {0};
        km_hash(ALGO_HASH, pkg->key_cipher, pkg->meta_data->length, hashed_rootkey);
        if (memcmp(hashed_rootkey, pkg->chck_value, pkg->chck_len) != 0)
        {
            log_warn("root key integrity check Wrong\n");
            break;
        }
        pkg->chck_alg = ALGO_HASH;
        // //printbuff("HASH", hashed_rootkey, pkg->chck_len);

        // 返回根密钥句柄
        if (SDF_ImportKey(hSessionHandle, pkg->key_cipher, pkg->meta_data->length, rootkey_handle) != SDR_OK)
        {
            log_warn("import rootkey failed\n");
            break;
        }

        // 输出加密形式的根密钥文件
        output_enc_key(hSessionHandle, pkg, import_raw_path);

        SDF_CloseSession(hSessionHandle); // 关闭会话
        SDF_CloseDevice(DeviceHandle);    // 关闭设备
        return pkg;
    } while (0);

    SDF_CloseSession(hSessionHandle); // 关闭会话
    SDF_CloseDevice(DeviceHandle);    // 关闭设备
    key_pkg_free(pkg);
    return NULL;
}

// 网关导出根密钥包到文件rootkey.bin中(给AS的) 本地存储根密钥于rootkey.txt中
km_keypkg_t *km_export_rootkey(struct KeyMetaData *keymeta, const char *export_bin_path, const char *backup_path)
{
    // 输出参数赋予空间
    km_keypkg_t *keypkg = km_key_pkg_new(keymeta, NULL, FALSE);

    void * DeviceHandle, *hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);
    SDF_OpenSession(DeviceHandle, &hSessionHandle);

    // 网关密码卡生成随机数作为根密钥
    SDF_GenerateRandom(hSessionHandle, keymeta->length,
                       keypkg->key_cipher);

    keypkg->chck_len = 32;
    km_hash(ALGO_HASH, keypkg->key_cipher, keymeta->length, keypkg->chck_value);

    // //printbuff("HASH", keypkg->chck_value, keypkg->chck_len);

    keypkg->iv_len = 0;                            // 没有iv
    keypkg->kek_cipher_len = 0;                    // 没有kek
    write_keypkg_to_file(export_bin_path, keypkg); // 导出到文件

    output_enc_key(hSessionHandle, keypkg, backup_path);
    keypkg->chck_alg = ALGO_HASH;

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return keypkg;
}

// 适用于SGW端：获取根密钥  输出：根密钥句柄
l_km_err km_get_rootkey_handle(void * *rootkey_handle, const char *filepath)
{
    void * DeviceHandle, *pSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄

    // 从文件区读取根密钥

    km_keypkg_t *restored_pkg = read_keypkg_from_file(filepath);
    // km_keypkg_t *restored_pkg = read_keypkg_from_file(filepath);
    if (restored_pkg == NULL)
    {
        log_warn("Error reading from file\n");
        return LD_ERR_KM_READ_FILE;
    }
    // //print_key_pkg(&restored_pkg);

    // 根密钥使用-校验密钥完整性
    uint32_t kek_index = 1;
    void * kek_handle;
    // 导入密钥加密密钥
    if (SDF_ImportKeyWithKEK(pSessionHandle, ALGO_WITH_KEK, kek_index, restored_pkg->kek_cipher,
                             restored_pkg->kek_cipher_len, &kek_handle) != LD_KM_OK)
    {
        log_warn("get key handle : import kek failed!\n");
        return LD_ERR_KM_IMPORT_KEY_WITH_KEK;
    }

    uint8_t mac_value[32] = {0};
    uint32_t mac_len;
    SDF_CalculateMAC(pSessionHandle, kek_handle, ALGO_MAC, restored_pkg->iv, restored_pkg->key_cipher,
                     restored_pkg->meta_data->length,
                     mac_value, &mac_len);
    if (memcmp(mac_value, restored_pkg->chck_value, mac_len) != 0)
    {
        log_warn("root key integrity Wrong\n");
        return LD_ERR_KM_ROOTKEY_VERIFY;
    }

    // 根密钥使用-获得句柄
    uint8_t rootkey_plain[32] = {0};
    uint32_t len_rootkey_plain = 0;
    uint8_t iv_dec[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
                          0x20};
    SDF_Decrypt(pSessionHandle, kek_handle, ALGO_ENC_AND_DEC, iv_dec, restored_pkg->key_cipher,
                restored_pkg->meta_data->length, rootkey_plain, &len_rootkey_plain);
    SDF_ImportKey(pSessionHandle, rootkey_plain, len_rootkey_plain, rootkey_handle); // 返回密钥句柄

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    key_pkg_free(restored_pkg);
    return LD_KM_OK;
}
*/