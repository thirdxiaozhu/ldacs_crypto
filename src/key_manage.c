// 调用密码卡生成密钥
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "key_manage.h"
#include <time.h>

#define DATA_SIZE 16
#define SM3_DIGEST_LENGTH 32

/*********************************************************
 *                     基础密码运算功能                  *
 ********************************************************/

// 生成随机数
l_km_err generate_random(int len, uint8_t *random_data)
{
    HANDLE DeviceHandle, pSessionHandle;
    int ret;

    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_KM_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }

    ret = SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    if (ret != LD_KM_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    ret = SDF_GenerateRandom(pSessionHandle, len, random_data);
    if (ret != LD_KM_OK)
    {
        printf("SDF_GenerateRandom Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_GENERATE_RANDOM;
    }
    // printbuff("random_data", random_data, len);
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_KM_OK;
}

// 国密算法加密接口
l_km_err
encrypt(void *key_handle, uint32_t alg_id, uint8_t *iv, uint8_t *data, uint32_t data_length, uint8_t *cipher_data,
        uint32_t *cipher_data_len)
{
    HANDLE DeviceHandle, pSessionHandle;
    HANDLE phKeyHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_KM_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }

    ret = SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    if (ret != LD_KM_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    // 调用SDF_Encrypt函数
    int result = SDF_Encrypt(pSessionHandle, key_handle, alg_id, iv, data, data_length, cipher_data, cipher_data_len);
    if (result != LD_KM_OK)
    {
        printf("SDF_Encrypt with phKeyHandle error!ret is %08x \n", result);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_ENCRYPT;
    }
    return LD_KM_OK;
}

// 国密算法解密
l_km_err decrypt(void *key_handle, uint32_t alg_id, uint8_t *iv, uint8_t *cipher_data, uint32_t cipher_data_len,
                 uint8_t *plain_data, uint32_t *plain_data_len)
{
    HANDLE DeviceHandle, pSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄

    // 调用SDF_Dncrypt函数

    int result = SDF_Decrypt(pSessionHandle, key_handle, alg_id, iv, cipher_data, cipher_data_len, plain_data,
                             plain_data_len);
    if (result != LD_KM_OK)
    {
        printf("SDF_Decrypt with phKeyHandle error!ret is %08x \n", result);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_DECRYPT;
    }
    return LD_KM_OK;
}

// hash算法
l_km_err hash(uint32_t alg_id, uint8_t *data, size_t data_len, uint8_t *output)
{
    HANDLE DeviceHandle, pSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_KM_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    if (ret != LD_KM_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    uint8_t hashResult[32];
    uint32_t hashResultLen = 32;

    ret = SDF_HashInit(pSessionHandle, alg_id, NULL, NULL, 0);
    if (ret != LD_KM_OK)
    {
        printf("SDF_HashInit Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_HashInit;
    }

    ret = SDF_HashUpdate(pSessionHandle, data, data_len);
    if (ret != LD_KM_OK)
    {
        printf("SDF_HashUpdate Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_HashUpdate;
    }

    ret = SDF_HashFinal(pSessionHandle, hashResult, &hashResultLen);
    if (ret != LD_KM_OK)
    {
        printf("SDF_HashFinish Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_HashFinal;
    }
    // printbuff("data", data, len);
    // printbuff("hashResult", hashResult, hashResultLen);
    memcpy(output, hashResult, 32);

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_KM_OK;
}

// MAC运算 SM4_CFB
l_km_err mac(void *key_handle, uint32_t alg_id, uint8_t *iv, uint8_t *data, uint32_t data_length, uint8_t *mac,
             uint32_t *mac_length)
{
    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    int ret = SDF_CalculateMAC(hSessionHandle, key_handle, alg_id, iv, data, data_length, mac, mac_length);
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    if (ret != LD_KM_OK)
    {
        printf("SDF_CalculateMACZ with phKeyHandle error!ret is %08x \n", ret);
        return LD_ERR_KM_MAC;
    }

    return LD_KM_OK;
}

// 通用sm3 hmac ，key长度要求为32byte
l_km_err
hmac(uint8_t *key, uint32_t key_len, uint8_t *data, uint32_t data_len, uint8_t *hmac_value, uint32_t *hmac_len)
{
    HANDLE DeviceHandle, pSessionHandle;
    uint32_t hash_result_len;
    uint8_t hash[64] = {0};
    uint8_t ipad_[HMAC_HASH_BLOCK_SIZE] = {0};
    uint8_t opad_[HMAC_HASH_BLOCK_SIZE] = {0};
    int ret;

    // 参数检查
    if (!key || key_len > 64 || !data || !data_len)
    {
        printf("hmac LD_ERR_KM_PARAMETERS_ERR\n");
        return LD_ERR_KM_PARAMETERS_ERR;
    }

    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_KM_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }

    ret = SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话
    if (ret != LD_KM_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    // prepare key
    memcpy(ipad_, key, (sizeof(uint8_t) * key_len));
    memcpy(opad_, key, sizeof(uint8_t) * key_len);

    // prepare for ipad and opad
    for (uint32_t i = 0; i < HMAC_HASH_BLOCK_SIZE; i++)
    {
        ipad_[i] ^= 0x36;
        opad_[i] ^= 0x5c;
    }

    // digest ipad and data
    ret = SDF_HashInit(pSessionHandle, SGD_SM3, NULL, NULL, 0);
    if (ret != LD_KM_OK)
    {
        printf("SDF_HashInit Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_HashInit;
    }
    ret = SDF_HashUpdate(pSessionHandle, ipad_, HMAC_HASH_BLOCK_SIZE);
    if (ret != LD_KM_OK)
    {
        printf("SDF_HashUpdate Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_HashUpdate;
    }
    ret = SDF_HashUpdate(pSessionHandle, data, data_len);
    if (ret != LD_KM_OK)
    {
        printf("SDF_HashUpdate Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_HashUpdate;
    }
    ret = SDF_HashFinal(pSessionHandle, hash, &hash_result_len);

    if (ret != LD_KM_OK)
    {
        printf("SDF_HashFinish Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_HashFinal;
    }
    // printbuff("hmac check point :digest ipad and data", hash, hash_result_len);

    // digest opad and hash
    SDF_HashInit(pSessionHandle, SGD_SM3, NULL, NULL, 0);
    SDF_HashUpdate(pSessionHandle, opad_, HMAC_HASH_BLOCK_SIZE);
    SDF_HashUpdate(pSessionHandle, hash, 32);
    SDF_HashFinal(pSessionHandle, hmac_value, hmac_len);
    // printbuff("hmac check point: digest opad and hash", hmac_value, *hmac_len);

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_KM_OK;
}

l_km_err hmac_with_keyhandle(void *handle, uint8_t *data, uint32_t data_len, uint8_t *hmac_value, uint32_t *hmac_len)
{
    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    uint8_t rand[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint8_t iv[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint8_t key[16];
    uint32_t key_len;
    int ret = SDF_Encrypt(hSessionHandle, handle, ALGO_ENC_AND_DEC, iv, rand, 16, key, &key_len);
    if (ret != LD_KM_OK)
    {
        printf("hmac_with_keyhandle  error!ret is %08x \n", ret);
        return LD_ERR_KM_SM3HMAC;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return hmac(key, key_len, data, data_len, hmac_value, hmac_len);
}

/*********************************************************
 *                     基础密钥管理功能                  *
 ********************************************************/

// 导入明文密钥
l_km_err import_key(uint8_t *key, uint32_t key_length, void **key_handle)
{
    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    int ret = SDF_ImportKey(hSessionHandle, key, key_length, key_handle);
    if (ret != LD_KM_OK)
    {
        printf("SDF_ImportKey with phKeyHandle error!ret is %08x \n", ret);
        return LD_ERR_KM_IMPORT_KEY;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_KM_OK;
}

// 销毁密钥
l_km_err destroy_key(void *key_handle)
{
    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    int ret = SDF_DestroyKey(hSessionHandle, key_handle);
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    if (ret != LD_KM_OK)
    {
        printf("SDF_DestroyKey with phKeyHandle error!ret is %08x \n", ret);
        return LD_ERR_KM_DESTROY_KEY;
    }

    return LD_KM_OK;
}

// 基于口令的密钥派生（prf：sm3 hmac）
l_km_err pbkdf2(uint8_t *password, uint32_t password_len, uint8_t *salt, uint32_t salt_len, uint32_t iterations,
                uint32_t derived_key_len, uint8_t *derived_key)
{
    // 参数检查
    if (password == NULL || salt == NULL)
    {
        printf("pbkdf2 fail , password and salt shouldn't be NULL\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    }
    if (salt_len < 4) // 参数检查 盐值长度不能小于4字节
    {
        printf("pbkdf2 fail , salt len should over 4 byte \n");
        return LD_ERR_KM_PARAMETERS_ERR;
    }
    if (iterations < 1024) // 迭代次数不能小于1024
    {
        printf("pbkdf2 fail , iterations should over 1024 times\n");
        return LD_ERR_KM_PARAMETERS_ERR;
    }
    if (derived_key_len != 16 && derived_key_len != 32 && derived_key_len != 64) // 派生密钥的长度为128 256 512byte
    {
        printf("pbkdf2 fail for illegal key len, 16/32/48/64 bytes are permitted\n");
        return LD_ERR_KM_PARAMETERS_ERR;
    }

    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    uint32_t dkLen = derived_key_len;                           // 所需的派生密钥长度
    uint32_t block_size = 32;                                   // 按照32byte将数据分块
    uint32_t block_num = (dkLen + block_size - 1) / block_size; // ceil(dkLen/block_size) 块数
    uint8_t *t = malloc(block_size * sizeof(uint8_t));
    uint8_t *u = malloc((salt_len + 4) * sizeof(uint8_t));
    uint8_t *xorsum = malloc((dkLen < 32 ? 32 : dkLen) * sizeof(uint8_t)); // 注意dklen<32时的空间分配
    // 动态分配内存检查
    if (t == NULL || u == NULL || xorsum == NULL)
    {
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

        if (hmac(password, password_len, u, salt_len + 4, t, &block_size) != LD_KM_OK)
        // if (SDFE_Hmac(hSessionHandle, password, password_len, u, salt_len + 4, t, &block_size) != LD_OK)
        {
            perror("pbkdf2 SM3-HMAC computation failed\n");
            free(t);
            free(u);
            free(xorsum);
            return LD_ERR_KM_PBKDF2;
        }
        // U_2 = U_1, U_3 = U_2, ..., U_l = U_{block_num-1}
        memcpy(xorsum, t, block_size);

        for (uint32_t j = 2; j <= iterations; j++)
        {
            if (hmac(password, password_len, t, block_size, t, &block_size) != LD_KM_OK)
            // if (SDFE_Hmac(hSessionHandle, password, password_len, t, block_size, t, &block_size) != LD_OK)
            {
                perror("pbkdf2 SM3-HMAC iteration2 computation failed\n");
                free(t);
                free(u);
                free(xorsum);
                return LD_ERR_KM_PBKDF2;
            }

            // U_2 xor U_3 xor ... xor U_l
            for (uint32_t k = 0; k < block_size; k++)
            {
                xorsum[k] ^= t[k];
            }
        }

        // Copy the derived key block to the output
        uint32_t copy_len = (i == block_num && dkLen % block_size != 0) ? (dkLen % block_size) : block_size;
        // printf("copy len %d ,(i - 1) * block_size:(%d -1) * %d\n", copy_len, i, block_size);
        memcpy(derived_key + (i - 1) * block_size, xorsum, copy_len);
        // printf("copy_len:%d,i:%d, hlen%d",copy_len,i,block_size);

        // printbuff("pbkdf2 output", derived_key, derived_key_len);
    }

    free(t);
    free(u);
    free(xorsum);

    SDF_CloseSession(hSessionHandle); // 关闭会话
    SDF_CloseDevice(DeviceHandle);    // 关闭设备
    return LD_KM_OK;
}

/*********************************************************
 *                     业务逻辑接口                      *
 ********************************************************/
/************
 * 密钥更新 *
 ***********/
// 更新主密钥 输入sac 输出主密钥包
l_km_err update_masterkey(uint8_t *sac_as, uint8_t *sac_source_gs, uint8_t *sac_target_gs, struct KeyPkg *pkg)
{
}

// 更新会话密钥
l_km_err update_sessionkey(struct KeyMetaData *meta_data, HANDLE masterkey_handle, uint8_t *nonce, uint32_t nonce_len,
                           struct KeyPkg *updated_keypkg)
{
    // 打开密码卡
    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    // 重新派生密钥
    uint32_t len = meta_data->length;       // 获取原密钥长度
    KeyType key_type = meta_data->key_type; // 获取密钥类型
    uint8_t *key = malloc(len);             // 定义新密钥
    HANDLE keyhandle;
    uint8_t owner_1[16];
    uint8_t owner_2[16];
    memcpy(owner_1, meta_data->owner_1, 16);
    memcpy(owner_2, meta_data->owner_2, 16);
    derive_key(masterkey_handle, key_type, len, owner_1, owner_2, nonce, nonce_len, &keyhandle,
               updated_keypkg); // 派生会话密钥

    // 撤销原密钥
    meta_data->state = SUSPENDED; // 改变密钥状态

    // 关闭密码卡
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_KM_OK;
}

/************
 * 密钥派生 *
 ***********/
l_km_err
derive_key(void *kdk_handle, enum KEY_TYPE key_type, uint32_t key_len, uint8_t *owner1, uint8_t *owner2, uint8_t *rand,
           uint32_t rand_len, void **key_handle, struct KeyPkg *pkg)
{
    // 参数检查 初始化输出变量空间
    if (pkg == NULL)
    {
        pkg = malloc(sizeof(struct KeyPkg));
    }

    uint8_t key[64];
    uint8_t salt[32];
    uint32_t salt_len;
    time_t current_time;
    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    // 派生密钥
    uint8_t *string_key_type = (uint8_t *)&key_type;
    uint8_t hash_of_keytype[32];
    int ret = hash(ALGO_HASH, string_key_type, sizeof(string_key_type), hash_of_keytype); // 计算key_type的hash值
    if (ret != LD_KM_OK)
    {
        printf("Error in derive : hash failed!\n\n");
        return LD_ERR_KM_DERIVE_KEY;
    }

    // keytype的hash_value作为iv 使用上级密钥对rand的hash值加密，取前16byte作为盐值输入pbkdf2
    uint8_t hash_of_rand[32];
    hash(ALGO_HASH, rand, rand_len, hash_of_rand); // 计算key_type的hash值
    ret = SDF_Encrypt(hSessionHandle, kdk_handle, ALGO_ENC_AND_DEC, hash_of_keytype, hash_of_rand, 32, salt, &salt_len);
    if (ret != LD_KM_OK)
    {
        printf("Error in derive : encrypt failed!\n");
        return LD_ERR_KM_DERIVE_KEY;
    }

    salt_len = 16; // 取前16byte输入pbkdf
    // hash_of_rand作为password，使用主密钥对key_type加密的结果作为iv  输入pbkdf2后派生出密钥
    ret = pbkdf2(hash_of_rand, 32, salt, salt_len, 1024, key_len, key); // 使用SM3-HMAC作为密钥派生的PRF，迭代次数1024次。
    if (ret != LD_KM_OK)
    {
        printf("Error in derive : pbkdf2 failed!\n");
        return LD_ERR_KM_DERIVE_KEY;
    }
    // printbuff("raw Key", key, key_len); // 密钥明文

    // 密钥加密存储
    uint32_t kek_index = 1;
    uint8_t cipher_kek[32];
    uint32_t cipherkek_len;
    void *kek_handle;
    ret = SDF_GenerateKeyWithKEK(hSessionHandle, 128, ALGO_WITH_KEK, kek_index, cipher_kek, &cipherkek_len,
                                 &kek_handle); // 生成对主密钥加密的密钥
    if (ret != LD_KM_OK)
    {
        printf("Error in derive : SDF_GenerateKeyWithKEK failed!\n");
        return LD_ERR_KM_DERIVE_KEY;
    }

    uint32_t iv_len = 16;
    uint8_t iv_enc[16];
    uint8_t iv_mac[16];
    SDF_GenerateRandom(hSessionHandle, 16, iv_enc);
    memcpy(iv_mac, iv_enc, 16); // 加密和Mac使用同一个密钥
    pkg->iv_len = iv_len;
    memcpy(pkg->iv, iv_enc, iv_len);
    uint8_t key_cipher[32];
    uint32_t cipher_len;
    ret = SDF_Encrypt(hSessionHandle, kek_handle, ALGO_ENC_AND_DEC, iv_enc, key, key_len, key_cipher, &cipher_len); // 主密钥密文
    if (ret != LD_KM_OK)
    {
        printf("Error in derive : SDF_Encrypt failed!\n");
        return LD_ERR_KM_DERIVE_KEY;
    }
    // printbuff("Key Cipher", key_cipher, cipher_len);

    // 将相关信息存入结构体
    uuid_t uuid;
    struct KeyMetaData *key_info = malloc(sizeof(struct KeyMetaData));
    key_info->key_type = key_type;
    uuid_generate(uuid); // 生成ID
    uuid_copy(key_info->id, uuid);
    memcpy(key_info->owner_1, owner1, strlen(owner1));                  // 指定所有者
    memset(key_info->owner_1 + strlen(owner1), 0, 16 - strlen(owner1)); // 不足部分填充0
    memcpy(key_info->owner_2, owner2, strlen(owner2));
    memset(key_info->owner_2 + strlen(owner2), 0, 16 - strlen(owner2)); // 不足部分填充0
    key_info->length = key_len;                                         // 长度
    key_info->state = ACTIVE;                                           // 状态 已激活
    key_info->creation_time = time(&current_time);
    key_info->update_cycle = 365; // 更新周期默认一年
    pkg->meta_data = key_info;

    memcpy(pkg->kek_cipher, cipher_kek, cipherkek_len);
    pkg->kek_cipher_len = cipherkek_len;
    memcpy(pkg->key_cipher, key_cipher, cipher_len);
    uint32_t chck_len;      // 校验值长度
    uint8_t chck_value[32]; // 长度为chck_len的校验值
    // printbuff("iv", iv_mac, iv_len);
    ret = SDF_CalculateMAC(hSessionHandle, kek_handle, ALGO_MAC, iv_mac, key_cipher, cipher_len, chck_value, &chck_len);
    if (ret != LD_KM_OK)
    {
        printf("Error in derive : SDF_CalculateMAC failed!\n");
        return LD_ERR_KM_DERIVE_KEY;
    }
    // printbuff("chck_value", chck_value, chck_len);

    pkg->chck_alg = ALGO_MAC;
    pkg->chck_len = chck_len;
    memcpy(pkg->chck_value, chck_value, chck_len);

    // 导入密钥 返回密钥句柄 截断 只取前16字节
    // void *temp_handle;
    key_len = key_len > 16 ? 16 : key_len;
    ret = SDF_ImportKey(hSessionHandle, key, key_len, key_handle);
    if (ret != LD_KM_OK)
    {
        printf("Error in derive : SDF_ImportKey, return : %d\n", ret);
        return LD_ERR_KM_DERIVE_KEY;
    }

    // 销毁内存中的密钥 关闭会话
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_KM_OK;
}

// 获取密钥句柄
l_km_err get_keyhandle(struct KeyPkg *pkg, void **key_handle)
{
    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    // 导入密钥加密密钥
    uint32_t kek_index = 1;
    void *kek_handle;
    int ret;
    ret = SDF_ImportKeyWithKEK(hSessionHandle, ALGO_WITH_KEK, kek_index, pkg->kek_cipher, pkg->kek_cipher_len,
                               &kek_handle);
    if (ret != LD_KM_OK)
    {
        printf("get key handle : import kek failed!\n");
        return LD_ERR_KM_IMPORT_KEY_WITH_KEK;
    }

    // 校验完整性
    uint32_t chck_len;      // 校验值长度
    uint8_t chck_value[32]; // 长度为chck_len的校验值
    // printbuff("iv", pkg->iv, pkg->iv_len);
    uint8_t iv_mac[16];
    uint8_t iv_dec[16];
    memcpy(iv_mac, pkg->iv, 16);
    memcpy(iv_dec, pkg->iv, 16);
    ret = SDF_CalculateMAC(hSessionHandle, kek_handle, ALGO_MAC, iv_mac, pkg->key_cipher, pkg->meta_data->length,
                           chck_value, &chck_len);
    // printbuff("chck", chck_value,chck_len);
    if (ret != LD_KM_OK) // 计算mac失败
    {
        printf("get key handle: calc mac failed!\n");
        return LD_ERR_KM_MAC;
    }
    if (memcmp(pkg->chck_value, chck_value, chck_len) != 0) // 密钥校验不通过
    {
        printf("get key handle: key verify failed!\n");
        printbuff("chck_value", chck_value, 32);
        // return LD_ERR_KM_MASTERKEY_VERIFY;
    }

    // 解密密钥
    uint8_t key[64];
    uint32_t key_len;
    ret = SDF_Decrypt(hSessionHandle, kek_handle, ALGO_ENC_AND_DEC, iv_dec, pkg->key_cipher, pkg->meta_data->length,
                      key, &key_len);
    if (ret != LD_KM_OK)
    {
        printf("get masterkey handle: decrypt failed!\n");
        return LD_ERR_KM_DECRYPT;
    }
    // printbuff("key cipher", pkg->key_cipher, pkg->meta_data->length);
    // printbuff("iv",pkg->iv,pkg->iv_len);
    // printbuff("decrypted key", key, key_len);

    // 导入密钥
    key_len = key_len > 16 ? 16 : key_len;
    ret = SDF_ImportKey(hSessionHandle, key, key_len, key_handle);
    if (ret != LD_KM_OK)
    {
        printf("get masterkey handle: import masterkey failed!\n");
        return LD_ERR_KM_IMPORT_KEY;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_KM_OK;
}

/************
 * 密钥生成 *
 ***********/

// 指定KEK索引和密钥元数据（密钥类型，密钥所有者，密钥长度，启用日期，更新周期），初始化元数据并生成密钥、密钥id，输出密钥句柄、使用KEK加密的密钥密文、和密钥元数据结构体。
l_km_err generate_key_with_kek(int kek_index, struct KeyMetaData *key_info, void **key_handle, uint8_t *cipher_key,
                               int *cipher_len)
{
    void *DeviceHandle, *pSessionHandle;
    if (key_info == NULL)
    {
        key_info = malloc(sizeof(struct KeyMetaData));
    }
    // cipher_key = (uint8_t *)malloc(sizeof(uint8_t) * (key_info->length));
    int ret; // iterate with crypto-device

    SDF_OpenDevice(&DeviceHandle);
    SDF_OpenSession(DeviceHandle, &pSessionHandle);

    // metadata calculate
    // key_info->counter = 0;
    // key_info->id = get_key_id();
    key_info->state = PRE_ACTIVATION;

    // GenerateKeyWithKEK 128bit SM4-ECB 产生根密钥并用KEK加密导出 此处接口密钥长度单位为bit！！！
    ret = SDF_GenerateKeyWithKEK(pSessionHandle, (key_info->length) * 8, ALGO_WITH_KEK, kek_index,
                                 cipher_key, cipher_len, key_handle);
    // printbuff("cipher key",cipher_key,*cipher_len);
    if (ret != LD_KM_OK)
    {
        printf("SDF_GenerateKeyKEK error!return is %08x\n", ret);
        free(cipher_key);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_GENERATE_KEY_WITH_KEK;
    }

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_KM_OK;
}

/************
 * 密钥存储 *
 ************/

// 将keypkg写入文件
l_km_err write_keypkg_to_file(const char *filename, struct KeyPkg *pkg)
{
    FILE *file = fopen(filename, "wb");
    if (file == NULL)
    {
        return LD_ERR_KM_PARAMETERS_NULL;
    }

    // Write metadata
    size_t meta_data_size = sizeof(struct KeyMetaData);
    if (fwrite(pkg->meta_data, meta_data_size, 1, file) != 1)
    {
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
    fwrite(&pkg->chck_len, sizeof(uint16_t), 1, file);
    fwrite(pkg->chck_value, sizeof(uint8_t), MAX_CHCK_LEN, file);

    fclose(file);
    return LD_KM_OK;
}

// 从文件读取出keypkg
l_km_err read_keypkg_from_file(const char *filename, struct KeyPkg *pkg)
{
    // 参数检查
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        return LD_ERR_KM_PARAMETERS_NULL;
    }

    // Read metadata
    pkg->meta_data = malloc(sizeof(struct KeyMetaData));
    size_t meta_data_size = sizeof(struct KeyMetaData);
    if (fread(pkg->meta_data, meta_data_size, 1, file) != 1)
    {
        fclose(file);
        return LD_ERR_KM_PARAMETERS_ERR;
    }

    fread(pkg->kek_cipher, sizeof(uint8_t), MAX_KEK_CIPHER_LEN, file); // read kek
    fread(&pkg->kek_cipher_len, sizeof(uint32_t), 1, file);
    fread(pkg->key_cipher, sizeof(uint8_t), MAX_KEY_CIPHER_LEN, file); // Read key
    // Read iv
    fread(&pkg->iv_len, sizeof(uint16_t), 1, file);
    fread(pkg->iv, sizeof(uint8_t), MAX_IV_LEN, file);
    // Read chck
    fread(&pkg->chck_alg, sizeof(uint16_t), 1, file);
    fread(&pkg->chck_len, sizeof(uint16_t), 1, file);
    fread(pkg->chck_value, sizeof(uint8_t), MAX_CHCK_LEN, file);
    fclose(file);

    // // 删除根密钥文件
    // if (remove(filename) != 0)
    // {
    //     perror("根密钥文件删除失败");
    // }

    return LD_KM_OK;
}

/***************
 *  根密钥预置  *
 **************/
// 网关导出根密钥包到文件rootkey.bin中(给AS的) 本地存储根密钥于rootkey.txt中
ld_keypkg_t *export_rootkey(struct KeyMetaData *root_keyinfo)
{
    // 输出参数赋予空间
    ld_keypkg_t *keypkg = malloc(sizeof(ld_keypkg_t));

    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                                                          // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle);                                         // 打开会话句柄
    uint8_t *export_filename = "/home/wencheng/crypto/key_management/keystore/rootkey.bin"; // 导出给AS的密钥文件
    uint32_t ret;
    time_t currentTime;

    // 网关密码卡生成随机数作为根密钥
    uint8_t rootkey[32];
    SDF_GenerateRandom(hSessionHandle, root_keyinfo->length,
                       rootkey); // printf("sec-gw generate root key（plain)====================\n");
    uint8_t hash_value[32];
    uint32_t hash_len = 32;
    uint32_t chck_algo = ALGO_HASH;
    hash(chck_algo, rootkey, root_keyinfo->length, hash_value);

    // 构造密钥包结构体用于密钥信息存储
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_copy(root_keyinfo->id, uuid);
    root_keyinfo->key_type = ROOT_KEY;
    keypkg->meta_data = root_keyinfo;
    root_keyinfo->creation_time = time(&currentTime);
    // 设置 chck_value、chck_algo、chck_len、key 字段
    keypkg->chck_alg = chck_algo;
    keypkg->chck_len = hash_len;
    memcpy(keypkg->chck_value, hash_value, hash_len);
    memcpy(keypkg->key_cipher, rootkey, root_keyinfo->length);
    keypkg->iv_len = 0;         // 没有iv
    keypkg->kek_cipher_len = 0; // 没有kek
    // printf("sec-gw generate root key pkg,write_keypkg_to_file（plain)====================\n");
    // print_key_pkg(pkg);
    write_keypkg_to_file(export_filename, keypkg); // 导出到文件

    // 使用本地密钥加密和完整性保护存储
    uint32_t kek_index = 1;
    // SDFE_GenerateKEK(hSessionHandle, 128, kek_index); // KEK需要提前生成
    uint8_t cipher_kek[32];
    uint32_t cipherkek_len;
    void *kek_handle;
    SDF_GenerateKeyWithKEK(hSessionHandle, 128, ALGO_WITH_KEK, kek_index, cipher_kek, &cipherkek_len,
                           &kek_handle); // 生成对密钥加密的密钥
    // printbuff("cipher kek",cipher_kek,cipherkek_len);
    uint8_t key_cipher[32];
    uint32_t cipher_len;
    uint8_t iv_enc[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
                          0x20};
    uint32_t iv_len = 16;
    keypkg->iv_len = iv_len;
    memcpy(keypkg->iv, iv_enc,
           iv_len); // 替换iv ivenc和mac相同
    SDF_Encrypt(hSessionHandle, kek_handle, ALGO_ENC_AND_DEC, iv_enc, keypkg->key_cipher, keypkg->meta_data->length,
                key_cipher, &cipher_len); // 使用kek加密根密钥 并生成pkg

    // 存入kek密文 替换验证码
    uint8_t iv_mac[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
                          0x20};
    uint32_t chck_len;      // 校验值长度
    uint8_t chck_value[32]; // 长度为chck_len的校验值
    SDF_CalculateMAC(hSessionHandle, kek_handle, ALGO_MAC, iv_mac, key_cipher, cipher_len, chck_value,
                     &chck_len); // 使用kek对根密钥计算消息验证码memcpy(pkg->kek_cipher, cipher_kek, cipherkek_len);
    memcpy(keypkg->kek_cipher, cipher_kek, cipherkek_len);
    keypkg->kek_cipher_len = cipherkek_len;
    memcpy(keypkg->key_cipher, key_cipher, cipher_len);
    keypkg->chck_alg = ALGO_MAC;
    keypkg->chck_len = chck_len;
    memcpy(keypkg->chck_value, chck_value, chck_len);
    // print_key_pkg(pkg);

    // 本地激活根密钥
    keypkg->meta_data->state = ACTIVE;

    // 本地存储根密钥
    uint8_t *filename = "/home/wencheng/crypto/key_management/keystore/rootkey.txt"; // 本地存储的密钥文件
    write_keypkg_to_file(filename, keypkg);                                          // 导出到文件

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return keypkg;
}

// 将文件存入密码卡文件区 指定输入文件的路径 存入密码卡时的文件名
l_km_err writefile_to_cryptocard(uint8_t *filepath, uint8_t *filename)
{
    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    FILE *file;
    uint32_t file_size;
    uint16_t result;

    // 打开文件
    file = fopen(filepath, "rb");
    if (file == NULL)
    {
        printf("Error opening file %s.\n", filepath);
        return LD_ERR_KM_OPEN_FILE;
    }

    // 定位文件末尾以获取文件大小
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    // printf("file %s size %d\n",filepath, file_size);
    rewind(file);

    // 分配内存以存储文件内容
    uint8_t *buffer = (uint8_t *)malloc(file_size * sizeof(uint8_t));
    if (buffer == NULL)
    {
        printf("Memory allocation error.\n");
        fclose(file);
        return LD_ERR_KM_WRITE_FILE;
    }

    // 将文件内容读入缓冲区
    result = fread(buffer, sizeof(uint8_t), file_size, file);
    if (result != file_size)
    {
        printf("Error reading file.\n");
        fclose(file);
        free(buffer);
        return LD_ERR_KM_WRITE_FILE;
    }

    // 创建密码卡文件
    // int createFileResult = SDF_CreateFile(hSessionHandle, filename, strlen(filename), file_size);
    // if (createFileResult != SDR_OK)
    // {
    //     printf("Error in createing cryptocard file %s, return %08x\n", filename, createFileResult);
    //     return LD_ERR_KM_CREATE_FILE;
    // }

    // 文件内容写入密码卡
    int writeFileResult = SDF_WriteFile(hSessionHandle, filename, strlen(filename), 0, file_size, buffer);
    if (writeFileResult != SDR_OK)
    {
        printf("Error writing to cryptocard file %s, return %08x\n", filename, writeFileResult);
        return LD_ERR_KM_WRITE_FILE;
    }

    SDF_CloseSession(hSessionHandle); // 关闭会话
    SDF_CloseDevice(DeviceHandle);    // 关闭设备

    return LD_KM_OK;
}

// 从密码卡读取文件 放到指定位置
l_km_err readfile_from_cryptocard(uint8_t *filename, uint8_t *filepath)
{
    HANDLE DeviceHandle, pSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    uint32_t ret;

    // 从文件区读取根密钥
    struct KeyPkg restored_pkg;
    uint32_t readLength = 266; // 根密钥文件的长度
    uint8_t restored_byteBuffer[readLength * 2];

    int readFileResult = SDF_ReadFile(pSessionHandle, filename, strlen(filename), 0, &readLength, restored_byteBuffer);
    if (readFileResult != 0)
    {
        printf("Error reading from file\n");
        return LD_ERR_KM_READ_FILE;
    }

    // 将根密钥结构体写入指定文件位置
    FILE *file;
    file = fopen(filepath, "wb");
    if (file == NULL)
    {
        printf("Error opening file.\n");
        return LD_ERR_KM_OPEN_FILE;
    }
    fwrite(restored_byteBuffer, readLength, 1, file);
    fclose(file);

    SDF_CloseSession(pSessionHandle); // 关闭会话
    SDF_CloseDevice(DeviceHandle);    // 关闭设备

    return LD_KM_OK;
}

// AS从密码卡中文件导入根密钥 验证文件中的根密钥 返回密钥包结构体
l_km_err import_rootkey(struct KeyPkg *rootkey_pkg, void **rootkey_handle)
{
    // 输出参数赋予空间
    if (rootkey_pkg == NULL)
    {
        rootkey_pkg = malloc(sizeof(struct KeyPkg));
    }

    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    uint8_t *rootkey_file = "/root/crypto/key_management/keystore/rootkey.bin";
    uint32_t ret;

    // AS密码卡：从文件导入根密钥结构体
    struct KeyPkg *pkg = malloc(sizeof(struct KeyPkg));
    read_keypkg_from_file(rootkey_file, pkg);
    // 删除根密钥文件
    FILE *file = fopen(rootkey_file, "rb");
    if (remove(rootkey_file) != 0)
    {
        perror("rootkey.bin删除失败");
    }

    // printf("restored keypkg,read_keypkg_from_file====================\n");
    // print_key_pkg(pkg);

    // 校验明文根密钥完整性
    uint8_t hash_rootkey[32];

    hash(ALGO_HASH, pkg->key_cipher, pkg->meta_data->length, hash_rootkey);
    if (memcmp(hash_rootkey, pkg->chck_value, pkg->chck_len) != 0)
    {
        printf("root key integrity check Wrong\n");
        return LD_ERR_KM_ROOTKEY_VERIFY;
    }

    // 返回根密钥句柄
    ret = SDF_ImportKey(hSessionHandle, pkg->key_cipher, pkg->meta_data->length, rootkey_handle);
    if (ret != SDR_OK)
    {
        return LD_ERR_KM_IMPORT_KEY;
        printf("import rootkey failed\n");
    }

    // 使用本地密钥加密和完整性保护存储
    uint32_t kek_index = 1;
    // SDFE_GenerateKEK(hSessionHandle, 128, kek_index); // KEK需要提前生成
    uint8_t cipher_kek[32];
    uint32_t cipherkek_len;
    void *kek_handle;
    SDF_GenerateKeyWithKEK(hSessionHandle, 128, ALGO_WITH_KEK, kek_index, cipher_kek, &cipherkek_len,
                           &kek_handle); // 生成对密钥加密的密钥
    // printbuff("cipher kek",cipher_kek,cipherkek_len);

    // 使用kek加密根密钥 并生成pkg
    uint8_t key_cipher[32];
    uint32_t cipher_len;
    uint8_t iv_enc[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
                          0x20};
    uint32_t iv_len = 16;
    pkg->iv_len = iv_len;
    memcpy(pkg->iv, iv_enc, iv_len); // 替换iv
    SDF_Encrypt(hSessionHandle, kek_handle, ALGO_ENC_AND_DEC, iv_enc, pkg->key_cipher, pkg->meta_data->length,
                key_cipher, &cipher_len);

    uint8_t iv_mac[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
                          0x20};
    uint32_t chck_len;      // 校验值长度
    uint8_t chck_value[32]; // 长度为chck_len的校验值
    SDF_CalculateMAC(hSessionHandle, kek_handle, ALGO_MAC, iv_mac, key_cipher, cipher_len, chck_value,
                     &chck_len); // 使用kek对根密钥计算消息验证码

    // 存入kek密文 替换验证码
    memcpy(pkg->kek_cipher, cipher_kek, cipherkek_len);
    pkg->kek_cipher_len = cipherkek_len;
    memcpy(pkg->key_cipher, key_cipher, cipher_len);
    pkg->chck_alg = ALGO_MAC;
    pkg->chck_len = chck_len;
    memcpy(pkg->chck_value, chck_value, chck_len);
    // printf("as read rootkey, encrypt and store in pcie-card file area=====================\n");
    // print_key_pkg(pkg);

    // 自动激活根密钥
    pkg->meta_data->state = ACTIVE;

    // 将根密钥写入文件区 存储于文件 "/root/crypto/key_management/keystore/rootkey.txt"
    uint8_t *byteBuffer = (uint8_t *)pkg; // 将结构体转换
    write_keypkg_to_file("/root/crypto/key_management/keystore/rootkey.txt", pkg);

    memcpy(rootkey_pkg, pkg, sizeof(struct KeyPkg)); // 返回密钥包结构体
    SDF_CloseSession(hSessionHandle);                // 关闭会话
    SDF_CloseDevice(DeviceHandle);                   // 关闭设备

    return LD_KM_OK;
}

// 适用于SGW端：获取根密钥  输出：根密钥句柄
l_km_err get_rootkey_handle(void **rootkey_handle)
{
    HANDLE DeviceHandle, pSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    uint32_t ret;
    uint8_t *rootkey_file = "/home/wencheng/crypto/key_management/keystore/rootkey.txt";

    // 从文件区读取根密钥
    struct KeyPkg restored_pkg;
    int readFileResult = read_keypkg_from_file(rootkey_file, &restored_pkg);
    if (readFileResult != 0)
    {
        printf("Error reading from file\n");
        return LD_ERR_KM_READ_FILE;
    }
    // print_key_pkg(&restored_pkg);

    // 根密钥使用-校验密钥完整性
    uint32_t kek_index = 1;
    void *kek_handle;
    ret = SDF_ImportKeyWithKEK(pSessionHandle, ALGO_WITH_KEK, kek_index, restored_pkg.kek_cipher,
                               restored_pkg.kek_cipher_len, &kek_handle); // 导入密钥加密密钥
    if (ret != LD_KM_OK)
    {
        printf("get key handle : import kek failed!\n");
        return LD_ERR_KM_IMPORT_KEY_WITH_KEK;
    }

    uint32_t iv_len = restored_pkg.iv_len;
    uint8_t iv[iv_len];
    memcpy(iv, restored_pkg.iv, iv_len);
    uint8_t mac_value[32];
    uint32_t mac_len;

    SDF_CalculateMAC(pSessionHandle, kek_handle, ALGO_MAC, iv, restored_pkg.key_cipher, restored_pkg.meta_data->length,
                     mac_value, &mac_len);
    if (memcmp(mac_value, restored_pkg.chck_value, mac_len) != 0)
    {
        printf("root key integrity Wrong\n");
        return LD_ERR_KM_ROOTKEY_VERIFY;
    }

    // 根密钥使用-获得句柄
    uint8_t rootkey_plain[32];
    uint32_t len_rootkey_plain;
    uint32_t algo_rootkey_enc = SGD_SM4_OFB;
    uint8_t iv_dec[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
                          0x20};
    SDF_Decrypt(pSessionHandle, kek_handle, algo_rootkey_enc, iv_dec, restored_pkg.key_cipher,
                restored_pkg.meta_data->length, rootkey_plain, &len_rootkey_plain);
    SDF_ImportKey(pSessionHandle, rootkey_plain, len_rootkey_plain, rootkey_handle); // 返回密钥句柄

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_KM_OK;
}

/*********************************************************
 *                     输出格式控制                      *
 ********************************************************/
// 打印字符串
l_km_err printbuff(const char *printtitle, uint8_t *buff, int len)
{
    if (buff == NULL)
    {
        printf("error: printbuff NULL pamameter\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    }
    int i;
    printf("%s:\n", printtitle);
    for (i = 0; i < len; i++)
    {
        printf("%02X ", buff[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }

    if ((i % 16) == 0)
    {
        printf("-----------------------------\n");
    }
    else
    {
        printf("\n-----------------------------\n");
    }
    return LD_KM_OK;
}

// 逐行打印密钥信息结构体
l_km_err print_key_metadata(struct KeyMetaData *key_info)
{
    char str[36];
    uuid_unparse(key_info->id, str);
    printf("ID:%s\n", str);

    printf("Type: ");

    switch (key_info->key_type)
    {
    case ROOT_KEY:
        printf("ROOT_KEY (KAS)\n");
        break;
    case MASTER_KEY_AS_SGW:
        printf("MASTER_KEY_AS_SGW (KASSGW)\n");
        break;
    case MASTER_KEY_AS_GS:
        printf("MASTER_KEY_AS_GS (KASGS)\n");
        break;
    case SESSION_KEY_USR_ENC:
        printf("SESSION_KEY_USR_ENC (KUENC)\n");
        break;
    case SESSION_KEY_USR_INT:
        printf("SESSION_KEY_USR_INT (KUINT)\n");
        break;
    case SESSION_KEY_DC_INT:
        printf("SESSION_KEY_DC_INT (KDC)\n");
        break;
    case SESSION_KEY_KEK:
        printf("SESSION_KEY_KEK (KKEK)\n");
        break;
    case SESSION_KEY_MAKE_INT:
        printf("SESSION_KEY_MAKE_INT (KM)\n");
        break;
    case GROUP_KEY_BC:
        printf("GROUP_KEY_DC (KBC)\n");
        break;
    case GROUP_KEY_CC:
        printf("GROUP_KEY_CC (KCC)\n");
        break;
    case NH_KEY:
        printf("NextHop KEY\n");
        break;
    default:
        printf("Unknown KEY_TYPE\n");
    }

    uint8_t emptyArray[MAX_OWENER_LEN] = {0};
    if (memcmp(key_info->owner_1, emptyArray, MAX_OWENER_LEN) == 0)
    {
        printf("Owner 1 : nil (Unspecified)\n");
    }
    else
    {
        printf("Owner 1: %s\n", key_info->owner_1);
    }
    if (memcmp(key_info->owner_2, emptyArray, MAX_OWENER_LEN) == 0)
    {
        printf("Owner 2 : nil (Unspecified)\n");
    }
    else
    {
        printf("Owner 2: %s\n", key_info->owner_2);
    }
    printf("Length: %u BYTES\n", key_info->length);

    printf("State: ");
    switch (key_info->state)
    {
    case PRE_ACTIVATION:
        printf("PRE_ACTIVATION\n");
        break;
    case ACTIVE:
        printf("ACTIVE\n");
        break;
    case SUSPENDED:
        printf("SUSPENDED\n");
        break;
    case DEACTIVATED:
        printf("DEACTIVATED\n");
        break;
    case COMPROMISED:
        printf("COMPROMISED\n");
        break;
    case DESTROYED:
        printf("DESTROYED\n");
        break;
    default:
        printf("Unknown\n");
    }
    struct tm *timeinfo = localtime(&key_info->creation_time);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    printf("Effectuation Time: %s\n", buffer);
    printf("Update Cycle: %lld days \n", (long long)key_info->update_cycle);
    // printf("Counter: %u\n", key_info->counter);

    return LD_KM_OK;
}

// 逐行打印key_pkg结构体
l_km_err print_key_pkg(struct KeyPkg *key_pkg)
{
    if (key_pkg == NULL)
    {
        // 处理错误，输入参数为空或者关键结构体为空
        printf("NULL key_pkg  for print_key_pkg function.\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    }
    else if (key_pkg->meta_data == NULL)
    {
        // 处理错误，输入参数为空或者关键结构体为空
        printf("NULL meta_data for print_key_pkg function.\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    }

    print_key_metadata(key_pkg->meta_data);
    uint8_t emptyArray[64] = {0};
    if (memcmp(key_pkg->kek_cipher, emptyArray, 16) == 0)
    {
        printf("KEK: nil (Unspecified)\n");
    }
    else
    {
        printbuff("KEK (cipher)", key_pkg->kek_cipher, 16);
    }
    printbuff("Key (cipher)", key_pkg->key_cipher, key_pkg->meta_data->length);
    printf("Check Algorithm: ");
    switch (key_pkg->chck_alg)
    {
    case ALGO_ENC_AND_DEC:
        printf("SGD_SM4_CFB\n");
        break;
    case ALGO_MAC:
        printf("SGD_SM4_MAC\n");
        break;
    case SGD_SM3:
        printf("SGD_SM3\n");
        break;
    case ALGO_WITH_KEK:
        printf("SGD_SM4_ECB\n");
        break;
    default:
        printf("unknown\n");
        break;
    }
    printbuff("IV", key_pkg->iv, key_pkg->iv_len);
    // printf("Check Length: %d\n", key_pkg->chck_len);
    printbuff("Check value", key_pkg->chck_value, key_pkg->chck_len);

    return LD_KM_OK;
}
