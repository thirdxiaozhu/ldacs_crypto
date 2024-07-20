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

#ifndef USE_GMSSL
#ifdef USE_SDF

#include <sdf/libsdf.h>
#include <sdfkmt/sdfe-func.h>
#include <sdfkmt/sdfe-type.h>

#elif USE_PIICO
#include <piico_pc/api.h>
#include <piico_pc/piico_define.h>
#include <piico_pc/piico_error.h>
#endif

#define DATA_SIZE 16
#define SM3_DIGEST_LENGTH 32



static field_desc km_fields[] = {
    // 密钥结构体字段描述
    {ft_uuid, 0, "id", NULL},
    {ft_enum, 0, "key_type", NULL},
    {ft_uint8t_pointer, 0, "owner1", NULL},
    {ft_uint8t_pointer, 0, "owner2", NULL},
    {ft_uint8t_pointer, 0, "key_cipher", NULL},
    {ft_uint32t, 0, "key_len", NULL},
    {ft_enum, 0, "key_state", NULL},
    {ft_timet, 128, "creatime", NULL},
    {ft_uint16t, 0, "updatecycle", NULL},
    {ft_uint32t, 0, "kek_len", NULL},
    {ft_uint8t_pointer, 0, "kek_cipher", NULL},
    {ft_uint8t_pointer, 0, "iv", NULL},
    {ft_uint16t, 0, "iv_len", NULL},
    {ft_enum, 0, "chck_algo", NULL},
    {ft_uint16t, 0, "check_len", NULL},
    {ft_uint8t_pointer, 0, "chck_value", NULL},
    {ft_uint16t, 0, "update_count", NULL},
    {ft_end, 0, NULL, NULL},
};

struct_desc static test_km_desc = {"km_pkg", km_fields};

/*********************************************************
 *                     基础密码运算功能                  *
 ********************************************************/

// 生成随机数
l_km_err km_generate_random(uint8_t *random_data, int len)
{
    CCARD_HANDLE DeviceHandle, pSessionHandle;
    int ret;

    if (SDF_OpenDevice(&DeviceHandle))
    {
        printf("SDF_OpenDevice error!\n");
        return LD_ERR_KM_OPEN_DEVICE;
    }

    if (SDF_OpenSession(DeviceHandle, &pSessionHandle))
    {
        printf("SDF_OpenSession error!\n");
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    if (SDF_GenerateRandom(pSessionHandle, len, random_data))
    {
        printf("SDF_GenerateRandom Function failure!, ret %08x\n", SDF_GenerateRandom(pSessionHandle, len, random_data));
        return LD_ERR_KM_GENERATE_RANDOM;
    }
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_KM_OK;
}

// 国密算法加密接口
l_km_err km_encrypt(void *key_handle, uint32_t alg_id, uint8_t *iv, uint8_t *data, uint32_t data_length,
                    uint8_t *cipher_data, uint32_t *cipher_data_len)
{
    CCARD_HANDLE DeviceHandle, pSessionHandle;
    CCARD_HANDLE phKeyHandle;
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
l_km_err km_decrypt(void *key_handle, uint32_t alg_id, uint8_t *iv, uint8_t *cipher_data, uint32_t cipher_data_len,
                    uint8_t *plain_data, uint32_t *plain_data_len)
{
    CCARD_HANDLE DeviceHandle, pSessionHandle;
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
l_km_err km_hash(uint32_t alg_id, uint8_t *data, size_t data_len, uint8_t *output)
{
    CCARD_HANDLE DeviceHandle, pSessionHandle;
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
l_km_err km_mac(CCARD_HANDLE key_handle, uint32_t alg_id, uint8_t *iv, uint8_t *data, uint32_t data_length, uint8_t *mac,
                uint32_t *mac_length)
{
    CCARD_HANDLE DeviceHandle, hSessionHandle;
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
l_km_err km_hmac(uint8_t *key, uint32_t key_len, uint8_t *data, uint32_t data_len, uint8_t *hmac_value, uint32_t *hmac_len)
{
    CCARD_HANDLE DeviceHandle, pSessionHandle;
    uint32_t hash_result_len;
    uint8_t hash[64] = {0};
    uint8_t ipad_[HMAC_HASH_BLOCK_SIZE] = {0};
    uint8_t opad_[HMAC_HASH_BLOCK_SIZE] = {0};
    int ret;

    // 参数检查
    if (!key || key_len > 64 || !data || !data_len)
    {
        printf("km_hmac LD_ERR_KM_PARAMETERS_ERR\n");
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
    // printbuff("km_hmac check point :digest ipad and data", km_hash, hash_result_len);

    // digest opad and km_hash
    SDF_HashInit(pSessionHandle, SGD_SM3, NULL, NULL, 0);
    SDF_HashUpdate(pSessionHandle, opad_, HMAC_HASH_BLOCK_SIZE);
    SDF_HashUpdate(pSessionHandle, hash, 32);
    SDF_HashFinal(pSessionHandle, hmac_value, hmac_len);
    // printbuff("km_hmac check point: digest opad and km_hash", hmac_value, *hmac_len);

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_KM_OK;
}

// 使用句柄完成hmac
l_km_err km_hmac_with_keyhandle(void *handle, uint8_t *data, uint32_t data_len, uint8_t *hmac_value, uint32_t *hmac_len)
{
    CCARD_HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    uint8_t rand[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint8_t iv[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint8_t key[16];
    uint32_t key_len;
    int ret = SDF_Encrypt(hSessionHandle, handle, ALGO_ENC_AND_DEC, iv, rand, 16, key, &key_len);
    if (ret != LD_KM_OK)
    {
        printf("km_hmac_with_keyhandle  error!ret is %08x \n", ret);
        return LD_ERR_KM_HMAC;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return km_hmac(key, key_len, data, data_len, hmac_value, hmac_len);
}

/*********************************************************
 *                     基础密钥管理功能                  *
 ********************************************************/

// 导入明文密钥
l_km_err km_import_key(uint8_t *key, uint32_t key_length, void **key_handle)
{
    CCARD_HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    int ret = SDF_ImportKey(hSessionHandle, key, key_length, key_handle);
    if (ret != SDR_OK)
    {
        printf("SDF_ImportKey with phKeyHandle error!ret is %08x \n", ret);
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
l_km_err km_import_key_with_kek(uint8_t *key, uint32_t key_length, int kek_index, CCARD_HANDLE *key_handle)
{
    CCARD_HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    int ret = SDF_ImportKeyWithKEK(hSessionHandle, ALGO_WITH_KEK, kek_index, key, key_length, key_handle);
    if (ret != SDR_OK)
    {
        printf("SDF_ImportKey with phKeyHandle error!ret is %08x \n", ret);
        return LD_ERR_KM_IMPORT_KEY;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_KM_OK;
}

// 销毁密钥
l_km_err km_destroy_key(CCARD_HANDLE key_handle)
{
    CCARD_HANDLE DeviceHandle, hSessionHandle;
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
                   uint32_t derived_key_len, uint8_t *derived_key)
{
    /* 参数检查 */
    if (password == NULL || salt == NULL)
    {
        printf("km_pbkdf2 fail , password and salt shouldn't be NULL\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    }
    /* 参数检查 盐值长度不能小于4字节*/
    if (salt_len < 4)
    {
        printf("km_pbkdf2 fail , salt len should over 4 byte \n");
        return LD_ERR_KM_PARAMETERS_ERR;
    }
    /* 迭代次数不能小于1024 */
    if (iterations < 1024)
    {
        printf("km_pbkdf2 fail , iterations should over 1024 times\n");
        return LD_ERR_KM_PARAMETERS_ERR;
    }
    /* 派生密钥的长度为128 256 512byte */
    if (derived_key_len != 16 && derived_key_len != 32 && derived_key_len != 64)
    {
        printf("km_pbkdf2 fail for illegal key len, 16/32/48/64 bytes are permitted\n");
        return LD_ERR_KM_PARAMETERS_ERR;
    }

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

        for (uint32_t j = 2; j <= iterations; j++)
        {
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

        // printbuff("km_pbkdf2 output", derived_key, derived_key_len);
    }

    free(t);
    free(u);
    free(xorsum);

    return LD_KM_OK;
}


// 将文件存入密码卡文件区 指定输入文件的路径 存入密码卡时的文件名
l_km_err km_writefile_to_cryptocard(uint8_t *filepath, uint8_t *filename)
{
    CCARD_HANDLE DeviceHandle, hSessionHandle;
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

// 密码卡内创建文件
l_km_err km_create_ccard_file(const char *filename, size_t file_size)
{
    CCARD_HANDLE DeviceHandle, pSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄

    // 调用实际的文件创建函数
    int createFileResult = SDF_CreateFile(pSessionHandle, (unsigned char*)filename, strlen(filename), file_size);

    // 检查函数调用结果
    if (createFileResult != SDR_OK)
    {
        printf("Error in creating cryptocard file %s, return %08x\n", filename, createFileResult);
        return LD_ERR_KM_CREATE_FILE; // 返回定义的错误代码
    }

    SDF_CloseSession(pSessionHandle); // 关闭会话
    SDF_CloseDevice(DeviceHandle);    // 关闭设备

    return LD_KM_OK;
}

// 从密码卡读取文件 放到指定位置
l_km_err km_readfile_from_cryptocard(const char *filename, const char *filepath)
{
    CCARD_HANDLE DeviceHandle, pSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    uint32_t ret;

    // 从文件区读取根密钥
    struct KeyPkg restored_pkg;
    uint32_t readLength = 268; // 根密钥文件的长度
    uint8_t restored_byteBuffer[readLength * 2];

    int readFileResult = SDF_ReadFile(pSessionHandle, (unsigned char*)filename, strlen(filename), 0, &readLength, restored_byteBuffer);
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
/*********************************************************
 *                     业务逻辑接口                      *
 ********************************************************/
/****************
 * 密钥生成派生 *
 ***************/
// 指定KEK索引和密钥元数据（密钥类型，密钥所有者，密钥长度，启用日期，更新周期），初始化元数据并生成密钥、密钥id，输出密钥句柄、使用KEK加密的密钥密文、和密钥元数据结构体。
l_km_err km_generate_key_with_kek(int kek_index, uint32_t kek_len, CCARD_HANDLE *key_handle, uint8_t *cipher_key, int *cipher_len)
{
    void *DeviceHandle, *pSessionHandle;
    int ret; // iterate with crypto-device

    SDF_OpenDevice(&DeviceHandle);
    SDF_OpenSession(DeviceHandle, &pSessionHandle);

    // GenerateKeyWithKEK 128bit SM4-ECB 产生根密钥并用KEK加密导出 此处接口密钥长度单位为bit！！！
    do
    {
        if (SDF_GenerateKeyWithKEK(pSessionHandle, kek_len * 8, ALGO_WITH_KEK, kek_index, cipher_key, cipher_len, key_handle) != LD_KM_OK)
        {
            printf("SDF_GenerateKeyKEK error!return is %08x\n", ret);
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
 * @brief 根密钥管理接口，用于生成、保存和导出根密钥
 * */
l_km_err km_rkey_gen_export(const char *as_name, const char *sgw_name, uint32_t key_len, uint32_t validity_period, const char *dbname, const char *tablename, const char *export_file_path)
{
    do
    {
        // 生成根密钥
        km_keymetadata_t *key_data = km_key_metadata_new(as_name, sgw_name, ROOT_KEY, key_len, validity_period);
        uint8_t root_key[key_len];
        km_generate_random(root_key, key_len);
        // printbuff("root key: ", root_key, key_len);
        km_keypkg_t *rk_rawpkg = km_key_pkg_new(key_data, root_key, FALSE); // 明文

        // 导出根密钥到文件
        // delete_file(export_file_path); // 清除已有文件
        if (write_keypkg_to_file(export_file_path, rk_rawpkg) != LD_KM_OK)
        {
            printf("write key to file failed\n");
            break;
        }
        print_key_pkg(rk_rawpkg);

        // 存储根密钥
        km_keypkg_t *keypkg = km_key_pkg_new(key_data, root_key, TRUE);
        // print_key_pkg(keypkg);
        uint8_t *primary_key = "id";
        if (create_table_if_not_exist(&test_km_desc, dbname, tablename, primary_key) != LD_KM_OK)
        {
            printf("create table failed\n");
            break;
        }
        if (store_key(dbname, tablename, keypkg, &test_km_desc) != LD_KM_OK)
        {
            printf("store key failed\n");
            break;
        }

        key_pkg_free(keypkg);

    } while (0);

    return LD_KM_OK; // 或者适当的错误码或成功码
}

/**
 * @brief 根密钥导入
*/
l_km_err km_rkey_import(const char *db_name, const char *table_name, const char *rkey_filename_in_ccard)
{

    // read root key from ccard
    const char *local_rkdir = "/home/wencheng/crypto/ldacs/ldacs_stack-main/rkstore/rootkey.txt";

    do
    {
        if (km_readfile_from_cryptocard(rkey_filename_in_ccard, local_rkdir) != LD_KM_OK)
        {
            break;
        }
        km_keypkg_t *raw_pkg = read_keypkg_from_file(local_rkdir);
        remove(local_rkdir);
        print_key_pkg(raw_pkg);

        // root key store
        km_keypkg_t *keypkg = km_key_pkg_new(raw_pkg->meta_data, raw_pkg->key_cipher, TRUE);
        // keypkg->meta_data->state = ACTIVE; // 激活密钥
        // print_key_pkg(keypkg);
        if (create_table_if_not_exist(&test_km_desc, db_name, table_name, "id") != LD_KM_OK)
        {
            break;
        }
        if (store_key(db_name, table_name, keypkg, &test_km_desc) != LD_KM_OK)
        {
            break;
        }
        return LD_KM_OK;

    } while (0);

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
km_keypkg_t *derive_key(CCARD_HANDLE kdk_handle, enum KEY_TYPE key_type, uint32_t key_len, const char *owner1, const char *owner2, uint8_t *rand, uint32_t rand_len, CCARD_HANDLE *key_handle)
{
    // 导入密钥 返回密钥句柄 截断 只取前16字节
    key_len = key_len > 16 ? 16 : key_len;

    km_keymetadata_t *meta = km_key_metadata_new(owner1, owner2, key_type, key_len, 365);
    km_keypkg_t *pkg = km_key_pkg_new(meta, NULL, FALSE);

    uint8_t key[64] = {0};
    uint8_t salt[32] = {0};
    uint32_t salt_len = 16; // 取前16byte输入pbkdf

    CCARD_HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);
    SDF_OpenSession(DeviceHandle, &hSessionHandle);

    do
    {

        // 派生密钥
        // TODO: ?? bug
        uint8_t hash_of_keytype[32] = {0};
        //        uint8_t *string_key_type = (uint8_t *) &key_type;
        //        if (km_hash(ALGO_HASH, string_key_type, sizeof(string_key_type), hash_of_keytype)) {
        //            printf("Error in derive : km_hash failed!\n\n");
        //            break;
        //        }
        if (km_hash(ALGO_HASH, (uint8_t *)type_names[key_type], strlen(type_names[key_type]), hash_of_keytype))
        {
            printf("Error in derive : km_hash failed!\n\n");
            break;
        }

        // keytype的hash_value作为iv 使用上级密钥对rand的hash值加密，取前16byte作为盐值输入pbkdf2
        uint8_t hash_of_rand[32] = {0};
        if (km_hash(ALGO_HASH, rand, rand_len, hash_of_rand))
        {
            printf("Error in derive : km_hash failed!\n\n");
            break;
        }

        int ret = SDF_Encrypt(hSessionHandle, kdk_handle, ALGO_ENC_AND_DEC, hash_of_keytype, hash_of_rand, 32, salt,
                              &salt_len);
        if (ret != SDR_OK)
        {
            printf("Error in derive : km_encrypt failed! %08x\n", ret);
            break;
        }

        // hash_of_rand作为password，使用主密钥对key_type加密的结果作为iv  输入pbkdf2后派生出密钥
        /* 使用SM3-HMAC作为密钥派生的PRF，迭代次数1024次 */
        if (km_pbkdf2(hash_of_rand, 32, salt, salt_len, 1024, key_len, key))
        {
            printf("Error in derive : km_pbkdf2 failed!\n");
            break;
        }

        // 密钥加密存储
        uint32_t kek_index = 1;
        CCARD_HANDLE kek_handle;
        /* 生成对主密钥加密的密钥 */
        uint8_t kek_cipher[16];
        uint32_t kek_len = 16;
        uint32_t kek_cipher_len;
        if (km_generate_key_with_kek(kek_index, kek_len, &kek_handle, pkg->kek_cipher, &pkg->kek_cipher_len) != LD_KM_OK) // TODO: KEK存入密钥包
        {
            printf("Error in derive : SDF_GenerateKeyWithKEK failed!\n");
            break;
        }

        pkg->iv_len = 16;
        uint8_t iv_mac[16];
        uint8_t iv_enc[16];
        if (km_generate_random(pkg->iv, pkg->iv_len))
        {
            break;
        }

        // SDF_GenerateRandom(hSessionHandle, 16, iv_enc);
        memcpy(iv_mac, pkg->iv, pkg->iv_len); // 加密和Mac使用同一个密钥
        memcpy(iv_enc, pkg->iv, pkg->iv_len);

        uint32_t cipher_len;

        /* 主密钥密文 */
        if (SDF_Encrypt(hSessionHandle, kek_handle, ALGO_ENC_AND_DEC, iv_enc,
                        key, key_len, pkg->key_cipher, &cipher_len))
        {
            printf("Error in derive : SDF_Encrypt failed!\n");
            break;
        }

        /* 校验算法 */
        if (SDF_CalculateMAC(hSessionHandle, kek_handle, ALGO_MAC, iv_mac,
                             pkg->key_cipher, cipher_len, pkg->chck_value, &(pkg->chck_len)))
        {
            printf("Error in derive : SDF_CalculateMAC failed!\n");
            break;
        }
        pkg->chck_alg = ALGO_MAC;
        pkg->meta_data->state = ACTIVE;

        if (key_handle != NULL && SDF_ImportKey(hSessionHandle, key, key_len, key_handle))
        {
            printf("Error in derive : SDF_ImportKey\n");
            break;
        }

        SDF_CloseSession(hSessionHandle);
        SDF_CloseDevice(DeviceHandle);

        return pkg;
    } while (0);

    // 销毁内存中的密钥 关闭会话
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    key_pkg_free(pkg);

    return NULL;
}

/**
 * @brief 内部接口：主密钥派生并存储所有会话密钥
 * @param[in] dbname   密钥库名
 * @param[in] tablename 密钥表名
 * @param[in] handle_mk 主密钥句柄
 * @param[in] key_len 所需密钥的长度
 * @param[in] sac_as  AS标识
 * @param[in] sac_gs GS标识
 * @param[in] rand 随机数
 * @param[in] rand_len 随机数长度
 */
l_km_err km_derive_all_session_key(uint8_t *db_name, uint8_t *table_name, CCARD_HANDLE handle_mk, uint32_t key_len, const char *sac_as, const char *sac_gs, uint8_t *rand, uint32_t rand_len)
{
    // 派生会话密钥
    enum KEY_TYPE key_types[4];
    key_types[0] = SESSION_KEY_USR_ENC;
    key_types[1] = SESSION_KEY_USR_INT;
    key_types[2] = SESSION_KEY_CONTROL_ENC;
    key_types[3] = SESSION_KEY_CONTROL_INT;

    km_keypkg_t *pkg;
    uint32_t sessionkey_len = 16;
    for (int i = 0; i <= 3; i++)
    {

        pkg = derive_key(handle_mk, key_types[i], sessionkey_len, sac_as, sac_gs, rand, rand_len, NULL);
        if (pkg == NULL)
        {
            printf("dervie key failed\n");
            return LD_ERR_KM_DERIVE_KEY;
        }
        // print_key_pkg(pkg);
        if (store_key(db_name, table_name, pkg, &test_km_desc) != LD_KM_OK)
        {
            printf("store_key failed: %d\n");
            return LD_ERR_KM_DERIVE_KEY;
        }

        key_pkg_free(pkg);
    }
    return LD_KM_OK;
}

/**
 * @brief 内部接口：主密钥KAS-GS的派生和存储
 * @param[in] dbname   密钥库名
 * @param[in] tablename 密钥表名
 * @param[in] handle_kassgw AS和SGW之间主密钥句柄
 * @param[in] key_len 所需密钥的长度
 * @param[in] sac_as  AS标识
 * @param[in] sac_gs  GS标识
 * @param[in] rand 随机数
 * @param[in] rand_len 随机数长度
 * @param[out] key_handle KAS-GS密钥的句柄
 * @return 返回报错码/成功码LD_KM_OK
 */

l_km_err km_derive_masterkey_asgs(uint8_t *db_name, uint8_t *table_name, CCARD_HANDLE handle_kassgw, uint32_t key_len, const char *sac_as, const char *sac_gs, uint8_t *rand, uint32_t rand_len, CCARD_HANDLE *handle_kasgs)
{
    uint8_t NH[16]; // 中间变量 下一跳密钥
    uint16_t len_kasgs = 16;
    CCARD_HANDLE handle_NH;
    struct KeyPkg *pkg_NH;
    struct KeyPkg *pkg_kasgs;

    do
    {
        // 参数准备
        pkg_NH = derive_key(handle_kassgw, NH_KEY, len_kasgs, sac_as, sac_gs, rand,
                            rand_len, &handle_NH); // NH = KDF(KAS-SGW,rand)
        if (pkg_NH == NULL)
        {
            printf("[**AS derive_key NH error**]\n");
            return LD_ERR_KM_DERIVE_KEY;
        }
        else
        {
            store_key(db_name, table_name, pkg_NH, &test_km_desc); // 存储NH密钥(中间密钥)
        }

        uint8_t xor_result[rand_len];
        uint16_t len_xor_res = rand_len;
        for (int i = 0; i < rand_len; i++)
        {
            xor_result[i] = sac_gs[i] ^ rand[i]; // SAC_GS^N3
        }

        // 密钥派生
        pkg_kasgs = derive_key(handle_NH, MASTER_KEY_AS_GS, len_kasgs, sac_as, sac_gs, xor_result,
                               len_xor_res, handle_kasgs); // KAS-GS=KDF(NH,SAC_GS^N3)
        if (pkg_kasgs == NULL)
        {
            return LD_ERR_KM_DERIVE_KEY;
        }
        else
        {
            // print_key_pkg(pkg_kasgs);
            store_key(db_name, table_name, pkg_kasgs, &test_km_desc); // AS端计算和存储与GS之间的主密钥
        }
        free(pkg_kasgs);

    } while (0);

    return LD_KM_OK;
}

// 外部接口 密钥派生
l_km_err km_derive_key(uint8_t *db_name, uint8_t *table_name, uint8_t *id, uint32_t key_len, uint8_t *gs_name, uint8_t *rand, uint32_t rand_len)
{
    do
    {
        // get key handle
        CCARD_HANDLE handle;
        if (get_handle_from_db(db_name, table_name, id, &handle) != LD_KM_OK)
        {
            printf("[** get_handle error**]\n");
            break;
        }

        // get owner
        QueryResult_for_owner qr_o = query_owner(db_name, table_name, id);
        if (qr_o.owner1 == NULL || qr_o.owner2 == NULL)
        {
            printf("[** query_owner error**]\n");
            break;
        }

        // react based on key type
        switch (query_keytype(db_name, table_name, id))
        {
        case ROOT_KEY:
        {
            // 派生主密钥kas-sgw
            km_keypkg_t *pkg = derive_key(handle, MASTER_KEY_AS_SGW, key_len, qr_o.owner1, qr_o.owner2, rand, rand_len, NULL);
            if (pkg == NULL)
            {
                printf("[**sgw derive_key kas-sgw error**]\n");
                break;
            }
            else
            {
                if (create_table_if_not_exist(&test_km_desc, db_name, table_name, "id") != LD_KM_OK) // 根据描述创建表
                {
                    break;
                }

                if (store_key(db_name, table_name, pkg, &test_km_desc) != LD_KM_OK)
                {
                    break;
                }
            }

            // 派生主密钥kas-gs
            if (km_derive_masterkey_asgs(db_name, table_name, handle, key_len, qr_o.owner1, gs_name, rand, rand_len, NULL) != LD_KM_OK)
            {
                printf("[**AS derive master KAS-GS failed]\n");
                break;
            }
            return LD_KM_OK;
        }
        case MASTER_KEY_AS_GS:
        {
            if (km_derive_all_session_key(db_name, table_name, handle, key_len, qr_o.owner1, qr_o.owner2, rand, rand_len) != LD_KM_OK)
            {
                printf("session key derive failed\n");
                break;
            }
            return LD_KM_OK;
        }
        default:
            printf("unexpected key type\n");
            break;
        }

    } while (0);

    return LD_ERR_KM_DERIVE_KEY;
}

// 获取密钥句柄
l_km_err km_get_keyhandle(struct KeyPkg *pkg, CCARD_HANDLE *key_handle)
{
    CCARD_HANDLE DeviceHandle, hSessionHandle;
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
        printf("get key handle: calc km_mac failed!\n");
        return LD_ERR_KM_MAC;
    }
    if (memcmp(pkg->chck_value, chck_value, chck_len) != 0) // 密钥校验不通过
    {
        printf("get key handle: key verify failed!\n");
        printbuff("chck_value", chck_value, 32);
        return LD_ERR_KM_MASTERKEY_VERIFY;
    }

    // 解密密钥
    uint8_t key[64];
    uint32_t key_len;
    ret = SDF_Decrypt(hSessionHandle, kek_handle, ALGO_ENC_AND_DEC, iv_dec, pkg->key_cipher, pkg->meta_data->length,
                      key, &key_len);
    if (ret != LD_KM_OK)
    {
        printf("get masterkey handle: km_decrypt failed!\n");
        return LD_ERR_KM_DECRYPT;
    }

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
 * 密钥更新 *
 ***********/
/**
 * @brief AS端 SGW更新会话密钥
 */
l_km_err km_update_sessionkey(uint8_t *dbname, uint8_t *tablename, uint8_t *id_mk, uint8_t *sac_as, uint8_t *sac_gs_t, uint32_t nonce_len, uint8_t *nonce)
{
    // 查询主密钥派生出来的所有会话密钥
    QueryResult_for_subkey result = query_subkey(dbname, tablename, id_mk, MASTER_KEY_AS_GS);

    // 逐个更新
    for (int i = 0; i < result.count; ++i)
    {
        do
        {
            printf("更新子密钥 %s\n", result.subkey_ids[i]);
            // 查询该密钥信息
            CCARD_HANDLE handle_mk;
            QueryResult_for_update qr = query_for_update(dbname, tablename, result.subkey_ids[i]);
            if (qr.key_len <= 0 || qr.update_cycle <= 0 || qr.update_count < 0)
            {
                printf("Query failed.\n");
                break;
            }

            // 查询主密钥句柄
            if (get_handle_from_db(dbname, tablename, id_mk, &handle_mk) != LD_KM_OK)
            {
                printf("get_handle_from_db failed\n");
                break;
            }

            // 生成新密钥
            km_keypkg_t *pkg;
            pkg = derive_key(handle_mk, str_to_ktype(result.key_types[i]), qr.key_len, sac_as, sac_gs_t, nonce, nonce_len, NULL);
            if (pkg == NULL)
            {
                printf("dervie key failed\n");
                break;
            }
            // printf("dervie key OK\n");

            // 存储新密钥
            if (store_key(dbname, tablename, pkg, &test_km_desc) != LD_KM_OK)
            {
                printf("store_key failed.\n");
                break;
            }
            // printf("store_key OK.\n");

            // 撤销旧密钥
            if (alter_keystate(dbname, tablename, result.subkey_ids[i], SUSPENDED) != LD_KM_OK)
            {
                printf("alter_keystate failed.\n");
                break;
            }

            // 释放变量空间
            free(result.subkey_ids[i]);
            free(result.key_types[i]);
            free(pkg);
            free(handle_mk);

        } while (0);
    }
    free(result.subkey_ids);
    free(result.key_types);

    return LD_KM_OK;
}

/**
 * @brief 网关和AS端更新主密钥 KAS-GS
 */
l_km_err km_update_masterkey(uint8_t *dbname, uint8_t *tablename, uint8_t *sac_sgw, uint8_t *sac_gs_s, uint8_t *sac_gs_t, uint8_t *sac_as, uint16_t len_nonce, uint8_t *nonce)
{
    do
    {
        // 如果不存在 则创建表
        uint8_t *primary_key = "id";
        if (create_table_if_not_exist(&test_km_desc, dbname, tablename, primary_key) != LD_KM_OK)
        {
            printf("create table err\n");
            return LD_ERR_KM_CREATE_DB;
        }

        // 查询主密钥id
        QueryResult_for_queryid qr_mk = query_id(dbname, tablename, sac_as, sac_gs_s, MASTER_KEY_AS_GS, ACTIVE);
        if (qr_mk.count != 1)
        {
            printf("Query mkid failed.\n");
            return LD_ERR_KM_QUERY;
        }
        // printf("Query mkid OK.\n");

        // 查询待更新密钥信息
        QueryResult_for_update qfu_masterkey = query_for_update(dbname, tablename, qr_mk.ids[0]);
        if (qfu_masterkey.key_len <= 0 || qfu_masterkey.update_cycle <= 0 || qfu_masterkey.update_count < 0)
        {
            printf("Query mk info failed.\n");
            return LD_ERR_KM_QUERY;
        }
        // printf("Query mk info OK.\n");

        // 查询NH密钥id
        QueryResult_for_queryid qr_NH = query_id(dbname, tablename, sac_as, sac_gs_s, NH_KEY, ACTIVE);
        if (qr_NH.count != 1)
        {
            printf("Query id_NH failed.\n");
            return LD_ERR_KM_QUERY;
        }
        // printf("Query id_NH OK.\n");

        // 查询NH密钥值
        QueryResult_for_keyvalue query_NH = query_keyvalue(dbname, tablename, qr_NH.ids[0]);
        if (!query_NH.key)
        {
            printf("Key NH value not found or error occurred.\n");
            return LD_ERR_KM_QUERY;
        }
        // printf("Query NH info OK.\n");

        // 计算新的NH密钥值 : NH = kdf(kas-sgw,NH')
        /*计算新的NH密钥值 : NH = kdf(kas-sgw,NH')*/

        // 查询主密钥Kas-sgw的id

        QueryResult_for_queryid qr_assgw = query_id(dbname, tablename, sac_as, sac_sgw, MASTER_KEY_AS_SGW, ACTIVE); // AS端

        if (qr_assgw.count != 1)
        {
            printf("Query kassgw failed.\n");
            return LD_ERR_KM_QUERY;
        }
        // printf("qr_assgw OK. kid_assgw = %s\n", qr_assgw.ids[0]);

        // 获取主密钥Kas-sgw句柄
        CCARD_HANDLE handle_asasw;
        if (get_handle_from_db(dbname, tablename, qr_assgw.ids[0], &handle_asasw) != LD_KM_OK)
        {
            printf("get_handle_from_db failed\n");
            return LD_ERR_KM_GET_HANDLE;
        }
        // printf("get_handle_from_db OK\n");

        // 重新计算NH
        km_keypkg_t *keypkg_NH; // 更新的NH
        keypkg_NH = derive_key(handle_asasw, NH_KEY, query_NH.key_len, sac_sgw, sac_as, query_NH.key, query_NH.key_len, NULL);
        if (keypkg_NH == NULL)
        {
            printf("derive keypkg_NH failed\n");
            return LD_ERR_KM_DERIVE_KEY;
        }
        // printf("derive keypkg_NH OK\n");

        // 存储NH密钥值
        if (alter_keyvalue(dbname, tablename, qr_NH.ids[0], keypkg_NH->meta_data->length, keypkg_NH->key_cipher) != LD_KM_OK)
        {
            printf("alter keyvalue failed\n");
            return LD_ERR_KM_ALTERDB;
        }
        // printf("store NH keyvalue OK\n");

        // NH 更新计数器自增
        if (increase_updatecount(dbname, tablename, qr_NH.ids[0]) != LD_KM_OK)
        {
            printf("increase update count failed\n");
            return LD_ERR_KM_ALTERDB;
        }
        // printf("increase update count OK\n");

        // 生成 kas-gs = kdf(NH, rand)
        uint8_t rand[32];
        uint32_t rand_len;
        if (km_hmac(nonce, len_nonce, sac_gs_t, sizeof(sac_gs_t), rand, &rand_len) != LD_KM_OK) // rand = hmac(sacgs-t,nonce)
        {
            printf("km_hmac failed\n");
            return LD_ERR_KM_HMAC;
        }

        CCARD_HANDLE handle_NH;
        if (get_handle_from_db(dbname, tablename, qr_NH.ids[0], &handle_NH) != LD_KM_OK)
        {
            printf("get keyhandle from db failed\n");
            return LD_ERR_KM_QUERY;
        }

        km_keypkg_t *keypkg_Kasgs;
        keypkg_Kasgs = derive_key(handle_NH, MASTER_KEY_AS_GS, qfu_masterkey.key_len, sac_as, sac_gs_t, rand, rand_len, NULL);
        if (keypkg_Kasgs == NULL)
        {
            printf("kasgs derive failed\n");
            return LD_ERR_KM_DERIVE_KEY;
        }
        // printf("kasgs derive OK\n");

        // 存储更新的主密钥
        if (store_key(dbname, tablename, keypkg_Kasgs, &test_km_desc) != LD_KM_OK)
        {
            printf("store_key failed.\n");
            return LD_ERR_KM_ALTERDB;
        }
        // printf("store master key OK.\n");

        // 会话密钥更新
        if (km_update_sessionkey(dbname, tablename, qr_mk.ids[0], sac_as, sac_gs_t, len_nonce, nonce) != LD_KM_OK)
        {
            printf("update masterkey %s's sessionkey failed\n", qr_mk.ids[0]);
            return LD_ERR_KM_UPDATE_SESSIONKEY;
        }
        printf("update masterkey %s's sessionkey OK\n", qr_mk.ids[0]);

        // 将原密钥的状态改为已经撤销
        if (alter_keystate(dbname, tablename, qr_mk.ids[0], SUSPENDED) != LD_KM_OK)
        {
            printf("alter keystate failed\n");
            return LD_ERR_KM_ALTERDB;
        }
        // printf("alter masterkey state OK\n");

    } while (0);

    return LD_KM_OK;
}


/**
 * @brief 撤销密钥及其派生密钥
 */
l_km_err km_revoke_key(uint8_t *dbname, uint8_t *tablename, uint8_t *id)
{

    // 查询子密钥
    QueryResult_for_subkey result = query_subkey(dbname, tablename, id, query_keytype(dbname, tablename, id));
    for (int i = 0; i < result.count; ++i)
    {
        if (alter_keystate(dbname, tablename, result.subkey_ids[i], SUSPENDED) != LD_KM_OK)
        {
            return LD_ERR_KM_ALTERDB;
        }
        printf("revoke key %s succeeded.\n", result.subkey_ids[i]);
        free(result.subkey_ids[i]);
    }

    // 撤销密钥
    if (alter_keystate(dbname, tablename, id, SUSPENDED) != LD_KM_OK)
    {
        return LD_ERR_KM_ALTERDB;
    }
    // printf("revoke key %s succeeded.\n", id_mk);

    return LD_KM_OK;
}

/**
 * @brief GS端安装主密钥 派生会话密钥
 */
l_km_err km_install_key(uint8_t *dbname, uint8_t *tablename, uint32_t key_len, uint8_t *key, uint8_t *sac_as, uint8_t *sac_gs, uint32_t nonce_len, uint8_t *nonce)
{
    do
    {
        // 如果不存在，先创建表
        uint8_t *primary_key = "id";
        if (create_table_if_not_exist(&test_km_desc, dbname, tablename, primary_key) != LD_KM_OK)
        {
            printf("create table err\n");
            break;
        }

        // 生成密钥描述信息
        uint32_t update_cycle = 365;
        km_keymetadata_t *md = km_key_metadata_new(sac_as, sac_gs, MASTER_KEY_AS_GS, key_len, update_cycle); // TODO: 更新周期待确定
        km_keypkg_t *pkg = km_key_pkg_new(md, key, TRUE);
        pkg->meta_data->state = ACTIVE;

        // 存入数据库
        if (store_key(dbname, tablename, pkg, &test_km_desc) != LD_KM_OK)
        {
            printf("store_key failed: %d\n");
            break;
        }
        key_pkg_free(pkg);

        // 查询主密钥id
        QueryResult_for_queryid qr_mk = query_id(dbname, tablename, sac_as, sac_gs, MASTER_KEY_AS_GS, ACTIVE);
        if (qr_mk.count == 0)
        {
            printf("NULL Query.\n");
            return 0;
        }
        else if (qr_mk.count > 1)
        {
            printf("query id not unique.\n");
            return 0;
        }

        // 查询主密钥句柄
        CCARD_HANDLE handle_mk;
        if (get_handle_from_db(dbname, tablename, qr_mk.ids[0], &handle_mk) != LD_KM_OK)
        {
            printf("get_handle_from_db failed\n");
            break;
        }

        // 派生会话密钥
        enum KEY_TYPE key_types[4];
        key_types[0] = SESSION_KEY_USR_ENC;
        key_types[1] = SESSION_KEY_USR_INT;
        key_types[2] = SESSION_KEY_CONTROL_ENC;
        key_types[3] = SESSION_KEY_CONTROL_INT;

        uint32_t sessionkey_len = 16;
        for (int i = 0; i <= 3; i++)
        {
            pkg = derive_key(handle_mk, key_types[i], sessionkey_len, sac_as, sac_gs, nonce, nonce_len, NULL);
            if (pkg == NULL)
            {
                printf("dervie key failed\n");
                break;
            }
            if (store_key(dbname, tablename, pkg, &test_km_desc) != LD_KM_OK)
            {
                printf("store_key failed: %d\n");
                break;
            }
            key_pkg_free(pkg);
        }

        return LD_KM_OK;

    } while (0);

    return LD_ERR_KM_INSTALL_KEY;
}


/************
 * 密钥存储 *
 ************/

// 将keypkg写入文件
l_km_err write_keypkg_to_file(const char *filename, km_keypkg_t *pkg)
{
    do
    {
        FILE *file = fopen(filename, "w");
        if (file == NULL)
        {
            printf("open file %s failed.\n", filename);
            return LD_ERR_KM_WRITE_FILE;
        }

        // Write metadata
        if (fwrite(pkg->meta_data, sizeof(km_keymetadata_t), 1, file) != 1)
        {
            printf("write metadata failed.\n");
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
km_keypkg_t *read_keypkg_from_file(const char *filename)
{
    // 参数检查
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        return NULL;
    }

    // Read metadata
    km_keymetadata_t *meta_data = malloc(sizeof(km_keymetadata_t));
    if (fread(meta_data, sizeof(km_keymetadata_t), 1, file) != 1)
    {
        fclose(file);
        return NULL;
    }

    km_keypkg_t *pkg = km_key_pkg_new(meta_data, NULL, FALSE);

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
    //     printf("integrity check failed!\n");
    //     return NULL;
    // }

    // 关闭文件
    fclose(file);

    return pkg;
}

/*********************************************************
 *                     输出格式控制                      *
 ********************************************************/
// Function to convert error code to string
const char *km_error_to_string(l_km_err err_code)
{
    switch (err_code)
    {
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
    case LD_ERR_KM_ROOTKEY_VERIFY:
        return "Root key verification error";
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
    case SESSION_KEY_CONTROL_ENC:
        printf("SESSION_KEY_CONTROL_ENC (KCENC)\n");
        break;
    case SESSION_KEY_CONTROL_INT:
        printf("SESSION_KEY_CONTROL_INT (KCINT)\n");
        break;
    case GROUP_KEY_BC:
        printf("GROUP_KEY_BC (KBC)\n");
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
    printbuff("Key ", key_pkg->key_cipher, key_pkg->meta_data->length);
    printf("Check Algorithm: %s\n", chck_algo_str(key_pkg->chck_alg));
    printbuff("IV", key_pkg->iv, key_pkg->iv_len);
    printbuff("Check value", key_pkg->chck_value, key_pkg->chck_len);

    return LD_KM_OK;
}


/**
 * 输入枚举类型的密钥类型 返回对应的字符串
 * @param[in] type 密钥类型
 * @return 密钥类型对应的字符串
 */
uint8_t *ktype_str(enum KEY_TYPE type)
{
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
enum KEY_TYPE str_to_ktype(const char *str)
{
    if (strcmp(str, "ROOT_KEY") == 0)
    {
        return ROOT_KEY;
    }
    else if (strcmp(str, "MASTER_KEY_AS_SGW") == 0)
    {
        return MASTER_KEY_AS_SGW;
    }
    else if (strcmp(str, "MASTER_KEY_AS_GS") == 0)
    {
        return MASTER_KEY_AS_GS;
    }
    else if (strcmp(str, "SESSION_KEY_USR_ENC") == 0)
    {
        return SESSION_KEY_USR_ENC;
    }
    else if (strcmp(str, "SESSION_KEY_USR_INT") == 0)
    {
        return SESSION_KEY_USR_INT;
    }
    else if (strcmp(str, "SESSION_KEY_CONTROL_ENC") == 0)
    {
        return SESSION_KEY_CONTROL_ENC;
    }
    else if (strcmp(str, "SESSION_KEY_CONTROL_INT") == 0)
    {
        return SESSION_KEY_CONTROL_INT;
    }
    else if (strcmp(str, "GROUP_KEY_KBC") == 0)
    {
        return GROUP_KEY_BC;
    }
    else if (strcmp(str, "GROUP_KEY_KCC") == 0)
    {
        return GROUP_KEY_CC;
    }
    else if (strcmp(str, "NH KEY") == 0)
    {
        return NH_KEY;
    }
}

/**
 * @brief 返回密钥状态 枚举转字符串
 * @param[in] state 密钥状态 枚举类型
 * @return 密钥状态字符串
 */
uint8_t *kstate_str(enum STATE state)
{
    switch (state)
    {
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

/**
 * @brief 校验算法解析
 * @param[in] chck_algo 校验算法(int类型)
 * @return 校验算法
 */
uint8_t *chck_algo_str(uint16_t chck_algo)
{
    switch (chck_algo)
    {
    case ALGO_ENC_AND_DEC:
        return ("SGD_SM4_CFB");
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


/**
 * @brief 十六进制字符串转换回字节序列
 * @param[in] hex_str
 * @return 字节序列
 */
uint8_t *hex_to_bytes(const char *hex_str)
{

    size_t len = strlen(hex_str);
    uint8_t *bytes = malloc(sizeof(uint8_t) * len / 2); // 原始字节数据的长度是字符串长度的一半
    for (size_t i = 0; i < len; i += 2)
    {
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
uint8_t *bytes_to_hex(uint16_t bytes_len, uint8_t *bytes)
{
    uint8_t *hex_str;
    hex_str = malloc(sizeof(uint8_t) * bytes_len * 2);
    for (int i = 0; i < bytes_len; i++)
    {
        sprintf(hex_str + i * 2, "%02X", bytes[i]);
    }
    return hex_str;
}

/**结构体初始化和销毁释放*/

// 外部接口
km_keymetadata_t *km_key_metadata_new(const char *owner_1, const char *owner_2, enum KEY_TYPE key_type, uint32_t key_len, uint16_t update_day)
{
    km_keymetadata_t *keydata = malloc(sizeof(km_keymetadata_t)); // 初始化分配空间
    uint8_t null_array[MAX_OWENER_LEN] = {0};
    memcpy(keydata->owner_1, null_array, MAX_OWENER_LEN);
    memcpy(keydata->owner_2, null_array, MAX_OWENER_LEN);

    uuid_t uuid;
    uuid_generate(uuid);

    uuid_copy(keydata->id, uuid);
    memcpy(keydata->owner_1, owner_1, strlen(owner_1));
    memcpy(keydata->owner_2, owner_2, strlen(owner_2));
    keydata->key_type = key_type;
    keydata->length = key_len;
    keydata->state = PRE_ACTIVATION;
    keydata->update_cycle = update_day;
    time(&keydata->creation_time);

    return keydata;
}

// 外部接口
km_keypkg_t *km_key_pkg_new(km_keymetadata_t *meta, uint8_t *key, bool is_encrypt)
{
    km_keypkg_t *keypkg = malloc(sizeof(km_keypkg_t));

    memset(keypkg, '\0', sizeof(km_keypkg_t));

    keypkg->meta_data = meta;

    if (key != NULL)
    { // 如果传入明文密钥 对其加密存储并存入控制信息
        if (is_encrypt)
        {
            do
            {
                uint32_t kek_index = 1;
                CCARD_HANDLE kek_handle;
                /* 生成KEK */
                if (km_generate_key_with_kek(kek_index, 16, &kek_handle, keypkg->kek_cipher, &keypkg->kek_cipher_len))
                {
                    printf("Error in derive : SDF_GenerateKeyWithKEK failed!\n");
                    break;
                }

                // 生成和存储IV
                keypkg->iv_len = 16;
                uint8_t iv_mac[16];
                uint8_t iv_enc[16];
                if (km_generate_random(keypkg->iv, keypkg->iv_len))
                {
                    break;
                }
                memcpy(iv_mac, keypkg->iv, keypkg->iv_len); // 加密和Mac使用同一个密钥
                memcpy(iv_enc, keypkg->iv, keypkg->iv_len);

                /* 主密钥加密 */
                uint32_t cipher_len;
                if (km_encrypt(kek_handle, ALGO_ENC_AND_DEC, iv_enc, key, meta->length, keypkg->key_cipher, &cipher_len))
                {
                    printf("Error in derive : SDF_Encrypt failed!\n");
                    break;
                }

                /* 校验算法 */
                if (km_mac(kek_handle, ALGO_MAC, iv_mac, keypkg->key_cipher, cipher_len, keypkg->chck_value, &keypkg->chck_len))
                {
                    printf("Error in derive : SDF_CalculateMAC failed!\n");
                    break;
                }
                keypkg->chck_alg = ALGO_MAC;

            } while (0);
        }
        else
        {
            do
            {
                uint32_t kek_index = 1;
                CCARD_HANDLE kek_handle;
                memset(keypkg->kek_cipher, 0, 16);
                keypkg->kek_cipher_len = 0;

                // 生成和存储IV
                keypkg->iv_len = 16;
                uint8_t iv_mac[16];
                uint8_t iv_enc[16];
                if (km_generate_random(keypkg->iv, keypkg->iv_len))
                {
                    break;
                }
                memcpy(iv_mac, keypkg->iv, keypkg->iv_len); // 加密和Mac使用同一个密钥
                memcpy(iv_enc, keypkg->iv, keypkg->iv_len);

                /* 主密钥 */
                memcpy(keypkg->key_cipher, key, keypkg->meta_data->length);

                /* 校验 */
                if (km_hash(ALGO_HASH, keypkg->key_cipher, keypkg->meta_data->length, keypkg->chck_value))
                {
                    printf("Error in derive : SDF_CalculateHash failed!\n");
                    break;
                }
                keypkg->chck_alg = ALGO_HASH;
                keypkg->chck_len = 32;

            } while (0);
        }
    }
    return keypkg;
}

// 外部接口
void key_pkg_free(km_keypkg_t *pkg)
{
    if (pkg == NULL)
        return;
    if (pkg->meta_data != NULL)
    {
        free(pkg->meta_data);
    }
    free(pkg);
}


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

static l_km_err output_enc_key(CCARD_HANDLE hSessionHandle, km_keypkg_t *keypkg, const char *export_raw_path)
{
    // 使用本地密钥加密和完整性保护存储
    uint32_t kek_index = 1;
    CCARD_HANDLE kek_handle;
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
 
km_keypkg_t *km_import_rootkey(CCARD_HANDLE *rootkey_handle, const char *import_bin_path, const char *import_raw_path)
{
    // 输出参数赋予空间
    CCARD_HANDLE DeviceHandle, hSessionHandle;
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
            printf("root key integrity check Wrong\n");
            break;
        }
        pkg->chck_alg = ALGO_HASH;
        // printbuff("HASH", hashed_rootkey, pkg->chck_len);

        // 返回根密钥句柄
        if (SDF_ImportKey(hSessionHandle, pkg->key_cipher, pkg->meta_data->length, rootkey_handle) != SDR_OK)
        {
            printf("import rootkey failed\n");
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

    CCARD_HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);
    SDF_OpenSession(DeviceHandle, &hSessionHandle);

    // 网关密码卡生成随机数作为根密钥
    SDF_GenerateRandom(hSessionHandle, keymeta->length,
                       keypkg->key_cipher);

    keypkg->chck_len = 32;
    km_hash(ALGO_HASH, keypkg->key_cipher, keymeta->length, keypkg->chck_value);

    // printbuff("HASH", keypkg->chck_value, keypkg->chck_len);

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
l_km_err km_get_rootkey_handle(CCARD_HANDLE *rootkey_handle, const char *filepath)
{
    CCARD_HANDLE DeviceHandle, pSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄

    // 从文件区读取根密钥

    km_keypkg_t *restored_pkg = read_keypkg_from_file(filepath);
    // km_keypkg_t *restored_pkg = read_keypkg_from_file(filepath);
    if (restored_pkg == NULL)
    {
        printf("Error reading from file\n");
        return LD_ERR_KM_READ_FILE;
    }
    // print_key_pkg(&restored_pkg);

    // 根密钥使用-校验密钥完整性
    uint32_t kek_index = 1;
    CCARD_HANDLE kek_handle;
    // 导入密钥加密密钥
    if (SDF_ImportKeyWithKEK(pSessionHandle, ALGO_WITH_KEK, kek_index, restored_pkg->kek_cipher,
                             restored_pkg->kek_cipher_len, &kek_handle) != LD_KM_OK)
    {
        printf("get key handle : import kek failed!\n");
        return LD_ERR_KM_IMPORT_KEY_WITH_KEK;
    }

    uint8_t mac_value[32] = {0};
    uint32_t mac_len;
    SDF_CalculateMAC(pSessionHandle, kek_handle, ALGO_MAC, restored_pkg->iv, restored_pkg->key_cipher,
                     restored_pkg->meta_data->length,
                     mac_value, &mac_len);
    if (memcmp(mac_value, restored_pkg->chck_value, mac_len) != 0)
    {
        printf("root key integrity Wrong\n");
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

#endif