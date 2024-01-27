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

int count;

/*********************************************************
 *                     输出格式控制                      *
 ********************************************************/
// 打印字符串
l_err printbuff(const char *printtitle, uint8_t *buff, int len)
{
    if (buff == NULL)
    {
        printf("error: printbuff NULL pamameter\n");
        return LD_ERR_KM_PARAMETERSERR_NULL;
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
    return LD_OK;
}

// 展示kekpkg中的内容
l_err print_kek_pkg(struct KEKPkg *kek_pkg)
{
    if (kek_pkg == NULL)
    {
        // 输入指针为空，无法打印
        return LD_ERR_KM_PARAMETERSERR_NULL;
    }

    // 打印 rcver
    printf("reciever name: %s \n", kek_pkg->rcver);

    // 打印 key_len
    printf("Key Length: %u\n", kek_pkg->key_len);
    printbuff("Key", kek_pkg->key, kek_pkg->key_len);

    // 打印 chck_len
    printf("Check Length: %d\n", kek_pkg->chck_len);
    printbuff("Check Value", kek_pkg->chck_value, kek_pkg->chck_len);

    return LD_OK;
}

// 逐行打印密钥信息结构体
l_err print_key_metadata(struct KeyMetaData *key_info)
{
    printf("ID: %u\n", key_info->id);

    printf("Type: ");

    switch (key_info->type)
    {
    case ROOT_KEY:
        printf("ROOT_KEY (KAS)\n");
        break;
    case MASTER_KEY_AS_SGW:
        printf("MASTER_KEY_AS_SGW (KASSGW)\n");
        break;
    case MASTER_KEY__AS_GS:
        printf("MASTER_KEY__AS_GS (KASGS)\n");
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
    case LOCAL_HMAC_KEY:
        printf("LOCAL_HMAC_KEY \n");
        break;
    default:
        printf("Unknown KEY_TYPE\n");
    }

    printf("Owner 1: %s\n", key_info->owner_1);
    printf("Owner 2: %s\n", key_info->owner_2);
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
    struct tm *timeinfo = localtime(&key_info->effectuation_time);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    printf("Effectuation Time: %s\n", buffer);
    printf("Update Cycle: %lld days \n", (long long)key_info->update_cycle);
    // printf("Counter: %u\n", key_info->counter);

    return LD_OK;
}

// 逐行打印key_pkg结构体
l_err print_key_pkg(struct KeyPkg *key_pkg)
{
    if (key_pkg == NULL)
    {
        // 处理错误，输入参数为空或者关键结构体为空
        printf("NULL key_pkg  for print_key_pkg function.\n");
        return LD_ERR_KM_PARAMETERSERR_NULL;
    }
    else if (key_pkg->meta_data == NULL)
    {
        // 处理错误，输入参数为空或者关键结构体为空
        printf("NULL meta_data for print_key_pkg function.\n");
        return LD_ERR_KM_PARAMETERSERR_NULL;
    }

    print_key_metadata(key_pkg->meta_data);
    printbuff("key ", key_pkg->key, key_pkg->meta_data->length);
    printf("Check Algorithm: ");
    switch (key_pkg->chck_alg)
    {
    case SGD_SM4_CFB:
        printf("SGD_SM4_CFB\n");
        break;
    case SGD_SM4_MAC:
        printf("SGD_SM4_MAC\n");
        break;
    default:
        printf("unknown\n");
        break;
    }
    printf("Check Length: %d\n", key_pkg->chck_len);
    printbuff("check value", key_pkg->chk_value, key_pkg->chck_len);

    return LD_OK;
}

/*********************************************************
 *                     基础密码运算功能                  *
 ********************************************************/

// 生成随机数
l_err generate_random(int len, uint8_t *random_data)
{
    HANDLE DeviceHandle, pSessionHandle;
    int ret;

    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }

    ret = SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    ret = SDF_GenerateRandom(pSessionHandle, len, random_data);
    if (ret != LD_OK)
    {
        printf("SDF_GenerateRandom Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_GENERATE_RANDOM;
    }
    // printbuff("random_data", random_data, len);
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_OK;
}

// 国密算法加密接口
l_err encrypt_with_domestic_algo(void *key_handle, unsigned int alg_id, uint8_t *iv, uint8_t *data, unsigned int data_length, uint8_t *cipher_data, unsigned int *cipher_data_len)
{
    HANDLE DeviceHandle, pSessionHandle;
    HANDLE phKeyHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }

    ret = SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    // 调用SDF_Encrypt函数
    int result = SDF_Encrypt(pSessionHandle, key_handle, alg_id, iv, data, data_length, cipher_data, cipher_data_len);
    if (result != LD_OK)
    {
        printf("SDF_Encrypt with phKeyHandle error!ret is %08x \n", result);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_ENCRYPT_WITH_DOMESTIC_ALGO;
    }
    return LD_OK;
}

// 国密算法解密
l_err decrypt_with_domestic_algo(void *key_handle, unsigned int alg_id, uint8_t *iv, uint8_t *cipher_data, unsigned int cipher_data_len, uint8_t *plain_data, unsigned int *plain_data_len)
{
    HANDLE DeviceHandle, pSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄

    // 调用SDF_Dncrypt函数

    int result = SDF_Decrypt(pSessionHandle, key_handle, alg_id, iv, cipher_data, cipher_data_len, plain_data, plain_data_len);
    if (result != LD_OK)
    {
        printf("SDF_Decrypt with phKeyHandle error!ret is %08x \n", result);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_DECRYPT_WITH_DOMESTIC_ALGO;
    }
    return LD_OK;
}

// sm3_hash算法
l_err hash(unsigned int alg_id, uint8_t *data, size_t data_len, uint8_t *output)
{
    HANDLE DeviceHandle, pSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    uint8_t hashResult[32];
    unsigned int hashResultLen = 32;

    ret = SDF_HashInit(pSessionHandle, SGD_SM3, NULL, NULL, 0);
    if (ret != LD_OK)
    {
        printf("SDF_HashInit Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_HashInit;
    }

    ret = SDF_HashUpdate(pSessionHandle, data, data_len);
    if (ret != LD_OK)
    {
        printf("SDF_HashUpdate Function failure! %08x \n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_HashUpdate;
    }

    ret = SDF_HashFinal(pSessionHandle, hashResult, &hashResultLen);
    if (ret != LD_OK)
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
    return LD_OK;
}

// MAC运算 SM4_CFB
l_err mac(void *key_handle, unsigned int alg_id, uint8_t *iv, uint8_t *data, unsigned int data_length, uint8_t *mac, unsigned int *mac_length)
{
    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    int ret = SDF_CalculateMAC(hSessionHandle, key_handle, alg_id, iv, data, data_length, mac, mac_length);
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    if (ret != LD_OK)
    {
        printf("SDF_CalculateMACZ with phKeyHandle error!ret is %08x \n", ret);
        return LD_ERR_KM_MAC;
    }

    return LD_OK;
}

// 国密hmac算法
l_err sm3_hmac(uint8_t *key, uint32_t key_len, uint8_t *data, uint32_t data_len, uint8_t *hmac_data, uint32_t *hmac_data_len)
{
    // 在这里进行参数检查
    if (hmac_data == NULL)
    {
        printf("hmac_data has not been initalized\n");
        return LD_ERR_KM_PARAMETERSERR_NULL;
    }
    HANDLE DeviceHandle, hSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    // 调用已有接口 SDFE_Hmac
    ret = SDFE_Hmac(hSessionHandle, key, key_len, data, data_len, hmac_data, hmac_data_len);
    if (ret != LD_OK)
    {
        printf("SDFE_Hmac with phKeyHandle error!ret is %08x \n", ret);
        return LD_ERR_KM_SM3HMAC;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_OK;
}

/*********************************************************
 *                     基础密钥管理功能                  *
 ********************************************************/
// 生成KEK
l_err generate_kek(unsigned int key_bits_len, unsigned int key_index)
{
    HANDLE DeviceHandle, hSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    int generate_ret = SDFE_GenerateKEK(hSessionHandle, key_bits_len, key_index);
    if (generate_ret != LD_OK)
    {
        printf("SDFE_GenerateKEK failed \n");
        return LD_ERR_KM_GENERATE_KEK;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_OK; ///////////////////////////////////////
}

// 导出KEK
l_err export_kek(unsigned int key_index, void *key, unsigned int *key_len)
{
    HANDLE DeviceHandle, hSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    int export_ret = SDFE_ExportKEK(hSessionHandle, key_index, key, key_len);
    if (export_ret != LD_OK)
    {
        printf("SDFE_ExportKEK failed \n");
        return LD_ERR_KM_EXPORT_KEK;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_OK;
}

// 导入KEK
l_err import_kek(unsigned int key_index, void *key, unsigned int key_len)
{
    HANDLE DeviceHandle, hSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    // import kek
    int result = SDFE_ImportKEK(hSessionHandle, key_index, key, key_len);
    if (result != LD_OK)
    {
        printf("kek has NOT been imported to index %d", key_index);
        return LD_ERR_KM_IMPORT_KEK;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_OK;
}

// 导入明文密钥
l_err import_key(uint8_t *key, unsigned int key_length, void **key_handle)
{
    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    int ret = SDF_ImportKey(hSessionHandle, key, key_length, key_handle);
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    if (ret != LD_OK)
    {
        printf("SDF_ImportKey with phKeyHandle error!ret is %08x \n", ret);
        return LD_ERR_KM_IMPORT_KEY;
    }

    return LD_OK;
}

// 销毁密钥
l_err destroy_key(void *key_handle)
{
    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    int ret = SDF_DestroyKey(hSessionHandle, key_handle);
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    if (ret != LD_OK)
    {
        printf("SDF_DestroyKey with phKeyHandle error!ret is %08x \n", ret);
        return LD_ERR_KM_DESTROY_KEY;
    }

    return LD_OK;
}

// 基于口令的密钥派生
l_err pbkdf2(uint8_t *password, uint32_t password_len, uint8_t *salt, uint32_t salt_len, uint32_t iterations, uint32_t derived_key_len, uint8_t *derived_key)
{
    // 参数检查
    if (password == NULL || salt == NULL)
    {
        printf("pbkdf2 fail , password and salt shouldn't be NULL\n");
        return LD_ERR_KM_PARAMETERSERR_NULL;
    }
    if (salt_len < 4) // 参数检查 盐值长度不能小于4字节
    {
        printf("pbkdf2 fail , salt len should over 4 byte\n");
        return LD_ERR_KM_PARAMETERSERR_PBKDF2;
    }
    if (iterations < 1024)
    {
        printf("pbkdf2 fail , iterations should over 1024 times\n");
        return LD_ERR_KM_PARAMETERSERR_PBKDF2;
    }
    if (derived_key_len != 16 && derived_key_len != 32 && derived_key_len != 48 && derived_key_len != 64)
    {
        printf("pbkdf2 fail for illegal key len, 16/32/48/64 bytes are permitted\n");
        return LD_ERR_KM_PARAMETERSERR_PBKDF2;
    }

    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    uint32_t dkLen = derived_key_len;
    uint32_t hLen = 32;                     // 按照16byte分块
    uint32_t l = (dkLen + hLen - 1) / hLen; // ceil(dkLen/hLen) 迭代次数
    uint8_t *t = malloc(hLen * sizeof(uint8_t));
    uint8_t *u = malloc((salt_len + 4) * sizeof(uint8_t));
    uint8_t *xorsum = malloc(dkLen * sizeof(uint8_t));
    if (t == NULL || u == NULL || xorsum == NULL)
    {
        perror("Memory allocation failed");
        free(t);
        free(u);
        free(xorsum);
        return LD_ERR_KM_MEMORY_ALLOCATION_IN_PBKDF2;
    }

    for (uint32_t i = 1; i <= l; i++) // 迭代计算每块
    {
        // Compute U_1 = PRF(password, salt || INT(i))
        memcpy(u, salt, salt_len);
        u[salt_len + 0] = (i >> 24) & 0xFF;
        u[salt_len + 1] = (i >> 16) & 0xFF;
        u[salt_len + 2] = (i >> 8) & 0xFF;
        u[salt_len + 3] = i & 0xFF;

        if (SDFE_Hmac(hSessionHandle, password, password_len, u, salt_len + 4, t, &hLen) != 0)
        {
            perror("SM3-HMAC computation failed");
            free(t);
            free(u);
            free(xorsum);
            return LD_ERR_KM_SM3HMAC;
        }

        // U_2 = U_1, U_3 = U_2, ..., U_l = U_{l-1}
        memcpy(xorsum, t, hLen);

        for (uint32_t j = 2; j <= iterations; j++)
        {
            if (SDFE_Hmac(hSessionHandle, password, password_len, t, hLen, t, &hLen) != 0)
            {
                perror("SM3-HMAC computation failed");
                free(t);
                free(u);
                free(xorsum);
                return LD_ERR_KM_PBKDF2;
            }

            // U_2 xor U_3 xor ... xor U_l
            for (uint32_t k = 0; k < hLen; k++)
            {
                xorsum[k] ^= t[k];
            }
        }

        // Copy the derived key block to the output
        // printbuff("xorsum", xorsum, derived_key_len);
        uint32_t copy_len = (i == l && dkLen % hLen != 0) ? (dkLen % hLen) : hLen;
        // printf("copy len %d ,(i - 1) * hLen:(%d -1) * %d\n", copy_len, i, hLen);
        memcpy(derived_key + (i - 1) * hLen, xorsum, copy_len);
        // printbuff("pbkdf2 output", derived_key, derived_key_len);
    }

    free(t);
    free(u);
    free(xorsum);
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_OK;
}

/*********************************************************
 *                     业务逻辑接口                      *
 ********************************************************/
// 密钥派生
l_err derive_key_assgw(void *root_key_handle, uint32_t key_len, uint8_t *id_as, uint32_t id_as_len, uint8_t *id_sgw, uint32_t id_sgw_len, uint8_t *shared_info, uint32_t shared_info_len, void *key_assgw_handle, struct KeyMetaData *key_info)
{
    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    uint8_t id_sgw_hash[32];
    uint8_t id_as_hash[32];
    uint8_t *password = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    uint32_t password_len;
    uint8_t *key_assgw = (uint8_t *)malloc(sizeof(uint8_t) * (key_len / 16));
    time_t current_time;

    // 检查输入参数是否为空
    if (key_info == NULL)
    {
        key_info = (struct KeyMetaData *)malloc(sizeof(struct KeyMetaData));
    }
    if (id_as == NULL || id_sgw == NULL || shared_info == NULL)
    {
        return LD_ERR_KM_PARAMETERSERR_NULL;
    }

    // 初始化密钥元数据
    key_info->id = get_key_id();
    key_info->type = MASTER_KEY_AS_SGW;
    memcpy(key_info->owner_1, id_as, id_as_len);
    memcpy(key_info->owner_2, id_sgw, id_sgw_len);
    printf("key len %d\n", key_len);
    key_info->length = key_len;
    key_info->state = PRE_ACTIVATION;
    key_info->effectuation_time = time(&current_time);
    key_info->update_cycle = 365; // 单位 天
    // key_info->counter = 0;

    // 派生密钥：id_sgw_hash作为iv，使用根密钥对id_as_hash加密的结果作为password 共享协商信息shared_info作为salt 输入pbkdf2后派生出密钥
    hash(SGD_SM3, id_sgw, id_sgw_len, id_sgw_hash);
    hash(SGD_SM3, id_as, id_as_len, id_as_hash);
    SDF_Encrypt(hSessionHandle, root_key_handle, SGD_SM4_CFB, id_sgw_hash, id_as_hash, 32, password, &password_len);
    // printbuff("password", password, password_len);
    pbkdf2(password, password_len, shared_info, shared_info_len, 1024, key_len, key_assgw); // 使用SM3-HMAC作为密钥派生的PRF，迭代次数1024次。
    printbuff("key_assgw", key_assgw, key_len);

    // 导入密钥 返回密钥句柄
    void *temp_handle;
    import_key(key_assgw, key_len, &temp_handle);

    printf("key as-sgw has been imported to pci-e crypto-card\n");

    // 销毁内存中的密钥 关闭会话
    free(key_assgw);
    free(password);
    printf("key as-sgw has been destructed in memory\n");
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    // 拷贝密钥句柄
    memcpy(key_assgw_handle, temp_handle, sizeof(void *));
    // printf("Key as-sgw syccessfully derived!the Handle is %p\n", temp_handle);

    /*
        // 对导入的密钥做加密测试 对比测试部分主函数的加密输出
        uint8_t iv_enc[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
        uint8_t iv_dec[16] = {0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
        uint8_t data[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                            0x29, 0xbe, 0xe1, 0xd6, 0x52, 0x49, 0xf1, 0xe9, 0xb3, 0xdb, 0x87, 0x3e, 0x24, 0x0d, 0x06, 0x47};
        unsigned int data_len = 32;
        unsigned int alg_id = SGD_SM4_CFB;
        uint8_t cipher_data[32];
        unsigned int cipher_data_len;
        encrypt_with_domestic_algo(key_assgw_handle, alg_id, iv_enc, data, data_len, cipher_data, &cipher_data_len);
        printbuff("cipher data:", cipher_data, cipher_data_len);
        */

    return LD_OK;
}

/************
 * 密钥生成 *
 ***********/

// 获取全局变量count的值并自增
int get_key_id()
{
    return ++count;
}

// 指定KEK索引和密钥元数据（密钥类型，密钥所有者，密钥长度，启用日期，更新周期），初始化元数据并生成密钥、密钥id，输出密钥句柄、使用KEK加密的密钥密文、和密钥元数据结构体。
l_err generate_key_with_kek(int kek_index, struct KeyMetaData *key_info, void **key_handle, uint8_t *cipher_key, int *cipher_len)
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
    key_info->id = get_key_id();
    key_info->state = PRE_ACTIVATION;

    // GenerateKeyWithKEK 128bit SM4-ECB 产生根密钥并用KEK加密导出 此处接口密钥长度单位为bit！！！
    ret = SDF_GenerateKeyWithKEK(pSessionHandle, (key_info->length) * 8, SGD_SM4_ECB, kek_index,
                                 cipher_key, cipher_len, key_handle);
    // printbuff("cipher key",cipher_key,*cipher_len);
    if (ret != LD_OK)
    {
        printf("SDF_GenerateKeyKEK error!return is %08x\n", ret);
        free(cipher_key);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_GENERATE_KEY_WITH_KEK;
    }

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_OK;
}

/************
 * 密钥存储 *
 ************/

// 将密钥及其元数据做标准封装 输出到密钥库文件中
l_err generate_key_pkg(struct KeyMetaData *key_info, uint8_t *cipher_key, uint8_t *mac_iv, void *mac_key_handle, struct KeyPkg *key_pkg)
{
    // 参数检查
    if (key_info == NULL)
    {
        printf("error: parameter key_info is null!\n");
        return LD_ERR_KM_PARAMETERSERR_NULL;
    }
    else if (cipher_key == NULL)
    {
        printf("error: parameter cipher_key is null!\n");
        return LD_ERR_KM_PARAMETERSERR_NULL;
    }
    else if (mac_key_handle == NULL)
    {
        printf("error: parameter mac_key_handle is null!\n");
        return LD_ERR_KM_PARAMETERSERR_NULL;
    }
    // 变量初始化分配空间
    if (key_pkg == NULL)
    {
        key_pkg = malloc(sizeof(struct KeyPkg));
    }

    // 使用hmac计算密钥的校验值
    uint8_t mac_value[32];
    uint32_t mac_len;
    int ret = mac(mac_key_handle, SGD_SM4_CFB, mac_iv, cipher_key, key_info->length, mac_value, &mac_len);
    // printbuff("check value", mac_value, mac_len);

    // 生成标准封装格式密钥包
    key_pkg->meta_data = key_info;
    memcpy(key_pkg->key, cipher_key, key_info->length);
    key_pkg->chck_alg = SGD_SM4_CFB;
    memcpy(key_pkg->chk_value, mac_value, mac_len);
    key_pkg->chck_len = mac_len;

    return LD_OK;
}

// 将kekpkg写入文件：默认在build文件夹下
l_err write_keypkg_to_file(const char *filename, struct KeyPkg *pkg)
{
    // 打开文件
    FILE *file = fopen(filename, "wb");
    if (file == NULL)
    {
        perror("Error opening file");
        return LD_ERR_KM_OPEN_FILE;
    }

    // 写入密钥属性
    fprintf(file, "ID: %d\n", pkg->meta_data->id);
    fprintf(file, "Owner 1: %s\n", pkg->meta_data->owner_1);
    fprintf(file, "Owner 2: %s\n", pkg->meta_data->owner_2);
    fprintf(file, "Type: %d\n", pkg->meta_data->type);
    fprintf(file, "Length: %d bytes\n", pkg->meta_data->length);
    fprintf(file, "State: %d\n", pkg->meta_data->state);
    fprintf(file, "Effectuation Time: %ld\n", pkg->meta_data->effectuation_time);
    fprintf(file, "Update Cycle: %ld days\n", pkg->meta_data->update_cycle);

    // 写入密钥信息
    fprintf(file, "Key: ");
    uint8_t *temp = malloc(sizeof(uint8_t) * pkg->meta_data->length);
    temp = pkg->key;
    for (int i = 0; i < pkg->meta_data->length; i++)
    {
        fprintf(file, "%02X ", temp[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    fprintf(file, "\n");
    fprintf(file, "Checksum Algorithm: %d\n", pkg->chck_alg);
    fprintf(file, "Checksum Length: %d\n", pkg->chck_len);
    fprintf(file, "Checksum Value:");
    uint8_t *buff = malloc(sizeof(uint8_t) * pkg->chck_len);
    buff = pkg->chk_value;
    for (int i = 0; i < pkg->chck_len; i++)
    {
        fprintf(file, "%02X ", buff[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    fprintf(file, "\n");

    fclose(file);

    // 关闭文件
    fclose(file);

    return LD_OK;
}

/*************
 *  KEK预置  *
 ************/
// 将kekpkg写入文件：默认在build文件夹下
l_err write_kekpkg_to_file(const char *filename, struct KEKPkg *pkg)
{
    FILE *file = fopen(filename, "wb");
    if (file == NULL)
    {
        perror("Error opening file for writing");
        return LD_ERR_KM_WRITE_FILE;
        // exit(EXIT_FAILURE);
    }

    // 写入rcver_len
    fwrite(&pkg->rcver_len, sizeof(uint32_t), 1, file);
    // 写入rcver
    fwrite(pkg->rcver, sizeof(uint8_t), pkg->rcver_len, file);

    // 写入key_len
    fwrite(&pkg->key_len, sizeof(uint32_t), 1, file);
    // 写入key
    fwrite(pkg->key, sizeof(uint8_t), pkg->key_len, file);

    // 写入chck_len
    fwrite(&pkg->chck_len, sizeof(uint32_t), 1, file);
    // 写入chck_value
    fwrite(pkg->chck_value, sizeof(uint8_t), pkg->chck_len, file);

    fclose(file);
    return LD_OK;
}

// 从文件读取出kekpkg
l_err read_kdkpkg_from_file(const char *filename, struct KEKPkg *pkg)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        perror("Error opening file for reading");
        return LD_ERR_KM_READ_FILE;
        // exit(EXIT_FAILURE);
    }

    // 读取rcver_len
    fread(&pkg->rcver_len, sizeof(uint32_t), 1, file);
    // 分配内存并读取rcver
    pkg->rcver = malloc(pkg->rcver_len * sizeof(uint8_t));
    fread(pkg->rcver, sizeof(uint8_t), pkg->rcver_len, file);

    // 读取key_len
    fread(&pkg->key_len, sizeof(uint32_t), 1, file);
    // 分配内存并读取key
    pkg->key = malloc(pkg->key_len * sizeof(uint8_t));
    fread(pkg->key, sizeof(uint8_t), pkg->key_len, file);

    // 读取chck_len
    fread(&pkg->chck_len, sizeof(uint32_t), 1, file);
    // 分配内存并读取chck_value
    pkg->chck_value = malloc(pkg->chck_len * sizeof(uint8_t));
    fread(pkg->chck_value, sizeof(uint8_t), pkg->chck_len, file);
    fclose(file);

    // 以写入方式打开文件，这将清空文件内容
    file = fopen(filename, "w");
    uint8_t *hint = "kek has been imported succesfully.";
    fwrite(hint, sizeof(uint8_t), strlen(hint), file);
    fclose(file);

    return LD_OK;
}

// 生成并导出KEK包
l_err generate_and_export_kek(int key_len, int kek_index, uint8_t *rcver, int rcver_len, struct KEKPkg *kek_pkg)
{
    HANDLE DeviceHandle, hSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    // 初始化结构体 分配空间
    kek_pkg->chck_value = (uint8_t *)malloc(32);
    kek_pkg->key = (uint8_t *)malloc(key_len / 16); // bit转字节
    kek_pkg->rcver = (uint8_t *)malloc(rcver_len);
    kek_pkg->rcver_len = rcver_len;
    memcpy(kek_pkg->rcver, rcver, rcver_len);

    int generate_ret = SDFE_GenerateKEK(hSessionHandle, key_len, kek_index);
    if (generate_ret != LD_OK)
    {
        printf("SDFE_GenerateKEK failed \n");
        return LD_ERR_KM_GENERATE_KEK;
    }

    int export_ret = SDFE_ExportKEK(hSessionHandle, kek_index, kek_pkg->key, &kek_pkg->key_len);
    if (export_ret != LD_OK)
    {
        printf("SDFE_ExportKEK failed \n");
        return LD_ERR_KM_EXPORT_KEK;
    }

    sm3_hmac(kek_pkg->key, kek_pkg->key_len, rcver, rcver_len, kek_pkg->chck_value, &kek_pkg->chck_len);
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_OK;
}

// 外部导入KEK：输入本地id验证kek 并导入KEK到指定索引位置
l_err external_import_kek(struct KEKPkg *kek_pkg, int kek_index, uint8_t *local_id, int id_len)
{
    HANDLE DeviceHandle, hSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }
    uint32_t local_chck_len;
    uint8_t local_chck_value[32];

    // verify kek
    if (memcmp(local_id, kek_pkg->rcver, id_len) != 0) // vefiry id
    {
        printf("this kek don't belong to me\n");
        return LD_ERR_KM_EXTERNAL_IMPORT_KEK;
    }
    else
    {
        printf("this kek belongs to me\n");
    }

    sm3_hmac(kek_pkg->key, kek_pkg->key_len, local_id, id_len, local_chck_value, &local_chck_len);
    // printbuff("pkg chck", kek_pkg->chck_value, kek_pkg->chck_len);
    // printbuff("local_chck", local_chck_value, local_chck_len);
    if (memcmp(local_chck_value, kek_pkg->chck_value, local_chck_len) != 0) // vefiry key
    {
        printf("this kek fail to pass hmac verify\n");
        return LD_ERR_KM_EXTERNAL_IMPORT_KEK;
    }
    else
    {
        printf("this kek has passed hmac verify\n");
    }

    // import kek
    int result = SDFE_ImportKEK(hSessionHandle, kek_index, kek_pkg->key, kek_pkg->key_len);
    if (result != LD_OK)
    {
        printf("kek has NOT been imported to index %d", kek_index);
        return LD_ERR_KM_EXTERNAL_IMPORT_KEK;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_OK;
}