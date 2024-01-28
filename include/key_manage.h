/* key management by wencheng in 20240119, uncompleted version.*/
#ifdef GLOBALS
int count;
#else
extern int count;
#endif

#ifndef KEY_MANAGE_H
#define KEY_MANAGE_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdint.h>
#include <unistd.h>
#include <sdf/libsdf.h>
#include <sdfkmt/sdfe-func.h>
#include <sdfkmt/sdfe-type.h>

/*
************************************************************************
*                           结构体声明和别名定义                         *
************************************************************************
*/
// 密钥句柄别名
typedef void *HANDLE;

// 报错码
typedef enum
{
    LD_OK = 0,
    LD_ERR_WRONG_PARA,
    LD_ERR_INTERNAL,
    LD_ERR_WAIT,
    LD_ERR_INVALID,
    LD_ERR_LOCK,
    LD_ERR_NOMEM,
    LD_ERR_THREAD,
    LD_ERR_QUEUE,

    LD_ERR_KM_OPEN_DEVICE,                 // 打开密码设备错误
    LD_ERR_KM_OPEN_SESSION,                // 与设备建立会话失败
    LD_ERR_KM_GENERATE_RANDOM,             // 生成随机数失败
    LD_ERR_KM_HashInit,                    // hash init失败
    LD_ERR_KM_HashUpdate,                  //  hash update失败
    LD_ERR_KM_HashFinal,                   // hash final失败
    LD_ERR_KM_MAC,                         // mac接口运行失败
    LD_ERR_KM_ENCRYPT_WITH_DOMESTIC_ALGO,  // 加密失败
    LD_ERR_KM_DECRYPT_WITH_DOMESTIC_ALGO,  // 解密失败
    LD_ERR_KM_SM3HMAC,                     // hmac失败
    LD_ERR_KM_PARAMETERSERR_PBKDF2,        // pbkdf2参数错误
    LD_ERR_KM_PARAMETERSERR_NULL,          // 接口参数为空
    LD_ERR_KM_MEMORY_ALLOCATION_IN_PBKDF2, // pbkdf2中分配内存错误
    LD_ERR_KM_GENERATE_KEY_WITH_KEK,       // 使用kek加密生成密钥错误
    LD_ERR_KM_GENERATE_KEK,                // 生成kek错误
    LD_ERR_KM_EXPORT_KEK,                  // 导出kek错误
    LD_ERR_KM_IMPORT_KEK,                  // 明文导入kek错误
    LD_ERR_KM_IMPORT_KEY,                  // 导入密钥错误
    LD_ERR_KM_DESTROY_KEY,                 // 销毁密钥错误
    LD_ERR_KM_PBKDF2,                      // pbkdf2执行错误
    LD_ERR_KM_EXTERNAL_IMPORT_KEK,         // 外部导入kek错误
    LD_ERR_KM_WRITE_FILE,        // 将kekpkg写入文件错误
    LD_ERR_KM_READ_FILE,        // 从文件读取kekpkg错误
    LD_ERR_KM_OPEN_FILE

} l_err;

// 密钥类型
enum KEY_TYPE
{
    KEK,               // store in pcie-card , for key establishment and storage
    ROOT_KEY,          // KAS
    MASTER_KEY_AS_SGW, // KASSGW
    MASTER_KEY__AS_GS, // KASGS
    // sesssion key
    SESSION_KEY_USR_ENC,  // KUENC
    SESSION_KEY_USR_INT,  // KUINT
    SESSION_KEY_DC_INT,   // KDC
    SESSION_KEY_KEK,      // KKEK
    SESSION_KEY_MAKE_INT, // KM
    GROUP_KEY_BC,         // KBC
    GROUP_KEY_CC,         // KCC
    // for local storage
    LOCAL_HMAC_KEY,
};

// 密钥状态
enum STATE
{
    PRE_ACTIVATION,
    ACTIVE,
    SUSPENDED,
    DEACTIVATED,
    COMPROMISED,
    DESTROYED,
};

// 密钥属性结构体
struct KeyMetaData
{
    uint16_t id;
    uint8_t owner_1[16];
    uint8_t owner_2[16];
    enum KEY_TYPE type;
    uint8_t length; // 单位 字节
    enum STATE state;
    time_t effectuation_time;
    time_t update_cycle; // 单位 天
    // uint8_t counter;
};

// kek包-用于kek的预置
struct KEKPkg
{
    uint32_t rcver_len;
    uint8_t *rcver;
    uint32_t key_len;
    uint8_t *key;
    uint32_t chck_len;
    uint8_t *chck_value;
};

// 密钥包 用于密钥的存储和分发
struct KeyPkg
{
    struct KeyMetaData* meta_data; // 密钥属性
    uint8_t key[64];                 // 密钥 存储时用密码卡加密，分发时用分发保护密钥加密
    uint16_t chck_alg;            // 校验算法标识
    uint16_t chck_len;            // 校验值长度
    uint8_t chk_value[32];           // 长度为chck_len的校验值
};

/*
************************************************************************
*                           基础密码运算功能                             *
************************************************************************
*/
// 随机数生成
l_err generate_random(int len, uint8_t *random_data);

// 国密加密（支持SM4_OFB/CFB/CBC/ECB）
l_err encrypt_with_domestic_algo(void *key_handle, unsigned int alg_id, uint8_t *iv, uint8_t *data,
                                 unsigned int data_length, uint8_t *cipher_data, unsigned int *cipher_data_len);
// 国密解密（支持SM4_OFB/CFB/CBC/ECB）
l_err decrypt_with_domestic_algo(void *key_handle, unsigned int alg_id, uint8_t *iv, uint8_t *cipher_data,
                                 unsigned int cipher_data_len, uint8_t *plain_data, unsigned int *plain_data_len);

// hash （支持SGD_SM3）
l_err hash(unsigned int alg_id, uint8_t *data, size_t data_len, uint8_t *output);

// mac （支持SSGD_SM4_CFB）
l_err mac(void *key_handle, unsigned int alg_id, uint8_t *iv, uint8_t *data, unsigned int data_length, uint8_t *mac, unsigned int *mac_length);

// sm3 hmac
l_err sm3_hmac(uint8_t *key, uint32_t key_len, uint8_t *data, uint32_t data_len,
               uint8_t *hmac_data, uint32_t *hmac_data_len);

/************************************************************************
*                           基础密钥管理功能                             *
************************************************************************/
// 导入明文密钥
l_err import_key(uint8_t *key, unsigned int key_length, void **key_handle);

// 销毁密钥
l_err destroy_key(void *key_handle);

// 导入KEK
l_err import_kek(unsigned int key_index, void *key, unsigned int key_len);

// 生成KEK
l_err generate_kek(unsigned int key_bits_len, unsigned int key_index);

// 导出KEK
l_err export_kek(unsigned int key_index, void *key, unsigned int *key_len);

/*
************************************************************************
*                          测试用：输出格式控制                          *
************************************************************************
*/
// 打印字符数组
l_err printbuff(const char *printtitle, uint8_t *buff, int len);

// 逐行打印密钥信息结构体
l_err print_key_metadata(struct KeyMetaData *key_info);

// 逐行打印key_pkg结构体
l_err print_key_pkg(struct KeyPkg *key_pkg);

// 打印kek包
l_err print_kek_pkg(struct KEKPkg *kek_pkg);
/*
************************************************************************
*                      业务逻辑接口：密钥生成和派生                       *
************************************************************************
*/

// 获取全局变量count的值并自增 用于密钥编号
int get_key_id();

// 指定KEK索引和密钥元数据（密钥类型，密钥所有者，密钥长度，自动启用选择，启用日期，有效期限）
// 初始化元数据并生成密钥、密钥id，输出密钥句柄、使用KEK加密的密钥密文、和密钥元数据结构体。
l_err generate_key_with_kek(int kek_index, struct KeyMetaData *key_info, void **key_handle, uint8_t *cipher_key, int *cipher_len);

// 基于口令的密钥派生函数（基于hmac实现）
l_err pbkdf2(uint8_t *password, uint32_t password_len, uint8_t *salt, uint32_t salt_len,
             uint32_t iterations, uint32_t derived_key_len, uint8_t *derived_key);

// KAS-SGW的派生
l_err derive_key_assgw(void *root_key_handle, uint32_t key_len, uint8_t *id_as, uint32_t id_as_len, uint8_t *id_sgw,
                       uint32_t id_sgw_len, uint8_t *shared_info, uint32_t shared_info_len, void *key_assgw_handle, struct KeyMetaData *key_info);

/*
************************************************************************
*                      业务逻辑接口：密钥存储                            *
************************************************************************
*/

// 将密钥及其元数据做标准封装 
l_err generate_key_pkg(struct KeyMetaData *key_info, uint8_t *cipher_key, uint8_t *hmac_iv,void *hmac_key_handle, struct KeyPkg *key_pkg);

l_err write_keypkg_to_file(const char *filename, struct KeyPkg *pkg);

/*
*************************************************************************
*                        业务逻辑接口：kek预置                            *
*************************************************************************
*/
// 光电+光电密码卡方案：因为AS不支持PCIE 此方案不适用
// 将kek写入文件
l_err write_kekpkg_to_file(const char *filename, struct KEKPkg *pkg);

// 将kek从文件中读出并清除文件内容
l_err read_kdkpkg_from_file(const char *filename, struct KEKPkg *pkg);

// 生成并导出KEK
l_err generate_and_export_kek(int key_len, int kek_index, uint8_t *rcver, int rcver_len, struct KEKPkg *kek_pkg);

// 验证并导入KEK到指定索引位置
l_err external_import_kek(struct KEKPkg *kek_pkg, int kek_index, uint8_t *local_id, int id_len);

// 光电+派科PICE转USB的接口 (未完成)
#endif
