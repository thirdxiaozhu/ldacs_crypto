/* key management by wencheng in 20240119, uncompleted version. 运行前手动生成1号KEK*/
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
#include <string.h>
#include <fcntl.h>
#include <uuid/uuid.h>

// #include <piico_pc/api.h>
// #include <piico_pc/piico_define.h>
// #include <piico_pc/piico_error.h>
#include <sdf/libsdf.h>
#include <sdfkmt/sdfe-func.h>
#include <sdfkmt/sdfe-type.h>

/*
************************************************************************
*                           结构体声明和别名定义                         *
************************************************************************
*/

typedef void *HANDLE; // 密钥句柄别名
#define HMAC_HASH_BLOCK_SIZE 64
#define SM3_DATA_LEN 32
#define MAX_OWENER_LEN 16
#define MAX_KEK_CIPHER_LEN 64
#define MAX_KEY_CIPHER_LEN 64
#define MAX_IV_LEN 16
#define MAX_CHCK_LEN 32
#define ALGO_WITH_KEK SGD_SM4_ECB    // generatekeywithkek importkeywithkek接口调用的算法
#define ALGO_ENC_AND_DEC SGD_SM4_CFB // 加解密调用的算法
#define ALGO_MAC SGD_SM4_MAC         // 加解密调用的算法
#define ALGO_HASH SGD_SM3            // hash调用的算法

// 报错码
typedef enum {
    LD_KM_OK = 0,

    LD_ERR_KM_OPEN_DEVICE = 100,           // 打开密码设备错误
    LD_ERR_KM_OPEN_SESSION,                // 与设备建立会话失败
    LD_ERR_KM_GENERATE_RANDOM,             // 生成随机数失败
    LD_ERR_KM_HashInit,                    // hash init失败
    LD_ERR_KM_HashUpdate,                  //  hash update失败
    LD_ERR_KM_HashFinal,                   // hash final失败
    LD_ERR_KM_MAC,                         // mac接口运行失败
    LD_ERR_KM_ENCRYPT,                     // 加密失败
    LD_ERR_KM_DECRYPT,                     // 解密失败
    LD_ERR_KM_SM3HMAC,                     // hmac失败
    LD_ERR_KM_PARAMETERS_ERR,              // pbkdf2参数错误
    LD_ERR_KM_PARAMETERS_NULL,             // 接口参数为空
    LD_ERR_KM_MEMORY_ALLOCATION_IN_PBKDF2, // pbkdf2中分配内存错误
    LD_ERR_KM_GENERATE_KEY_WITH_KEK,       // 使用kek加密生成密钥错误
    LD_ERR_KM_GENERATE_KEK,                // 生成kek错误
    LD_ERR_KM_EXPORT_KEK,                  // 导出kek错误
    LD_ERR_KM_IMPORT_KEY_WITH_KEK,         // 导入密文密钥错误
    LD_ERR_KM_IMPORT_KEY,                  // 导入明文密钥错误
    LD_ERR_KM_DESTROY_KEY,                 // 销毁密钥错误
    LD_ERR_KM_PBKDF2,                      // pbkdf2执行错误
    LD_ERR_KM_EXTERNAL_IMPORT_KEK,         // 外部导入kek错误
    LD_ERR_KM_WRITE_FILE,                  // 将kekpkg写入文件错误
    LD_ERR_KM_READ_FILE,                   // 从文件读取kekpkg错误
    LD_ERR_KM_OPEN_FILE,                   // 打开文件错误
    LD_ERR_KM_ROOTKEY_VERIFY,              // 根密钥验证错误
    LD_ERR_KM_MASTERKEY_VERIFY,            // 主密钥验证错误
    LD_ERR_KM_DERIVE_KEY,                  // 密钥派生错误
    LD_ERR_KM_DERIVE_SESSION_KEY           // 会话密钥派生错误

} l_km_err;

// 密钥类型
enum KEY_TYPE {
    KEK = 0,              // store in pcie-card , for key establishment and storage
    ROOT_KEY,             // KAS 根密钥
    MASTER_KEY_AS_SGW,    // KASSGW 主密钥
    MASTER_KEY_AS_GS,     // KASGS 主密钥
    SESSION_KEY_USR_ENC,  // KUENC 用户数据加密
    SESSION_KEY_USR_INT,  // KUINT 用户数据完整性
    SESSION_KEY_DC_INT,   // KDC 保护DC信道完整性
    SESSION_KEY_KEK,      // KKEK 组密钥分发保护
    SESSION_KEY_MAKE_INT, // KM 派生会话密钥过程中完整性保护
    GROUP_KEY_BC,         // KBC BC信道完整性保护
    GROUP_KEY_CC,         // KCC CC信道完整性保护
};

// 密钥状态 用于控制密钥的使用
enum STATE {
    PRE_ACTIVATION, // 未激活
    ACTIVE,         // 已激活
    SUSPENDED,      // 已撤销
    DEACTIVATED,    // 已失活
    COMPROMISED,    // 已泄露
    DESTROYED,      // 已销毁
};

// 密钥属性结构体 用于指定密钥的参数
struct KeyMetaData {
    uuid_t id;
    uint8_t owner_1[MAX_OWENER_LEN];
    uint8_t owner_2[MAX_OWENER_LEN];
    enum KEY_TYPE key_type;
    uint32_t length; // 单位 字节
    enum STATE state;
    time_t creation_time;
    time_t update_cycle; // 单位 天
    // uint8_t counter;
};

// 密钥包 用于密钥的存储和分发
struct KeyPkg {
    struct KeyMetaData *meta_data;          // 密钥属性
    uint8_t kek_cipher[MAX_KEK_CIPHER_LEN]; // 密钥加密密钥的密文 用于密钥存储保护
    uint32_t kek_cipher_len;
    uint8_t key_cipher[MAX_KEY_CIPHER_LEN]; // 密钥 存储时用密码卡加密，分发时用分发保护密钥加密
    uint16_t iv_len;
    uint8_t iv[MAX_IV_LEN];           // 初始化向量 用于生成校验码
    uint16_t chck_len;                // 校验值长度
    uint16_t chck_alg;                // 校验算法标识
    uint8_t chck_value[MAX_CHCK_LEN]; // 长度为chck_len的校验值
};

/*
************************************************************************
*                           基础密码运算功能                             *
************************************************************************
*/
// 随机数生成
l_km_err generate_random(
        int len,
        uint8_t *random_data);

// 国密加密（支持SM4_OFB/CFB/CBC/ECB）
l_km_err encrypt(
        void *key_handle,
        uint32_t alg_id,
        uint8_t *iv,
        uint8_t *data,
        uint32_t data_length,
        uint8_t *cipher_data,
        uint32_t *cipher_data_len);

// 国密解密（支持SM4_OFB/CFB/CBC/ECB）
l_km_err decrypt(
        void *key_handle,
        uint32_t alg_id,
        uint8_t *iv,
        uint8_t *cipher_data,
        uint32_t cipher_data_len,
        uint8_t *plain_data,
        uint32_t *plain_data_len);

// hash （支持SGD_SM3）输出32byte的结果
l_km_err hash(
        uint32_t alg_id,
        uint8_t *data,
        size_t data_len,
        uint8_t *output);

// mac （支持SGD_SM4_CFB）
l_km_err mac(
        void *key_handle,
        uint32_t alg_id,
        uint8_t *iv,
        uint8_t *data,
        uint32_t data_length,
        uint8_t *mac,
        uint32_t *mac_length);

// sm3 hmac key长度要求为32byte
l_km_err hmac(
        uint8_t *key,
        uint32_t key_len,
        uint8_t *data,
        uint32_t data_len,
        uint8_t *hmac_value,
        uint32_t *hmac_len);

// sm3 hmac key长度要求为32byte
l_km_err hmac_with_keyhandle(
        void *handle,
        uint8_t *data,
        uint32_t data_len,
        uint8_t *hmac_value,
        uint32_t *hmac_len);

/************************************************************************
 *                           基础密钥管理功能                             *
 ************************************************************************/
// 导入明文密钥
l_km_err import_key(
        uint8_t *key,
        uint32_t key_length,
        void **key_handle);

// 销毁密钥
l_km_err destroy_key(
        void *key_handle);

// 指定KEK索引和密钥元数据，生成密钥，返回密钥句柄和密钥密文
l_km_err generate_key_with_kek(
        int kek_index,
        struct KeyMetaData *key_info,
        void **key_handle,
        uint8_t *cipher_key,
        int *cipher_len);

// 基于口令的密钥派生函数（prf：sm3 hmac）
l_km_err pbkdf2(
        uint8_t *password,
        uint32_t password_len,
        uint8_t *salt,
        uint32_t salt_len,
        uint32_t iterations,
        uint32_t derived_key_len,
        uint8_t *derived_key);

/*************************************************************************
 *                      业务逻辑接口：密钥生成和派生                       *
 *************************************************************************/

// 密钥派生
l_km_err derive_key(
        void *kdk_handle,
        enum KEY_TYPE key_type,
        uint32_t key_len,
        uint8_t *owner1,
        uint8_t *owner2,
        uint8_t *rand,
        uint32_t rand_len,
        void **key_handle,
        struct KeyPkg *pkg);

// 输入密钥包 获取密钥句柄
l_km_err get_keyhandle(
        struct KeyPkg *pkg,
        void **key_handle);

/*************************************************************************
 *                      业务逻辑接口：密钥更新                            *
 *************************************************************************/
// 更新会话密钥
l_km_err update_sessionkey(
        struct KeyMetaData *meta_data,  // 会话密钥元数据
        HANDLE masterkey_handle,       // 主密钥句柄
        uint8_t *nonce,                // 随机数
        uint32_t nonce_len,            // 随机数长度
        struct KeyPkg *updated_keypkg); // 更新的会话密钥

/*************************************************************************
 *                      业务逻辑接口：密钥存储                            *
 *************************************************************************/

/**************************************************************************
 *                        业务逻辑接口：预置根密钥                           *
 **************************************************************************/
// 网关导出根密钥包到文件rootkey.bin中(给AS的) 本地存储根密钥于rootkey.txt中
l_km_err export_rootkey(
        struct KeyMetaData *root_keyinfo,
        struct KeyPkg *pkg);

// 将文件存入密码卡文件区 指定输入文件的路径 存入密码卡时的文件名
l_km_err writefile_to_cryptocard(
        uint8_t *filepath,
        uint8_t *filename);

// 验证文件中的根密钥 存储于密码卡 返回密钥包结构体
l_km_err import_rootkey(
        struct KeyPkg *rootkey_pkg,
        void **rootkey_handle);

// 从密码卡读取文件 放到指定位置
l_km_err readfile_from_cryptocard(
        uint8_t *filename,
        uint8_t *filepath);

// 从文件中获取根密钥  输出根密钥句柄
l_km_err get_rootkey_handle(
        void **rootkey_handle);

/* ************************************************************************
 *                          测试用：输出和显示格式控制                          *
 *************************************************************************/

// 打印字符数组
l_km_err printbuff(
        const char *printtitle,
        uint8_t *buff, int len);

// 逐行打印密钥信息结构体
l_km_err print_key_metadata(
        struct KeyMetaData *key_info);

// 逐行打印key_pkg结构体
l_km_err print_key_pkg(
        struct KeyPkg *key_pkg);

// 将密钥包输出到文件
l_km_err write_keypkg_to_file(
        const char *filename,
        struct KeyPkg *pkg);

// 从文件读出密钥包
l_km_err read_keypkg_from_file(
        const char *filename,
        struct KeyPkg *pkg);

#endif
