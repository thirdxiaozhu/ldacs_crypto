/* key management by wencheng in 20240119, uncompleted version. 运行前手动生成1号KEK*/

#ifndef KEY_MANAGE_H
#define KEY_MANAGE_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdint.h>
#include <string.h>
#include <uuid/uuid.h>
#include <ldacs/ldacs_sim/ldacs_def.h>

// 暂时之计
#include <sdf/libsdf.h>
#include <sdfkmt/sdfe-func.h>
#include <sdfkmt/sdfe-type.h>

/*
************************************************************************
*                           结构体声明和别名定义                         *
************************************************************************
*/

#define HMAC_HASH_BLOCK_SIZE 64
#define SM3_DATA_LEN 32
#define MAX_OWENER_LEN 16
#define MAX_KEK_CIPHER_LEN 64
#define MAX_KEY_CIPHER_LEN 64
#define MAX_IV_LEN 16
#define MAX_CHCK_LEN 32
#define ALGO_WITH_KEK SGD_SM4_ECB    // generatekeywithkek importkeywithkek接口调用的算法
#define ALGO_ENC_AND_DEC SGD_SM4_CFB // 加解密调用的算法
#define ALGO_MAC SGD_SM4_MAC         // MAC调用的算法
#define ALGO_HASH SGD_SM3            // hash调用的算法

// 密钥句柄别名
typedef void *CCARD_HANDLE;

// typedef enum { TRUE = 1, FALSE = 0 } bool;

// 报错码
typedef enum {
    LD_KM_OK = 0,

    LD_ERR_KM_OPEN_DEVICE = 100,           // 打开密码设备错误
    LD_ERR_KM_OPEN_SESSION,                // 与设备建立会话失败
    LD_ERR_KM_OPEN_DB,                     //  打开数据库失败
    LD_ERR_KM_EXE_DB,                      // 执行sql语句失败
    LD_ERR_KM_MALLOC,                      // 分配空间失败
    LD_ERR_KM_FREE,                        // 释放空间失败
    LD_ERR_KM_GENERATE_RANDOM,             // 生成随机数失败
    LD_ERR_KM_HashInit,                    // hash init失败
    LD_ERR_KM_HashUpdate,                  //  hash update失败
    LD_ERR_KM_HashFinal,                   // hash final失败
    LD_ERR_KM_MAC,                         // mac接口运行失败
    LD_ERR_KM_ENCRYPT,                     // 加密失败
    LD_ERR_KM_DECRYPT,                     // 解密失败
    LD_ERR_KM_HMAC,                        // hmac失败
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
    LD_ERR_KM_CREATE_FILE,
    LD_ERR_KM_DELETE_FILE,
    LD_ERR_KM_ROOTKEY_VERIFY,     // 根密钥验证错误
    LD_ERR_KM_MASTERKEY_VERIFY,   // 主密钥验证错误
    LD_ERR_KM_DERIVE_KEY,         // 密钥派生错误
    LD_ERR_KM_DERIVE_SESSION_KEY, // 会话密钥派生错误
    LD_ERR_KM_CREATE_DB,          // 创建数据库或者数据表错误
    LD_ERR_KM_QUERY,              // 查询数据库错误
    LD_ERR_KM_ALTERDB,            // 修改数据库错误
    LD_ERR_KM_GET_HANDLE,         // 获取密钥句柄错误
    LD_ERR_KM_UPDATE_SESSIONKEY,  // 更新会话密钥错误
    LD_ERR_KM_INSTALL_KEY,        // 安装密钥错误
    LD_ERR_KM_KEY_STATE,          // 密钥状态错误
    LD_ERR_KM_CONVERT,            // 格式转换错误
    LD_ERR_REVOKE_KEY,            // 密钥撤销错误
    LD_ERR_KM_SGW_MK_UPDATE,      // 网关端密钥更新错误
} l_km_err;

#ifndef USE_GMSSL
// 密钥类型
enum KEY_TYPE {
    /* 根密钥和主密钥 */
    ROOT_KEY,          // KAS 根密钥
    MASTER_KEY_AS_SGW, // AS和SGW之间 主密钥
    MASTER_KEY_AS_GS,  // KASGS 主密钥
    NH_KEY,            // 下一跳密钥 临时变量
    /* 会话密钥 */
    SESSION_KEY_USR_ENC,     // KUENC 用户数据加密
    SESSION_KEY_USR_INT,     // KUINT 用户数据完整性
    SESSION_KEY_CONTROL_ENC, // 控制信道机密性
    SESSION_KEY_CONTROL_INT, // 控制信道完整性
    /* 组密钥 */
    GROUP_KEY_BC, // BC信道完整性保护
    GROUP_KEY_CC, // CC信道完整性保护

};

static const char *type_names[] = {
        "ROOT_KEY",
        "MASTER_KEY_AS_SGW",
        "MASTER_KEY_AS_GS",
        "NH_KEY",
        "SESSION_KEY_USR_ENC",
        "SESSION_KEY_USR_INT",
        "SESSION_KEY_CONTROL_ENC",
        "SESSION_KEY_CONTROL_INT",
        "GROUP_KEY_BC",
        "GROUP_KEY_CC",
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
typedef struct KeyMetaData {
    uuid_t id;
    uint8_t owner_1[MAX_OWENER_LEN];
    uint8_t owner_2[MAX_OWENER_LEN];
    enum KEY_TYPE key_type;
    uint32_t length; // 单位 字节
    enum STATE state;
    time_t creation_time;
    time_t update_cycle; // 单位 天
    // uint8_t counter;
} km_keymetadata_t;

// 密钥包 用于密钥的存储和分发
typedef struct KeyPkg {
    struct KeyMetaData *meta_data;          // 密钥属性
    uint8_t kek_cipher[MAX_KEK_CIPHER_LEN]; // 密钥加密密钥的密文 用于密钥存储保护
    uint32_t kek_cipher_len;
    uint8_t key_cipher[MAX_KEY_CIPHER_LEN]; // 密钥 存储时用密码卡加密，分发时用分发保护密钥加密
    uint16_t iv_len;
    uint8_t iv[MAX_IV_LEN];           // 初始化向量 用于生成校验码
    uint16_t chck_len;                // 校验值长度
    uint16_t chck_alg;                // 校验算法标识
    uint8_t chck_value[MAX_CHCK_LEN]; // 长度为chck_len的校验值
} km_keypkg_t;

/*
************************************************************************
*                 外部接口:密钥结构体相关                               *
************************************************************************
*/
// 初始化密钥元数据
km_keymetadata_t *km_key_metadata_new(
        const char *owner_1,
        const char *owner_2,
        enum KEY_TYPE key_type,
        uint32_t key_len,
        uint16_t update_day);

/**
 * @brief 初始化密钥包描述信息。如果传入明文密钥，对密钥加密存储。
 * @param[in] meta 描述信息
 * @param[in] key 明文密钥
 * @return 带有描述信息的密钥结构体
 */
km_keypkg_t *km_key_pkg_new(
        km_keymetadata_t *meta,
        uint8_t *key,
        bool is_encrypt);

// 释放密钥包空间
void key_pkg_free(
        km_keypkg_t *pkg);

/*
************************************************************************
*                 外部接口:基础密码运算功能                             *
************************************************************************
*/
// 随机数生成
l_km_err km_generate_random(
        uint8_t *random_data,
        int len);

// 国密加密（支持SM4_OFB/CFB/CBC/ECB）
l_km_err km_encrypt(
        void *key_handle,
        uint32_t alg_id,
        uint8_t *iv,
        uint8_t *data,
        uint32_t data_length,
        uint8_t *cipher_data,
        uint32_t *cipher_data_len);

// 国密加密（支持SM4_OFB/CFB/CBC/ECB）
l_km_err km_sym_encrypt(
        const char *db_name,
        const char *table_name,
        const char *key_id,
        uint32_t alg_id,
        uint8_t *iv,
        uint8_t *data,
        uint32_t data_length,
        uint8_t *cipher_data,
        uint32_t *cipher_data_len);

l_km_err km_decrypt(
        void *key_handle,
        uint32_t alg_id,
        uint8_t *iv,
        uint8_t *cipher_data,
        uint32_t cipher_data_len,
        uint8_t *plain_data,
        uint32_t *plain_data_len);

// 国密解密（支持SM4_OFB/CFB/CBC/ECB）
l_km_err km_sym_decrypt(
        const char *db_name,
        const char *table_name,
        const char *key_id,
        uint32_t alg_id,
        uint8_t *iv,
        uint8_t *cipher_data,
        uint32_t cipher_data_len,
        uint8_t *plain_data,
        uint32_t *plain_data_len);

// hash （支持SGD_SM3）输出32byte的结果
l_km_err km_hash(
        uint32_t alg_id,
        uint8_t *data,
        size_t data_len,
        uint8_t *output);

l_km_err km_mac(
        CCARD_HANDLE key_handle,
        uint32_t alg_id,
        uint8_t *iv,
        uint8_t *data,
        uint32_t data_length,
        uint8_t *mac,
        uint32_t *mac_length);

// sm3 hmac key长度要求为32byte
l_km_err km_hmac(
        uint8_t *key,
        uint32_t key_len,
        uint8_t *data,
        uint32_t data_len,
        uint8_t *hmac_value,
        uint32_t *hmac_len);

// sm3 hmac key长度要求为32byte
l_km_err km_hmac_with_keyhandle(
        CCARD_HANDLE handle,
        uint8_t *data,
        uint32_t data_len,
        uint8_t *hmac_value,
        uint32_t *hmac_len);

l_km_err km_sm3_hmac(
        const char *db_name,
        const char *table_name,
        const char *key_id,
        uint8_t *data,
        uint32_t data_len,
        uint8_t *hmac_value,
        uint32_t *hmac_len);

/************************************************************************
 *                  内部接口：基础密钥管理功能                            *
 ************************************************************************/
// 导入明文密钥
l_km_err km_import_key(
        uint8_t *key,
        uint32_t key_length,
        CCARD_HANDLE *key_handle);

// 销毁密钥
l_km_err km_destroy_key(
        CCARD_HANDLE key_handle);

// 指定KEK索引和密钥元数据，生成密钥，返回密钥句柄和密钥密文
l_km_err km_generate_key_with_kek(
        int kek_index,
        uint32_t kek_len,
        CCARD_HANDLE *key_handle,
        uint8_t *cipher_key,
        int *cipher_len);

/**
 * @brief 使用KEK导入密钥
 * @param[in] key 密钥（密文）
 * @param[in] key_len 密钥长度
 * @param[in] kek_index kek下标
 * @param[out] key_handle
 */
l_km_err km_import_key_with_kek(
        uint8_t *key,
        uint32_t key_length,
        int kek_index,
        CCARD_HANDLE *key_handle);

/*************************************************************************
 *                      外部接口：业务逻辑-密钥生成和派生                  *
 *************************************************************************/
/**
 * @brief 外部接口：根密钥生成、保存和导出
 * @param[in] dbname 数据库名称，用于存储根密钥
 * @param[in] tablename 数据库中的表名，用于存储根密钥
 * @param[in] rkey_filename_in_ccard 在密码卡中根密钥文件名
 * @return 成功返回LD_KM_OK，失败返回其他错误码
 * */
l_km_err km_rkey_import(
        const char *db_name,
        const char *table_name,
        const char *rkey_filename_in_ccard);

/**
 * @brief 外部接口：将文件存入密码卡文件区
 * @param[in] filepath 指定输入文件的路径
 * @param[in] filename 存入密码卡时的文件名
 */
l_km_err km_writefile_to_cryptocard(
        uint8_t *filepath,
        uint8_t *filename);

/**
 * @brief 外部接口：根密钥生成、保存和导出
 * @param[in] sac_name 服务访问客户端标识
 * @param[in] sac_name 网关标识
 * @param[in] key_len 根密钥长度
 * @param[in] validity_period 根密钥有效期（单位：天）
 * @param[in] dbname 数据库名称，用于存储根密钥
 * @param[in] tablename 数据库中的表名，用于存储根密钥
 * @param[in] export_file_path 导出根密钥的文件路径
 * @return 成功返回LD_KM_OK，失败返回其他错误码
 * */
l_km_err km_rkey_gen_export(
        const char *as_name,
        const char *sgw_name,
        uint32_t key_len,
        uint32_t validity_period,
        const char *dbname,
        const char *tablename,
        const char *export_file_path);

/**
 * @brief 外部接口：单个密钥的派生
 * @param[in] id 根密钥id/主密钥id
 * @param[in] key_type 所需的密钥类型
 * @param[in] key_len 所需密钥的长度
 * @param[in] rand 随机数
 * @param[in] rand_len 随机数长度
 * @return 报错码
 */
l_km_err km_derive_key(
        uint8_t *db_name,
        uint8_t *table_name,
        uint8_t *id,
        uint32_t key_len,
        uint8_t *gs_name,
        uint8_t *rand,
        uint32_t rand_len);

/*************************************************************************
 *                      外部接口：业务逻辑-密钥使用                        *
 *************************************************************************/

/**
 * @brief 外部接口：查询密钥句柄
 * @param[in] db_name
 * @param[in] table_name
 * @param[in] id 密钥id
 * @param[out] handle 密钥句柄
 * @return 是否执行成功
 */
l_km_err get_handle_from_db(
        uint8_t *db_name,
        uint8_t *table_name,
        uint8_t *id,
        CCARD_HANDLE *handle);

/*************************************************************************
 *                      外部接口：业务逻辑-密钥更新                       *
 *************************************************************************/

/**
 * @brief 外部接口：AS端更新主密钥 KAS-GS
 * @param[in] sgw_name sgw身份
 * @param[in] gs_s_name 源GS标识
 * @param[in] gs_t_name 目的GS标识
 * @param[in] as_name   AS标识
 * @param[in] dbname   密钥库名
 * @param[in] tablename 密钥表名
 * @param[in] len_nonce 随机数长度
 * @param[in] nonce 随机数
 * @return 更新结果
 */
l_km_err km_update_masterkey(
        uint8_t *dbname,
        uint8_t *tablename,
        uint8_t *sgw_name,
        uint8_t *gs_s_name,
        uint8_t *gs_t_name,
        uint8_t *as_name,
        uint16_t len_nonce,
        uint8_t *nonce);

/**
 *  @brief 外部接口：网关端更新主密钥 KAS-GS
 * @param[in] key_id 密钥id标识
 * @param[in] gs_t_name 目的GS标识
 * @param[in] dbname   密钥库名
 * @param[in] tablename 密钥表名
 * @param[in] len_nonce 随机数长度
 * @param[in] nonce 随机数
 */
l_km_err sgw_update_master_key(
        uint8_t *dbname,
        uint8_t *tablename,
        uint8_t *key_id,
        uint8_t *sgw_name,
        uint8_t *gs_t_name,
        uint16_t len_nonce,
        uint8_t *nonce);

/**
 * @brief 外部接口：撤销密钥及其派生密钥
 * @param[in] dbname   密钥库名
 * @param[in] tablename 密钥表名
 * @param[in] id 密钥标识
 * @return 报错码
 */
l_km_err km_revoke_key(
        uint8_t *dbname,
        uint8_t *tablename,
        uint8_t *id);

/**
 * @brief 外部接口：GS端安装主密钥 派生会话密钥
 * @param[in] dbname   密钥库名
 * @param[in] tablename 密钥表名
 * @param[in] key 主密钥
 * @param[in] as_name AS端标识
 * @param[in] sac_gs GS本地标识
 */
l_km_err km_install_key(
        uint8_t *dbname,
        uint8_t *tablename,
        uint32_t key_len,
        uint8_t *key,
        uint8_t *as_name,
        uint8_t *sac_gs,
        uint32_t nonce_len,
        uint8_t *nonce);

/*************************************************************************
 *                      内部接口：业务逻辑-密钥存储                       *
 *************************************************************************/
// 输入密钥包 获取密钥句柄
l_km_err km_getkeyhandle(
        struct KeyPkg *pkg,
        CCARD_HANDLE *key_handle);

// 从密码卡读取文件 放到指定位置
l_km_err km_readfile_from_cryptocard(
        const char *filename,
        const char *filepath);

/* ************************************************************************
 *                  内部测试用：输出和显示格式控制                          *
 *************************************************************************/
// 报错码解析
const char *km_error_to_string(
        l_km_err err_code);

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
        km_keypkg_t *pkg);

// 从文件读出密钥包
km_keypkg_t *read_keypkg_from_file(
        const char *filename);

/**
 * @brief 字节序列转换为十六进制字符串
 * @param[in] bytes_len
 * @param[in] bytes
 * @return 十六进制串
 */
uint8_t *bytes_to_hex(
        uint16_t bytes_len,
        uint8_t *bytes);

/**
 * @brief 字节序列转换为十六进制字符串
 * @param[in] hex_str
 * @return 字节串
 */
uint8_t *hex_to_bytes(
        const char *hex_str);

/**
 * 输入枚举类型的密钥类型 返回对应的字符串
 * @param[in] type 密钥类型
 * @return 密钥类型对应的字符串
 */
uint8_t *ktype_str(
        enum KEY_TYPE type);

/**
 * 输入枚举类型的字符串 返回对应的密钥类型
 * @param[in] type_str 密钥类型
 * @return 密钥类型
 */
enum KEY_TYPE str_to_ktype(
        const char *type_str);

/**
 * @brief 返回密钥状态 枚举转字符串
 * @param[in] state 密钥状态 枚举类型
 * @return 密钥状态字符串
 */
uint8_t *kstate_str(
        enum STATE state);

enum STATE str_kstate(const uint8_t *state_str);

/**
 * @brief 校验算法解析
 * @param[in] chck_algo 校验算法(int类型)
 * @return 校验算法
 */
uint8_t *chck_algo_str(
        uint16_t chck_algo);

#endif
#endif
