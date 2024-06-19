/**
 * created by wencheng on 2024-5-20
 * struct convert to bitstream , for store in database
 * 密钥存储、查询、修改
 */

#include "key_manage.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_ID_LEN 128

enum field_type
{
    /*
     * key management relevant
     */
    ft_uuid,
    ft_uint8t_pointer,
    ft_enum,
    ft_uint32t,
    ft_timet,
    ft_uint16t,
    ft_end,
};

typedef struct field_desc
{ // struct field descriptor
    enum field_type field_type;
    const int size; /* size, in bits, of field */
    const char *name;
    const void *desc; /*未使用： enum_names for enum or char *[] for bits */
} field_desc;

typedef struct struct_desc_s
{
    const char *name;
    struct field_desc *fields;
} struct_desc;

/**
 * 基于描述创建密钥表
 * @param sd 理想的数据表描述
 * @param[in] db_name 数据库名
 * @param[in] table_name 表名
 * @param[in] primary_key 主键
 * @return 处理结果:成功/失败
 */
l_km_err create_table_if_not_exist(
    struct_desc *sd,
    uint8_t *db_name,
    uint8_t *table_name,
    uint8_t *primary_key);

/**
 * @bref 存储密钥：按照描述编码和组装结构体 插入指定数据库表
 * @param pkg 密钥结构体
 * @param sd 结构体描述
 * @return 是否执行成功
 */
l_km_err store_key(
    uint8_t *db_name,
    uint8_t *table_name,
    struct KeyPkg *pkg,
    struct_desc *sd);

/******************** 查询数据库 **************************/
typedef struct
{
    uint16_t key_len;
    uint8_t *key_cipher;
    uint16_t kek_len;
    uint8_t *kek_cipher;
    uint16_t iv_len;
    uint8_t *iv;
} Result_Query_for_handle;

/**
 * @brief 查询密钥句柄
 * @param[in] db_name
 * @param[in] table_name
 * @param[in] id 密钥id
 * @param[out] handle 密钥句柄
 * @return 是否执行成功
 */
l_km_err get_handle_from_db(uint8_t *db_name, uint8_t *table_name, uint8_t *id, CCARD_HANDLE *handle);

typedef struct
{
    CCARD_HANDLE kek_handle;
    uint16_t iv_len;
    uint8_t *iv;
} QueryResult_for_kekhandle;

/**
 * @brief 获取kek密钥句柄
 * @param[in] db_name
 * @param[in] table_name
 * @param[in] id 密钥id
 * @return 查询结果
 */
QueryResult_for_kekhandle query_kekhandle(
    uint8_t *db_name,
    uint8_t *table_name,
    uint8_t *id);

typedef struct
{
    uint8_t *ids[MAX_ID_LEN];
    uint32_t count;
} QueryResult_for_queryid;


/**
 * @bref 基于所有者和密钥类型查询密钥
 * @param key_type 密钥类型
 * @param owner1 所有者
 * @param owner2 所有者
 * @return id:密钥标识，NULL :未查询到结果
 *
 */
QueryResult_for_queryid query_id(
    uint8_t *db_name,
    uint8_t *table_name,
    uint8_t *owner1,
    uint8_t *owner2,
    enum KEY_TYPE key_type);

// 查询结果结构体
typedef struct
{
    uint16_t key_len;
    uint16_t update_cycle;
    uint16_t update_count;
} QueryResult_for_update;

QueryResult_for_update query_for_update(
    uint8_t *db_name,
    uint8_t *table_name,
    uint8_t *id);

// 结构体用于存储查询密钥
typedef struct
{
    int key_len;  // 密钥长度
    uint8_t *key; // 密钥值（明文）
} QueryResult_for_keyvalue;

/**
 * @bref 查询密钥值
 * @param[in] dbname
 * @param[in] tablename
 * @param id 密钥编号
 * @return key:密钥值，NULL :未查询到结果
 *
 */
QueryResult_for_keyvalue query_keyvalue(
    uint8_t *db_name,
    uint8_t *table_name,
    uint8_t *id);

// 结构体用于存储密钥所有者
typedef struct
{
    uint8_t *owner1; 
    uint8_t *owner2; 
} QueryResult_for_owner;

/**
 * @bref 查询密钥拥有者
 * @param[in] dbname
 * @param[in] tablename
 * @param id 密钥编号
 * @return 密钥所有者
 *
 */
QueryResult_for_owner query_owner(
    uint8_t *db_name,
    uint8_t *table_name,
    uint8_t *id);


// 结果集结构体定义
typedef struct {
    int count;          // 结果数量
    char **subkey_ids;  // 子密钥id数组
    char **key_types;   // key_type数组
} QueryResult_for_subkey;


/**
 * @bref 查询激活状态的子密钥id
 * @param[in] dbname
 * @param[in] tablename
 * @param[in] id_mk 主密钥id
 * @return 子密钥id
*/
QueryResult_for_subkey query_subkey(
uint8_t *db_name,
    uint8_t *table_name,
    uint8_t *id);

/******************** 修改数据库 **************************/
/**
 * @brief 修改密钥状态
 * @param[in] id 密钥id
 * @param[in] state 想要改成的密钥状态
 */
l_km_err alter_keystate(
    uint8_t *db_name,
    uint8_t *table_name,
    uint8_t *id,
    enum STATE state);

/**
 * @brief 更新计数增加一次
 * @param[in] dbname
 * @param[in] tablename
 * @param[in] id
 * @param[in] dbname
 * @return 成功与否
 */
l_km_err increase_updatecount(
    uint8_t *dbname,
    uint8_t *tablename,
    uint8_t *id);


/**
 * @brief 修改密钥值
 * @param[in] dbname
 * @param[in] tablename
 * @param[in] id 密钥id
 * @param[in] key_len 密钥长度
 * @param[in] 密钥值
 * @return 修改成功与否
 */
l_km_err alter_keyvalue(
    uint8_t *db_name,
    uint8_t *table_name,
    uint8_t *id,
    uint16_t key_len,
    uint8_t *key);

/******************** 格式处理 **************************/

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
 * @param[in] bytes_len
 * @param[in] bytes
 * @return 十六进制串
 */
uint8_t *bytes_to_hex(
    uint16_t bytes_len,
    uint8_t *bytes);

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
    uint8_t* type_str);

/**
 * @brief 返回密钥状态 枚举转字符串
 * @param[in] state 密钥状态 枚举类型
 * @return 密钥状态字符串
 */
uint8_t *kstate_str(
    enum STATE state);

/**
 * @brief 校验算法解析
 * @param[in] chck_algo 校验算法(int类型)
 * @return 校验算法
 */
uint8_t *chck_algo_str(
    uint16_t chck_algo);
