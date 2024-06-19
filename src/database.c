#include "database.h"
#include "key_manage.h"
#include <sqlite3.h>

#ifdef USE_SDF

#include <sdf/libsdf.h>
#include <sdfkmt/sdfe-func.h>
#include <sdfkmt/sdfe-type.h>

#elif USE_PIICO
#include <piico_pc/api.h>
#include <piico_pc/piico_define.h>
#include <piico_pc/piico_error.h>
#endif

#define MAX_QUERY_RESULT_LENGTH 512

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
enum KEY_TYPE str_to_ktype(uint8_t *str)
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
    case SGD_SM3:
        return ("SGD_SM3");
        break;
    case ALGO_WITH_KEK:
        return ("SGD_SM4_ECB");
        break;
    default:
        return ("unknown");
        break;
    }
}

/**
 * @brief 按照描述编码和组装结构体 插入指定数据库表
 */
l_km_err store_key(uint8_t *db_name, uint8_t *table_name, struct KeyPkg *pkg, struct_desc *sd)
{

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    struct KeyPkg *p_pkg; // 指向结构体的指针 指示当前位置
    p_pkg = pkg;
    const field_desc *current_field = sd->fields; // 构建描述指针
    const field_desc *next_field;

    int maxSQLLength = 2048; // 分配内存，用于存储 SQL 语句
    char *sql = (char *)malloc(maxSQLLength * sizeof(char));
    if (sql == NULL)
    {
        fprintf(stderr, "Memory allocation error\n");
        return LD_ERR_KM_MALLOC;
    }

    /******************************
     *  构建 INSERT INTO 语句      *
     *****************************/
    sprintf(sql, "INSERT INTO %s (", table_name);
    // 添加字段名
    while (current_field->field_type != ft_end)
    {
        next_field = current_field;
        next_field++; // 指向下一个描述域
        strcat(sql, current_field->name);
        if (next_field->field_type != ft_end)
        {
            strcat(sql, ", ");
        }
        current_field++;
    }

    // 添加字段值
    current_field = sd->fields;
    strcat(sql, ") VALUES (");
    while (current_field->field_type != ft_end)
    {
        uint8_t uuid[16];
        uint8_t str_uuid[16];
        uint8_t emptyArray[MAX_OWENER_LEN] = {0};
        switch (current_field->field_type) // 按照描述解析和重排结构体
        {
            {
            case ft_uuid:
                strcat(sql, "'");
                uuid_unparse(p_pkg->meta_data->id, str_uuid);
                strcat(sql, str_uuid);
                strcat(sql, "'");
                break;
            case ft_uint8t_pointer:
                // 从结构体读取多长 根据名字判断
                strcat(sql, "'");

                if (!strcmp(current_field->name, "owner1"))
                {
                    if (memcmp(p_pkg->meta_data->owner_1, emptyArray, MAX_OWENER_LEN) == 0)
                    {
                        strcat(sql, "nil (Unspecified)");
                    }
                    else
                    {
                        strcat(sql, p_pkg->meta_data->owner_1);
                    }
                }
                else if (!strcmp(current_field->name, "owner2"))
                {

                    if (memcmp(p_pkg->meta_data->owner_1, emptyArray, MAX_OWENER_LEN) == 0)
                    {
                        strcat(sql, "nil (Unspecified)");
                    }
                    else
                    {
                        strcat(sql, p_pkg->meta_data->owner_2);
                    }
                }
                else if (!strcmp(current_field->name, "key_cipher"))
                {
                    uint8_t emptyArray[MAX_KEK_CIPHER_LEN] = {0};
                    if (memcmp(p_pkg->kek_cipher, emptyArray, MAX_KEK_CIPHER_LEN) == 0)
                    {
                        strcat(sql, "nil (Unspecified)");
                    }
                    else
                    {
                        uint16_t len = p_pkg->meta_data->length; // TODO: 重复出现 可以抽象成一个接口
                        uint8_t buff[len];
                        memcpy(buff, p_pkg->key_cipher, len);
                        uint8_t key_cipher[len * 2];
                        for (int i = 0; i < len; i++) // 转为字符串
                        {
                            snprintf(key_cipher + i * 2, len, "%02X", buff[i]);
                        }
                        strcat(sql, key_cipher);
                    }
                }
                else if (!strcmp(current_field->name, "kek_cipher"))
                {
                    uint8_t emptyArray[MAX_KEK_CIPHER_LEN] = {0};
                    if (memcmp(p_pkg->kek_cipher, emptyArray, MAX_KEK_CIPHER_LEN) == 0)
                    {
                        strcat(sql, "nil (Unspecified)");
                    }
                    else
                    {
                        uint16_t len = p_pkg->kek_cipher_len;
                        uint8_t buff[len];
                        memcpy(buff, p_pkg->kek_cipher, len);
                        uint8_t kek_cipher[len * 2];
                        for (int i = 0; i < len; i++) // 转为字符串
                        {
                            snprintf(kek_cipher + i * 2, len, "%02X", buff[i]);
                        }
                        strcat(sql, kek_cipher);
                    }
                }
                else if (!strcmp(current_field->name, "iv"))
                {
                    uint16_t iv_len = p_pkg->iv_len;
                    uint8_t buff[iv_len];
                    memcpy(buff, p_pkg->iv, iv_len);
                    uint8_t iv[iv_len * 2];
                    for (int i = 0; i < iv_len; i++) // 转为字符串
                    {
                        snprintf(iv + i * 2, iv_len, "%02X", buff[i]);
                    }
                    strcat(sql, iv);
                }
                else if (!strcmp(current_field->name, "chck_value"))
                {
                    uint16_t chck_len = p_pkg->chck_len;
                    uint8_t buff[chck_len];
                    memcpy(buff, p_pkg->chck_value, chck_len);
                    uint8_t chck[chck_len * 2];
                    for (int i = 0; i < chck_len; i++) // 转为字符串
                    {
                        snprintf(chck + i * 2, chck_len, "%02X", buff[i]);
                    }
                    strcat(sql, chck);
                }
                strcat(sql, "'");

                break;
            case ft_enum:
                strcat(sql, "'");
                if (!strcmp(current_field->name, "key_type"))
                {
                    strcat(sql, ktype_str(p_pkg->meta_data->key_type));
                }
                else if (!strcmp(current_field->name, "key_state"))
                {
                    strcat(sql, kstate_str(p_pkg->meta_data->state));
                }
                else if (!strcmp(current_field->name, "chck_algo"))
                {
                    strcat(sql, chck_algo_str(p_pkg->chck_alg));
                }
                strcat(sql, "'");
                break;
            case ft_uint32t:
                if (!strcmp(current_field->name, "key_len"))
                {
                    size_t sqlLength = strlen((char *)sql); // 计算字符串的长度
                    size_t lastIndex = sqlLength - 1;       // 计算最后一个有效字符的位置
                    snprintf(sql + lastIndex, sizeof(p_pkg->meta_data->length), "%u", p_pkg->meta_data->length);
                }
                else if (!strcmp(current_field->name, "kek_len"))
                {
                    size_t sqlLength = strlen((char *)sql); // 计算字符串的长度
                    size_t lastIndex = sqlLength - 1;       // 计算最后一个有效字符的位置
                    snprintf(sql + lastIndex, sizeof(p_pkg->kek_cipher_len), "%u", p_pkg->kek_cipher_len);
                }

                break;
            case ft_timet: // TODO: check
                if (!strcmp(current_field->name, "creatime"))
                {
                    struct tm *timeinfo = localtime(&(p_pkg->meta_data->creation_time));
                    char buffer[80];
                    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
                    strcat(sql, "'");
                    strcat(sql, buffer);
                    strcat(sql, "'");
                }
                break;
            case ft_uint16t:
                if (!strcmp(current_field->name, "check_len"))
                {
                    size_t sqlLength = strlen((char *)sql);                                        // 计算字符串的长度
                    size_t lastIndex = sqlLength - 1;                                              // 计算最后一个有效字符的位置
                    snprintf(sql + lastIndex, sizeof(p_pkg->chck_len) * 2, "%u", p_pkg->chck_len); // TODO: why is "*2"
                }
                else if (!strcmp(current_field->name, "updatecycle"))
                {
                    size_t sqlLength = strlen((char *)sql); // 计算字符串的长度
                    size_t lastIndex = sqlLength - 1;       // 计算最后一个有效字符的位置
                    snprintf(sql + lastIndex, sizeof(p_pkg->meta_data->update_cycle), "%u", p_pkg->meta_data->update_cycle);
                }
                else if (!strcmp(current_field->name, "iv_len"))
                {
                    size_t sqlLength = strlen((char *)sql); // 计算字符串的长度
                    size_t lastIndex = sqlLength - 1;       // 计算最后一个有效字符的位置
                    snprintf(sql + lastIndex, sizeof(p_pkg->iv_len) * 2, "%u", p_pkg->iv_len);
                }
                else if (!strcmp(current_field->name, "update_count"))
                {
                    // 更新次数计数：0
                    size_t sqlLength = strlen((char *)sql); // 计算字符串的长度
                    size_t lastIndex = sqlLength - 1;       // 计算最后一个有效字符的位置
                    uint16_t update_count = 0;
                    snprintf(sql + lastIndex, sizeof(update_count), "%u", update_count);
                }
                break;
            case ft_end:
                break;
            default:
                break;
            }
        }
        next_field = current_field;
        next_field++; // 指向下一个描述域
        if (next_field->field_type != ft_end)
        {
            strcat(sql, ", ");
        }
        current_field++;
    }
    strcat(sql, ");");
    // printf("Generated SQL statement: %s\n", sql);

    /******************************
     *        执行insert语句       *
     *****************************/

    // 打开数据库
    rc = sqlite3_open(db_name, &db);
    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return LD_ERR_KM_OPEN_DB;
    }

    // 执行插入数据的SQL语句
    rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    // 关闭数据库
    sqlite3_close(db);
    return LD_KM_OK;
}

/**
 * @brief 根据字段类型返回对应的 SQL 类型字符串
 */
const char *sql_type(enum field_type type)
{
    switch (type)
    {
    case ft_uuid:
        return "VARCHAR(128)";
    case ft_enum:
        return "VARCHAR(32)";
    case ft_uint8t_pointer:
        return "VARCHAR(256)";
    case ft_uint32t:
        return "INT";
    case ft_timet:
        return "VARCHAR(128)";
    case ft_uint16t:
        return "INT";
    default:
        return "";
    }
}

/**
 * @bref 基于描述创建密钥表
 */
l_km_err create_table_if_not_exist(struct_desc *sd, uint8_t *db_name, uint8_t *table_name, uint8_t *primary_key)
{
    const field_desc *current_field = sd->fields;

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    uint8_t *query = NULL;
    size_t query_size = 0;
    FILE *stream = open_memstream((char **)&query, &query_size);

    // 打开数据库
    rc = sqlite3_open(db_name, &db);
    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return LD_ERR_KM_OPEN_DB;
    }

    // 根据描述，组装创建表的sql语句
    fprintf(stream, "CREATE TABLE IF NOT EXISTS %s (\n", table_name);
    while (current_field->field_type != ft_end)
    {
        fprintf(stream, "    %s %s", current_field->name, sql_type(current_field->field_type));
        fprintf(stream, ",\n");
        current_field++;
    }
    fprintf(stream, "    PRIMARY KEY (%s)\n", primary_key);
    fprintf(stream, ");\n");
    fclose(stream);

    // 执行创建表的SQL语句
    rc = sqlite3_exec(db, query, 0, 0, &zErrMsg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    sqlite3_close(db); // 关闭数据库
    free(query);       // 释放内存

    return LD_KM_OK;
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

// 回调函数，用于处理查询结果 密钥更新时调用
int query_callback_for_handle(void *data, int argc, char **argv, char **azColName)
{
    Result_Query_for_handle *result = (Result_Query_for_handle *)data;
    if (argc > 0 && argv[0])
    {
        result->key_len = atoi(argv[0]);
    }
    if (argc > 1 && argv[1])
    {
        result->key_cipher = hex_to_bytes(argv[1]);
    }
    if (argc > 2 && argv[2])
    {
        result->kek_len = atoi(argv[2]);
    }
    if (argc > 3 && argv[3])
    {
        result->kek_cipher = hex_to_bytes(argv[3]);
    }
    if (argc > 4 && argv[4])
    {
        result->iv_len = atoi(argv[4]);
    }
    if (argc > 5 && argv[5])
    {
        result->iv = hex_to_bytes(argv[5]);
    }
    return 0;
}

/**
 * @brief 获取密钥句柄
 * @param[in] db_name
 * @param[in] table_name
 * @param[in] id 密钥id
 * @param[out] handle 密钥句柄
 * @return 是否执行成功
 */
l_km_err get_handle_from_db(uint8_t *db_name, uint8_t *table_name, uint8_t *id, CCARD_HANDLE *key_handle)
{
    /* 读取密钥 */
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    Result_Query_for_handle result;

    // 打开数据库
    rc = sqlite3_open(db_name, &db);
    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return LD_ERR_KM_OPEN_DB;
    }

    // 构建查询语句
    char query[MAX_QUERY_RESULT_LENGTH];
    snprintf(query, MAX_QUERY_RESULT_LENGTH, "SELECT key_len, key_cipher, kek_len ,kek_cipher, iv_len, iv FROM %s WHERE id='%s'", table_name, id);

    // 执行查询
    rc = sqlite3_exec(db, query, query_callback_for_handle, &result, &zErrMsg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return LD_ERR_KM_EXE_DB;
    }

    // 关闭数据库
    sqlite3_close(db);

    /* 解密密钥  获取句柄*/
    CCARD_HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄

    // 导入密钥加密密钥
    uint32_t kek_index = 1;
    void *kek_handle;
    int ret;
    ret = SDF_ImportKeyWithKEK(hSessionHandle, ALGO_WITH_KEK, kek_index, result.kek_cipher, result.kek_len, &kek_handle);
    if (ret != LD_KM_OK)
    {
        printf("get key handle : import kek failed!\n");
        return LD_ERR_KM_IMPORT_KEY_WITH_KEK;
    }

    // 解密密钥
    uint8_t key[32]; // 明文密钥
    uint32_t key_len;
    ret = SDF_Decrypt(hSessionHandle, kek_handle, ALGO_ENC_AND_DEC, result.iv, result.key_cipher, result.key_len, key, &key_len);
    if (ret != LD_KM_OK)
    {
        printf("get masterkey handle: decrypt failed!\n");
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

// 回调函数，用于处理kek查询结果
int query_callback_for_kekhandle(void *data, int argc, char **argv, char **azColName)
{
    QueryResult_for_kekhandle *result = (QueryResult_for_kekhandle *)data;
    uint32_t kek_len;
    uint8_t *kek_cipher;

    if (argc > 0 && argv[0]) // kek len
    {
        kek_len = atoi(argv[0]);
    }
    if (argc > 1 && argv[1]) // kek cipher
    {
        kek_cipher = malloc(sizeof(uint8_t) * kek_len);
        kek_cipher = hex_to_bytes(argv[1]);
    }
    if (argc > 2 && argv[2]) // iv len
    {
        result->iv_len = atoi(argv[2]);
    }
    if (argc > 3 && argv[3]) // iv
    {
        result->iv = malloc(sizeof(uint8_t) * result->iv_len);
        result->iv = hex_to_bytes(argv[3]);
    }

    // 导入kek
    if (km_import_key_with_kek(kek_cipher, kek_len, 1, &result->kek_handle) != LD_KM_OK)
    {
        printf("[query_callback_for_kekhandle] import key failed\n");
        return -1;
    }

    return 0;
}

/**
 * @brief 获取kek密钥句柄
 * @param[in] db_name
 * @param[in] table_name
 * @param[in] id 密钥id
 * @return 查询结果
 */
QueryResult_for_kekhandle query_kekhandle(uint8_t *db_name, uint8_t *table_name, uint8_t *id)
{

    /* 读取密钥 */
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    QueryResult_for_kekhandle result;
    do
    {
        // 打开数据库
        rc = sqlite3_open(db_name, &db);
        if (rc)
        {
            fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            break;
        }

        // 构建查询语句
        char query[MAX_QUERY_RESULT_LENGTH];
        snprintf(query, MAX_QUERY_RESULT_LENGTH, "SELECT kek_len ,kek_cipher, iv_len, iv FROM %s WHERE id='%s'", table_name, id);

        // 执行查询
        rc = sqlite3_exec(db, query, query_callback_for_kekhandle, &result, &zErrMsg);
        if (rc != SQLITE_OK)
        {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
            sqlite3_close(db);
            break;
        }

        // 关闭数据库
        sqlite3_close(db);

    } while (0);

    return result;
}

/****************************************************************
 *                              查询                            *
 *****************************************************************/
// 查询id结果结构体
typedef struct
{
    uint8_t id[128];
} Result_Query_id;

// 回调函数，用于处理查询结果
int query_callback_id(void *data, int argc, char **argv, char **azColName)
{
    Result_Query_id *result = (Result_Query_id *)data;
    if (argc > 0 && argv[0])
    {
        strncpy(result->id, argv[0], sizeof(result->id) - 1);
        result->id[sizeof(result->id) - 1] = '\0';
    }
    else
    {
        printf("null query\n");
        memset(result->id, 0, sizeof(result->id));
    }
    return 0;
}



/**
 * @bref 基于所有者和密钥类型查询激活状态的密钥
 * @param key_type 密钥类型
 * @param owner1 所有者
 * @param owner2 所有者
 * @return id:密钥标识，count :查询到的id数量
 *
 */
QueryResult_for_queryid query_id(uint8_t *db_name, uint8_t *table_name, uint8_t *owner1, uint8_t *owner2, enum KEY_TYPE key_type)
{
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    QueryResult_for_queryid results = {.count = 0}; // Initialize results with count as 0

    // Open the database
    rc = sqlite3_open((const char *)db_name, &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return results;
    }

    // Prepare SQL statement
    char sql_stmt[512];
    snprintf(sql_stmt, sizeof(sql_stmt),
             "SELECT id FROM %s WHERE owner1=? AND owner2=? AND key_type=? AND key_state='ACTIVE'",
             table_name);

    // Prepare the query
    rc = sqlite3_prepare_v2(db, sql_stmt, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return results;
    }

    // Bind parameters
    rc = sqlite3_bind_text(stmt, 1, (const char *)owner1, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to bind parameter 1: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return results;
    }

    rc = sqlite3_bind_text(stmt, 2, (const char *)owner2, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to bind parameter 2: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return results;
    }

    rc = sqlite3_bind_text(stmt, 3, ktype_str(key_type), -1, SQLITE_STATIC);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to bind parameter 3: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return results;
    }

    // Execute the query
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        if (results.count < MAX_ID_LEN)
        {
            // Allocate memory for each id
            results.ids[results.count] = malloc(MAX_ID_LEN * sizeof(uint8_t));
            if (results.ids[results.count] == NULL)
            {
                fprintf(stderr, "Failed to allocate memory\n");
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                return results;
            }
            // Copy the id into the array
            strncpy((char *)results.ids[results.count], (const char *)sqlite3_column_text(stmt, 0), MAX_ID_LEN);
            results.count++;
        }
        else
        {
            fprintf(stderr, "Exceeded maximum number of results\n");
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return results;
        }
    }

    // Check for errors or no results found
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "Error in fetching data: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return results;
    }

    // Finalize statement and close database
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return results;
}

// 回调函数，用于处理查询结果 密钥更新时调用
int query_callback_for_update(void *data, int argc, char **argv, char **azColName)
{
    QueryResult_for_update *result = (QueryResult_for_update *)data;
    if (argc > 0 && argv[0])
    {
        result->key_len = atoi(argv[0]);
    }
    if (argc > 1 && argv[1])
    {
        result->update_cycle = atoi(argv[1]);
    }
    if (argc > 2 && argv[2])
    {
        result->update_count = atoi(argv[2]);
    }
    return 0;
}

/**
 * @brief 根据密钥id查询密钥长度 更新周期
 * @param[in] db_name 数据库名
 * @param[in] table_name 表名
 * @param[in] id 密钥id
 * @return 结构体：含密钥长度 更新周期
 */
QueryResult_for_update query_for_update(uint8_t *db_name, uint8_t *table_name, uint8_t *id)
{
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    QueryResult_for_update result;

    // 打开数据库
    rc = sqlite3_open(db_name, &db);
    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        result.key_len = 0;
        result.update_cycle = 0;
        result.update_count = 0;
        return result;
    }

    // 构建查询语句
    char query[MAX_QUERY_RESULT_LENGTH];
    snprintf(query, MAX_QUERY_RESULT_LENGTH, "SELECT key_len, updatecycle , update_count FROM %s WHERE id='%s'", table_name, id);

    // 执行查询
    rc = sqlite3_exec(db, query, query_callback_for_update, &result, &zErrMsg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        result.key_len = 0;
        result.update_cycle = 0;
        result.update_count = 0;
        return result;
    }

    // 关闭数据库
    sqlite3_close(db);

    // 返回查询结果
    return result;
}

/**
 * @brief 修改密钥状态
 * @param[in] db_name 数据库名
 * @param[in] table_name 表名
 * @param[in] id 密钥id
 * @param[in] state 想要改成的密钥状态
 * @return 成功与否
 */
l_km_err alter_keystate(uint8_t *db_name, uint8_t *table_name, uint8_t *id, enum STATE state)
{
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;

    // 打开数据库
    rc = sqlite3_open(db_name, &db);
    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return LD_ERR_KM_OPEN_DB;
    }

    // 构建更新语句
    char query[512];
    snprintf(query, sizeof(query), "UPDATE '%s' SET key_state = '%s' WHERE id = '%s'", table_name, kstate_str(state), id);

    // 执行更新操作
    rc = sqlite3_exec(db, query, NULL, 0, &zErrMsg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return LD_ERR_KM_EXE_DB;
    }

    // 关闭数据库
    sqlite3_close(db);

    return LD_KM_OK;
}

/**
 * @brief 更新计数增加一次
 * @param[in] dbname
 * @param[in] tablename
 * @param[in] id
 * @param[in] dbname
 * @return 成功与否
 */
l_km_err increase_updatecount(uint8_t *dbname, uint8_t *tablename, uint8_t *id)
{
    sqlite3 *db;
    char *err_msg = 0;

    // Open database
    int rc = sqlite3_open(dbname, &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return LD_ERR_KM_OPEN_DB;
    }

    // Construct SQL statement
    char query[256];
    snprintf(query, sizeof(query), "UPDATE %s SET update_count = update_count + 1 WHERE id = '%s'", tablename, id);

    // Execute SQL statement
    rc = sqlite3_exec(db, query, 0, 0, &err_msg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return LD_ERR_KM_EXE_DB;
    }

    // Close database
    sqlite3_close(db);
    return LD_KM_OK;
}

// 回调函数，用于从查询结果中提取密钥值和密钥长度
static int callback_for_query_keyvalue(void *data, int argc, char **argv, char **azColName)
{

    QueryResult_for_keyvalue *result = (QueryResult_for_keyvalue *)data;
    uint32_t kek_len;
    uint8_t *kek;
    uint32_t key_len;
    uint8_t *key_cipher;
    uint32_t iv_len;
    uint8_t *iv;

    if (argc > 0 && argv[0]) // 获取kek_len
    {
        kek_len = atoi(argv[0]);
        kek = malloc(sizeof(uint8_t) * kek_len);
    }
    if (argc > 1 && argv[1]) // 获取kek
    {
        kek = hex_to_bytes(argv[1]);
    }
    if (argc > 2 && argv[2]) // 获取密钥长度
    {
        key_len = atoi(argv[2]);
    }
    if (argc > 3 && argv[3]) // 获取key_cipher
    {
        key_cipher = malloc(sizeof(uint8_t) * result->key_len);
        key_cipher = hex_to_bytes(argv[3]);
    }
    if (argc > 4 && argv[4]) // 获取iv_len
    {
        iv_len = atoi(argv[4]);
    }
    if (argc > 5 && argv[5]) // 获取iv
    {
        iv = malloc(sizeof(uint8_t) * iv_len);
        iv = hex_to_bytes(argv[5]);
    }

    // 导入密钥
    CCARD_HANDLE kek_handle;
    if (km_import_key_with_kek(kek, kek_len, 1, &kek_handle) != LD_KM_OK)
    {
        printf("Error importing kek with kek\n");
        return LD_ERR_KM_IMPORT_KEY_WITH_KEK;
    }

    // 解密密钥
    uint8_t *key;
    if (km_decrypt(kek_handle, ALGO_ENC_AND_DEC, iv, key_cipher, key_len, key, &key_len) != LD_KM_OK)
    {
        printf("Error decrypting key\n");
        return LD_ERR_KM_DECRYPT;
    }

    // 返回密钥明文和密钥长度
    result->key_len = key_len;
    result->key = (uint8_t *)malloc(result->key_len); // 分配空间
    result->key = key;

    return 0;
}

/**
 * @bref 查询密钥
 * @param[in] dbname
 * @param[in] tablename
 * @param id 密钥编号
 * @return key:密钥值，NULL :未查询到结果
 *
 */
// 查询密钥值和密钥长度
QueryResult_for_keyvalue query_keyvalue(uint8_t *db_name, uint8_t *table_name, uint8_t *id)
{
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    uint8_t *key_cipher = NULL;
    QueryResult_for_keyvalue result;

    rc = sqlite3_open(db_name, &db); // 打开数据库
    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        result.key_len = 0;
        result.key = NULL;
        return result;
    }

    // 构建 SQL 查询语句
    char sql[512];
    snprintf(sql, sizeof(sql), "SELECT kek_len, kek_cipher, key_len, key_cipher, iv_len, iv FROM %s WHERE id='%s';", table_name, id);

    // 执行查询
    rc = sqlite3_exec(db, sql, callback_for_query_keyvalue, &result, &zErrMsg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        result.key_len = 0;
        result.key = NULL;
        return result;
    }

    sqlite3_close(db); // 关闭数据库

    return result;
}

// 查询密钥拥有者的函数接口
QueryResult_for_owner query_owner(uint8_t *db_name, uint8_t *table_name, uint8_t *id)
{
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    QueryResult_for_owner result = {NULL, NULL};

    // 打开数据库连接
    rc = sqlite3_open((char *)db_name, &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "无法打开数据库: %s\n", sqlite3_errmsg(db));
        return result;
    }

    // 准备SQL查询语句，根据id查询owner1和owner2
    char *sql = "SELECT owner1, owner2 FROM %s WHERE id = ?";
    char query_sql[256]; // 假设足够大以容纳SQL语句
    snprintf(query_sql, sizeof(query_sql), sql, table_name);

    // 准备SQL语句
    rc = sqlite3_prepare_v2(db, query_sql, -1, &stmt, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL语句准备失败: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return result;
    }

    // 绑定id参数
    sqlite3_bind_text(stmt, 1, (char *)id, -1, SQLITE_STATIC);

    // 执行查询
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
    {
        // 读取查询结果
        const unsigned char *owner1 = sqlite3_column_text(stmt, 0);
        const unsigned char *owner2 = sqlite3_column_text(stmt, 1);

        // 分配内存并复制查询结果
        if (owner1)
        {
            result.owner1 = (uint8_t *)malloc(strlen((const char *)owner1) + 1);
            strcpy((char *)result.owner1, (const char *)owner1);
        }
        if (owner2)
        {
            result.owner2 = (uint8_t *)malloc(strlen((const char *)owner2) + 1);
            strcpy((char *)result.owner2, (const char *)owner2);
        }
    }

    // 释放语句资源
    sqlite3_finalize(stmt);

    // 关闭数据库连接
    sqlite3_close(db);

    return result;
}

// 查询子密钥id接口定义
QueryResult_for_subkey query_subkey(uint8_t *db_name, uint8_t *table_name, uint8_t *id_mk)
{
    sqlite3 *db;
    sqlite3_stmt *stmt;
    QueryResult_for_subkey result = {0, NULL, NULL};

    // 打开数据库连接
    int rc = sqlite3_open(db_name, &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return result;
    }

    // 准备查询语句
    const char *sql = "SELECT id, key_type FROM %s WHERE owner1 = (SELECT owner1 FROM %s WHERE id = ?) AND owner2 = (SELECT owner2 FROM %s WHERE id = ?) AND id != ? AND key_type LIKE '%%SESSION%%' AND key_state = 'ACTIVE'";
    char query[512];
    snprintf(query, sizeof(query), sql, table_name, table_name, table_name);

    // 准备SQL语句
    rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare SQL statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return result;
    }

    // 绑定参数
    sqlite3_bind_text(stmt, 1, id_mk, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, id_mk, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, id_mk, -1, SQLITE_STATIC);

    // 执行查询
    result.count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        result.count++;
        result.subkey_ids = realloc(result.subkey_ids, result.count * sizeof(char *));
        result.key_types = realloc(result.key_types, result.count * sizeof(char *));

        // 获取查询结果
        result.subkey_ids[result.count - 1] = strdup((const char *)sqlite3_column_text(stmt, 0));
        result.key_types[result.count - 1] = strdup((const char *)sqlite3_column_text(stmt, 1));
    }

    // 释放资源
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return result;
}

/**
 * @brief 修改密钥值，将密钥用kek加密存储
 * @param[in] dbname
 * @param[in] tablename
 * @param[in] id 密钥id
 * @param[in] key_len 密钥长度
 * @param[in] 密钥值(明文)
 * @return 修改成功与否
 */
l_km_err alter_keyvalue(uint8_t *db_name, uint8_t *table_name, uint8_t *id, uint16_t key_len, uint8_t *key)
{
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;

    // 打开数据库
    rc = sqlite3_open(db_name, &db);
    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return LD_ERR_KM_OPEN_DB;
    }

    // 获取kek和iv TODO: 未完成
    QueryResult_for_keyvalue result = query_keyvalue(db_name, table_name, id);
    if (!result.key)
    {
        printf("Key not found or error occurred.\n");
    }

    // 获取kek句柄 TODO: 未完成
    CCARD_HANDLE kek_handle;
    // if(km_import_key_with_kek(result.));

    // 对密钥进行加密 TODO: 未完成
    uint8_t *key_cipher;
    // if(km_encrypt(kek_handle, ALGO_ENC_AND_DEC, ));

    // 构建 SQL UPDATE 语句
    char sql[1024];
    snprintf(sql, sizeof(sql), "UPDATE %s SET key_cipher=?, key_len=? WHERE id=?;", table_name);

    // 编译 SQL 语句
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return LD_ERR_KM_EXE_DB;
    }

    // 绑定参数
    rc = sqlite3_bind_text(stmt, 1, bytes_to_hex(key_len, key), -1, SQLITE_STATIC);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return LD_ERR_KM_EXE_DB;
    }
    rc = sqlite3_bind_int(stmt, 2, key_len);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return LD_ERR_KM_EXE_DB;
    }
    rc = sqlite3_bind_text(stmt, 3, (char *)id, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return LD_ERR_KM_EXE_DB;
    }

    // 执行 SQL 语句
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return LD_ERR_KM_EXE_DB;
    }

    // 释放资源
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return LD_KM_OK;
}