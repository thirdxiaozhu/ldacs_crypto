#include "kmdb.h"
#include "key_manage.h"
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>

#ifdef USE_SDF

#include <sdf/libsdf.h>
#include <sdfkmt/sdfe-func.h>
#include <sdfkmt/sdfe-type.h>

#elif defined(USE_PIICO)

#include <piico_pc/api.h>
#include <piico_pc/piico_define.h>
#include <piico_pc/piico_error.h>

#endif

#define MAX_QUERY_RESULT_LENGTH 512
#define SQL_QUERY_SIZE 512

#ifndef USE_GMSSL

/**
 * @brief 根据字段类型返回对应的 SQL 类型字符串
 */
//const char *sql_type(enum km_field_type type)
//{
//    switch (type)
//    {
//    case ft_uuid:
//        return "VARCHAR(128)";
//    case ft_enum:
//        return "VARCHAR(32)";
//    case ft_uint8t_pointer:
//        return "VARCHAR(256)";
//    case ft_uint32t:
//        return "INTEGER";
//    case ft_timet:
//        return "VARCHAR(128)";
//    case ft_uint16t:
//        return "INTEGER";
//    default:
//        return "";
//    }
//}

const char *sql_type(enum km_field_type type) {
    switch (type) {
        case ft_uuid:
            return "text";
        case ft_enum:
            return "text";
        case ft_uint8t_pointer:
            return "text";
        case ft_uint32t:
            return "integer";
        case ft_timet:
            return "text";
        case ft_uint16t:
            return "integer";
        default:
            return "";
    }
}


/**
 * @bref 基于描述创建密钥表
 */
l_km_err create_table_if_not_exist(struct_desc *sd, const char *db_name, const char *table_name, uint8_t *primary_key,
                                   const char *foreign_table,
                                   uint8_t *foreign_key, bool is_auto_increase) {
    const km_field_desc *current_field = sd->fields;

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    uint8_t *query = NULL;
    size_t query_size = 0;
    FILE *stream = open_memstream((char **) &query, &query_size);

    // 打开数据库
    rc = sqlite3_open(db_name, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return LD_ERR_KM_OPEN_DB;
    }

    // 根据描述，组装创建表的sql语句
    fprintf(stream, "CREATE TABLE IF NOT EXISTS %s (\n", table_name);
    while (current_field->km_field_type != ft_end) {
        if (strcmp((char *) primary_key, current_field->name) == 0) // 当前字段是主键字段
        {

            if (is_auto_increase == TRUE) // 主键需要自增
            {

                fprintf(stream, "    %s %s PRIMARY KEY AUTOINCREMENT,\n", current_field->name,
                        sql_type(current_field->km_field_type));
            } else // 主键不需要自增
            {

                fprintf(stream, "    %s %s PRIMARY KEY,\n", current_field->name,
                        sql_type(current_field->km_field_type));
            }
        } else {
            fprintf(stream, "    %s %s", current_field->name, sql_type(current_field->km_field_type));
        }
        current_field++;
        if (current_field->km_field_type != ft_end && strcmp((char *) primary_key, (current_field - 1)->name) != 0) {
            // 不是最后一个字段，且不是主键字段时，添加逗号换行
            fprintf(stream, ",\n");
        }
    }

    // 添加外键约束
    if (foreign_table != NULL && foreign_key != NULL) {
        fprintf(stream, ",\n    FOREIGN KEY (%s) REFERENCES %s(id)\n", foreign_key, foreign_table);
    }

    fprintf(stream, ");\n");
    fclose(stream);

    // 打印生成的 SQL 语句
    // printf("Generated SQL: %s\n", query);

    // 执行创建表的SQL语句
    rc = sqlite3_exec(db, query, 0, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);       // 关闭数据库
        free(query);             // 释放内存
        return LD_ERR_KM_EXE_DB; // 返回错误码
    }

    sqlite3_close(db); // 关闭数据库
    free(query);       // 释放内存

    return LD_KM_OK; // 返回成功码
}

/**
 * @brief 按照描述编码和组装结构体 插入指定数据库表
 */
l_km_err store_key(const char *db_name, const char *table_name, struct KeyPkg *pkg, struct_desc *sd) {

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    struct KeyPkg *p_pkg; // 指向结构体的指针 指示当前位置
    p_pkg = pkg;
    const km_field_desc *current_field = sd->fields; // 构建描述指针
    const km_field_desc *next_field;

    int maxSQLLength = 2048; // 分配内存，用于存储 SQL 语句
    char *sql = (char *) malloc(maxSQLLength * sizeof(char));
    if (sql == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        return LD_ERR_KM_MALLOC;
    }

    /******************************
     *  构建 INSERT INTO 语句      *
     *****************************/
    sprintf(sql, "INSERT INTO %s (", table_name);
    // 添加字段名
    while (current_field->km_field_type != ft_end) {
        next_field = current_field;
        next_field++; // 指向下一个描述域
        strcat(sql, current_field->name);
        if (next_field->km_field_type != ft_end) {
            strcat(sql, ", ");
        }
        current_field++;
    }

    // 添加字段值
    current_field = sd->fields;
    strcat(sql, ") VALUES (");
    while (current_field->km_field_type != ft_end) {
        uint8_t uuid[16];
        uint8_t str_uuid[128];
        uint8_t emptyArray[MAX_OWENER_LEN] = {0};
        switch (current_field->km_field_type) // 按照描述解析和重排结构体
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

                if (!strcmp(current_field->name, "owner1")) {
                    if (memcmp(p_pkg->meta_data->owner_1, emptyArray, MAX_OWENER_LEN) == 0) {
                        strcat(sql, "nil (Unspecified)");
                    } else {
                        strcat(sql, p_pkg->meta_data->owner_1);
                    }
                } else if (!strcmp(current_field->name, "owner2")) {

                    if (memcmp(p_pkg->meta_data->owner_1, emptyArray, MAX_OWENER_LEN) == 0) {
                        strcat(sql, "nil (Unspecified)");
                    } else {
                        strcat(sql, p_pkg->meta_data->owner_2);
                    }
                } else if (!strcmp(current_field->name, "key_cipher")) {
                    uint8_t emptyArray[MAX_KEK_CIPHER_LEN] = {0};
                    if (memcmp(p_pkg->kek_cipher, emptyArray, MAX_KEK_CIPHER_LEN) == 0) {
                        strcat(sql, "nil (Unspecified)");
                    } else {
                        uint16_t len = p_pkg->meta_data->length; // TODO: 重复出现 可以抽象成一个接口
                        uint8_t buff[len];
                        memcpy(buff, p_pkg->key_cipher, len);
                        char key_cipher[len * 2 + 1]; // 使用 char 类型，因为 snprintf 生成的是字符
                        for (int i = 0; i < len; i++) // 转为字符串
                        {
                            snprintf(key_cipher + i * 2, len, "%02X", buff[i]); // TODO:CHECK len改成3？剩余key_cipher大小
                        }
                        strcat(sql, key_cipher);
                    }
                } else if (!strcmp(current_field->name, "kek_cipher")) {
                    uint8_t emptyArray[MAX_KEK_CIPHER_LEN] = {0};
                    if (memcmp(p_pkg->kek_cipher, emptyArray, MAX_KEK_CIPHER_LEN) == 0) {
                        strcat(sql, "nil (Unspecified)");
                    } else {
                        uint16_t len = p_pkg->kek_cipher_len;
                        uint8_t buff[len];
                        memcpy(buff, p_pkg->kek_cipher, len);
                        uint8_t kek_cipher[len * 2 + 1];
                        for (int i = 0; i < len; i++) // 转为字符串
                        {
                            snprintf(kek_cipher + i * 2, len, "%02X", buff[i]);
                        }
                        strcat(sql, kek_cipher);
                    }
                } else if (!strcmp(current_field->name, "iv")) {
                    uint16_t iv_len = p_pkg->iv_len;
                    uint8_t buff[iv_len];
                    memcpy(buff, p_pkg->iv, iv_len);
                    uint8_t iv[iv_len * 2 + 1];
                    for (int i = 0; i < iv_len; i++) // 转为字符串
                    {
                        snprintf(iv + i * 2, iv_len, "%02X", buff[i]);
                    }
                    strcat(sql, iv);
                } else if (!strcmp(current_field->name, "chck_value")) {
                    uint16_t chck_len = p_pkg->chck_len;
                    uint8_t buff[chck_len];
                    memcpy(buff, p_pkg->chck_value, chck_len);
                    uint8_t chck[chck_len * 2 + 1];
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
                if (!strcmp(current_field->name, "key_type")) {
                    strcat(sql, ktype_str(p_pkg->meta_data->key_type));
                } else if (!strcmp(current_field->name, "key_state")) {
                    strcat(sql, kstate_str(p_pkg->meta_data->state));
                } else if (!strcmp(current_field->name, "chck_algo")) {
                    strcat(sql, chck_algo_str(p_pkg->chck_alg));
                }
                strcat(sql, "'");
                break;
                case ft_uint32t:
                    if (!strcmp(current_field->name, "key_len")) {
                        size_t sqlLength = strlen((char *) sql); // 计算字符串的长度
                        size_t lastIndex = sqlLength - 1;       // 计算最后一个有效字符的位置
                        snprintf(sql + lastIndex, sizeof(p_pkg->meta_data->length), "%u", p_pkg->meta_data->length);
                    } else if (!strcmp(current_field->name, "kek_len")) {
                        size_t sqlLength = strlen((char *) sql); // 计算字符串的长度
                        size_t lastIndex = sqlLength - 1;       // 计算最后一个有效字符的位置
                        snprintf(sql + lastIndex, sizeof(p_pkg->kek_cipher_len), "%u", p_pkg->kek_cipher_len);
                    }
                break;
                case ft_timet: // TODO: check
                    if (!strcmp(current_field->name, "creatime")) {
                        struct tm *timeinfo = localtime(&(p_pkg->meta_data->creation_time));
                        char buffer[80];
                        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
                        strcat(sql, "'");
                        strcat(sql, buffer);
                        strcat(sql, "'");
                    }
                break;
                case ft_uint16t:
                    if (!strcmp(current_field->name, "check_len")) {
                        size_t sqlLength = strlen((char *) sql); // 计算字符串的长度
                        size_t lastIndex = sqlLength - 1;       // 计算最后一个有效字符的位置
                        snprintf(sql + lastIndex, sizeof(p_pkg->chck_len) * 2, "%u",
                                 p_pkg->chck_len); // TODO: why is "*2"
                    } else if (!strcmp(current_field->name, "updatecycle")) {
                        size_t sqlLength = strlen((char *) sql); // 计算字符串的长度
                        size_t lastIndex = sqlLength - 1;       // 计算最后一个有效字符的位置
                        snprintf(sql + lastIndex, sizeof(p_pkg->meta_data->update_cycle), "%u",
                                 p_pkg->meta_data->update_cycle);
                    } else if (!strcmp(current_field->name, "iv_len")) {
                        size_t sqlLength = strlen((char *) sql); // 计算字符串的长度
                        size_t lastIndex = sqlLength - 1;       // 计算最后一个有效字符的位置
                        snprintf(sql + lastIndex, sizeof(p_pkg->iv_len) * 2, "%u", p_pkg->iv_len);
                    } else if (!strcmp(current_field->name, "update_count")) {
                        // 更新次数计数：0
                        size_t sqlLength = strlen((char *) sql); // 计算字符串的长度
                        size_t lastIndex = sqlLength - 1;       // 计算最后一个有效字符的位置
                        uint16_t update_count = 0;
                        snprintf(sql + lastIndex, sizeof(update_count), "%u", update_count);
                    } else if (!strcmp(current_field->name, "update_count")) {
                        // 更新次数计数：0
                        size_t sqlLength = strlen((char *) sql); // 计算字符串的长度
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
        if (next_field->km_field_type != ft_end) {
            strcat(sql, ", ");
        }
        current_field++;
    }
    strcat(sql, ");");
    // log_warn("Generated SQL statement: %s\n", sql);

    /******************************
     *        执行insert语句       *
     *****************************/

    // 打开数据库
    rc = sqlite3_open(db_name, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return LD_ERR_KM_OPEN_DB;
    }

    // 执行插入数据的SQL语句
    rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    // 关闭数据库
    sqlite3_close(db);

    // 释放变量
    free(sql);
    return LD_KM_OK;
}

/**
 * @brief 存储随机数：为指定密钥存储用于密钥派生的随机数
 * @param[in] db_name 数据库名
 * @param[in] table_name 表名
 * @param[in] id 密钥id
 * @param[in] rand_len 随机数长度
 * @param[in] rand 随机数
 * @return 是否执行成功
 */
l_km_err store_rand(const char *db_name, const char *table_name, uint8_t *key_id, uint32_t rand_len, uint8_t *rand) {
    // 链接数据库
    sqlite3 *db;
    int rc;
    sqlite3_stmt *stmt;
    char *err_msg = NULL;

    // 打开数据库
    rc = sqlite3_open(db_name, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return LD_ERR_KM_OPEN_DB;
    }

    // 构建 SQL 查询语句
    char sql[1024];
    snprintf(sql, sizeof(sql), "INSERT INTO %s (rand_len, rand, key_id) VALUES (?, ?, ?);", table_name);

    // 编译 SQL 语句
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return LD_ERR_KM_EXE_DB;
    }

    // 将随机数转换为十六进制字符串
    uint16_t rand_str_len = rand_len * 2 + 1;
    char *rand_str = bytes_to_hex(rand_len, rand);
    if (!rand_str) {
        sqlite3_close(db);
        return LD_ERR_KM_MALLOC;
    }

    // 绑定参数
    sqlite3_bind_int(stmt, 1, rand_len);
    sqlite3_bind_text(stmt, 2, rand_str, rand_str_len, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, (const char *) key_id, -1, SQLITE_STATIC);

    // 执行 SQL 语句
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        free(rand_str);
        rand_str = NULL;
        return LD_ERR_KM_EXE_DB;
    }

    // 释放资源
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    free(rand_str);
    rand_str = NULL;

    return LD_KM_OK;
}

// 回调函数，用于处理kek查询结果
int query_callback_for_kekhandle(void *data, int argc, char **argv, char **azColName) {
    QueryResult_for_kekhandle *result = (QueryResult_for_kekhandle *) data;
    uint32_t kek_len, iv_len;
    uint8_t *kek_cipher = NULL, *iv = NULL;

    if (argc < 4 || !argv[0] || !argv[1] || !argv[2] || !argv[3]) {
        log_warn("[query_callback_for_kekhandle] 参数无效\n");
        return 1;
    }

    kek_len = atoi(argv[0]);
    kek_cipher = hex_to_bytes(argv[1]); // 假设 hex_to_bytes 函数实现了 hex 字符串到字节数组的转换
    iv_len = atoi(argv[2]);
    iv = hex_to_bytes(argv[3]);

    if (kek_cipher == NULL || iv == NULL) {
        log_warn("[query_callback_for_kekhandle] 内存分配失败\n");
        if (kek_cipher != NULL) {
            free(kek_cipher);
        }
        if (iv != NULL) {
            free(iv);
        }
        return 1;
    }

    if (km_import_key_with_kek(kek_cipher, kek_len, 1, &result->kek_handle) != LD_KM_OK) {
        log_warn("[query_callback_for_kekhandle] import key failed\n");
        free(kek_cipher);
        free(iv);
        return -1;
    }

    result->iv_len = iv_len;
    result->iv = iv;

    return 0;
}

/**
 * @brief 获取kek密钥句柄
 * @param[in] db_name
 * @param[in] table_name
 * @param[in] id 密钥id
 * @return 查询结果
 */
QueryResult_for_kekhandle *query_kekhandle(uint8_t *db_name, uint8_t *table_name, uint8_t *id) {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    QueryResult_for_kekhandle *result = (QueryResult_for_kekhandle *) malloc(sizeof(QueryResult_for_kekhandle));
    if (result == NULL) {
        log_warn("内存分配失败\n");
        return NULL;
    }

    memset(result, 0, sizeof(QueryResult_for_kekhandle));

    // 打开数据库
    rc = sqlite3_open((const char *) db_name, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return result; // 返回未初始化的结果
    }

    // 构建查询语句
    char *sql_query = NULL;
    asprintf(&sql_query, "SELECT kek_len, kek_cipher, iv_len, iv FROM %s WHERE id='%s'", table_name, id);

    rc = sqlite3_exec(db, sql_query, query_callback_for_kekhandle, result, &zErrMsg);
    free(sql_query);

    if (rc != SQLITE_OK) {
        log_warn("查询失败: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        free(result);
        return NULL;
    }

    // 在实际应用中，可能需要更多错误处理逻辑
    if (result->kek_handle == NULL || result->iv == NULL) {
        free(result->kek_handle);
        free(result->iv);
        free(result);
        return NULL;
    }

    return result;
}

/**
 * @brief 释放 QueryResult_for_kekhandle 结构体所占用的内存
 * @param[in] result 指向 QueryResult_for_kekhandle 结构体的指针
 */
void free_kekhandle_result(QueryResult_for_kekhandle *result) {
    if (result != NULL) {
        // 释放 iv 指向的内存
        if (result->iv != NULL) {
            free(result->iv);
        }

        // 释放结构体本身的内存
        free(result);
    }
}
/****************************************************************
 *                              查询                            *
 *****************************************************************/

/**
 * @bref 基于所有者和密钥类型查询激活状态的密钥
 * @param key_type 密钥类型
 * @param owner1 所有者
 * @param owner2 所有者
 * @return id:密钥标识，count :查询到的id数量
 *
 */

// 查询回调函数
static int queryid_callback(void *data, int argc, char **argv, char **azColName) {
    // log_warn("Callback called: argc = %d\n", argc);
    // log_warn("Callback called, argv[0]: %s\n", argv[0] ? argv[0] : "NULL");

    QueryResult_for_queryid *result = (QueryResult_for_queryid *) data;

    if (result->count >= MAX_QUERY_RESULT_LENGTH) {
        // 达到最大ID数量限制，停止处理
        return 1;
    }

    if (argv[0] != NULL) {
        size_t id_len = strlen(argv[0]) + 1;
        result->ids[result->count] = (char *) malloc(id_len);
        if (result->ids[result->count] == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            return 1; // 触发错误处理
        }
        strcpy(result->ids[result->count], argv[0]);
        result->count++;
    }

    return 0; // 继续处理下一个结果
}

/**
 * @bref 基于所有者和密钥类型查询激活状态的密钥
 * @param key_type 密钥类型
 * @param owner1 所有者
 * @param owner2 所有者
 * @return id:密钥标识，count :查询到的id数量
 *
 */
QueryResult_for_queryid *
query_id(const char *db_name, const char *table_name, const char *owner1, const char *owner2, enum KEY_TYPE key_type,
         enum STATE state) {
    QueryResult_for_queryid *result = (QueryResult_for_queryid *) malloc(sizeof(QueryResult_for_queryid));
    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    memset(result, 0, sizeof(QueryResult_for_queryid));

    sqlite3 *db;
    char *err_msg = NULL;

    // 打开数据库
    if (sqlite3_open(db_name, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        free_queryid_result(result);
        return NULL;
    }

    char query[1024];
    snprintf(query, sizeof(query),
             "SELECT id FROM %s WHERE owner1='%s' AND owner2='%s' AND key_type='%s' AND key_state='%s' ORDER BY creatime DESC",
             table_name, owner1, owner2, ktype_str(key_type), kstate_str(state));
    // log_warn("query: %s\n", query);

    // 执行查询
    if (sqlite3_exec(db, query, queryid_callback, result, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        free_queryid_result(result);
        return NULL;
    }

    // 关闭数据库
    sqlite3_close(db);
    return result;
}

void free_queryid_result(QueryResult_for_queryid *result) {
    if (result == NULL)
        return;

    // 遍历 ids 数组，释放每个指针指向的内存
    for (uint32_t i = 0; i < result->count; i++) {
        if (result->ids[i] != NULL) {
            free(result->ids[i]);
            result->ids[i] = NULL; // 避免悬挂指针
        }
    }
    free(result);
    result = NULL;
}

// 回调函数，用于处理查询结果 密钥更新时调用
int query_callback_for_update(void *data, int argc, char **argv, char **azColName) {
    QueryResult_for_update *result = (QueryResult_for_update *) data;

    // 假设查询返回的数据按顺序是 key_len, update_cycle, update_count
    if (argc == 3) {
        result->key_len = (uint16_t) atoi(argv[0]);
        result->update_cycle = (uint16_t) atoi(argv[1]);
        result->update_count = (uint16_t) atoi(argv[2]);
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
QueryResult_for_update *query_for_update(uint8_t *db_name, uint8_t *table_name, uint8_t *id) {
    sqlite3 *db;
    char *err_msg = NULL;
    QueryResult_for_update *result = (QueryResult_for_update *) malloc(sizeof(QueryResult_for_update));

    if (result == NULL) {
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }

    // 打开数据库
    int rc = sqlite3_open((const char *) db_name, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "无法打开数据库: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        free(result);
        return NULL;
    }

    // 准备 SQL 查询语句
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT key_len, updatecycle, update_count FROM %s WHERE id = '%s';", table_name, id);

    // 执行 SQL 查询
    rc = sqlite3_exec(db, sql, query_callback_for_update, result, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL 查询失败: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        free(result);
        return NULL;
    }

    // 关闭数据库
    sqlite3_close(db);

    return result;
}

void free_update_result(QueryResult_for_update *result) {
    if (result != NULL) {
        // 释放结构体本身的内存
        free(result);
    }
}

uint32_t query_keylen(uint8_t *db_name, uint8_t *table_name, uint8_t *id) {
    sqlite3 *db;
    char *err_msg = 0;
    int rc;
    uint32_t key_len = 0;
    char sql[256];

    // 打开数据库
    rc = sqlite3_open((const char *) db_name, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    // 构建SQL查询语句
    snprintf(sql, sizeof(sql), "SELECT key_len FROM %s WHERE id = ?", table_name);

    // 执行SQL查询
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    // 绑定参数
    sqlite3_bind_text(stmt, 1, (const char *) id, -1, SQLITE_STATIC);

    // 执行查询
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        key_len = sqlite3_column_int(stmt, 0);
    } else {
        fprintf(stderr, "No row found for id: %s\n", id);
    }

    // 清理
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return key_len;
}

/**
 * @brief 修改密钥状态
 * @param[in] db_name 数据库名
 * @param[in] table_name 表名
 * @param[in] id 密钥id
 * @param[in] state 想要改成的密钥状态
 * @return 成功与否
 */
l_km_err alter_keystate(const char *db_name, const char *table_name, uint8_t *id, enum STATE state) {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;

    // 打开数据库
    rc = sqlite3_open(db_name, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return LD_ERR_KM_OPEN_DB;
    }

    // 构建更新语句
    char query[512];
    snprintf(query, sizeof(query), "UPDATE '%s' SET key_state = '%s' WHERE id = '%s'", table_name, kstate_str(state),
             id);

    // 执行更新操作
    rc = sqlite3_exec(db, query, NULL, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
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
 * @brief 启用密钥
 */
l_km_err enable_key(const char *db_name, const char *table_name, const char *id) {
    // 修改状态为ACTIVE
    if (alter_keystate(db_name, table_name, (uint8_t *) id, ACTIVE) != LD_KM_OK) {
        return LD_ERR_KM_ALTERDB;
    }

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
l_km_err increase_updatecount(uint8_t *dbname, uint8_t *tablename, uint8_t *id) {
    sqlite3 *db;
    char *err_msg = 0;

    // Open database
    int rc = sqlite3_open(dbname, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return LD_ERR_KM_OPEN_DB;
    }

    // Construct SQL statement
    char query[256];
    snprintf(query, sizeof(query), "UPDATE %s SET update_count = update_count + 1 WHERE id = '%s'", tablename, id);

    // Execute SQL statement
    rc = sqlite3_exec(db, query, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
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
static int callback_for_query_keyvalue(void *data, int argc, char **argv, char **azColName) {
    QueryResult_for_keyvalue *result = (QueryResult_for_keyvalue *) data;

    // 默认值
    result->key_len = 0;
    result->key = NULL;

    if (argc == 0) // 没有返回数据
    {
        log_warn("Error: No data returned from query\n");
        return LD_ERR_KM_QUERY; // 假设有一个错误码表示没有数据
    }

    uint32_t kek_len = 0;
    uint8_t *kek = NULL;
    uint32_t key_len = 0;
    uint8_t *key_cipher = NULL;
    uint32_t iv_len = 0;
    uint8_t *iv_enc = NULL;
    uint8_t *iv_mac = NULL;
    uint8_t *check_algo = NULL;
    uint32_t check_len = 0;
    uint8_t *rcvd_chck_value = NULL;
    uint8_t *calc_chck_value = NULL;

    // 获取 kek_len
    if (argc > 0 && argv[0] != NULL) {
        kek_len = atoi(argv[0]);
        if (kek_len > 0) {
            kek = hex_to_bytes(argv[1]);
            if (kek == NULL) {
                log_warn("Error: Conversion of kek failed\n");
                return LD_ERR_KM_CONVERT;
            }
        }
    }
    // log_buf(LOG_WARN, "kek", kek, kek_len);

    // 获取 key_len
    if (argc > 2 && argv[2] != NULL) {
        key_len = atoi(argv[2]);
    }

    // 获取 key_cipher
    if (argc > 3 && argv[3] != NULL) {
        if (key_len > 0) {
            key_cipher = hex_to_bytes(argv[3]);
            if (key_cipher == NULL) {
                log_warn("Error: Conversion of key_cipher failed\n");
                free(kek);
                return LD_ERR_KM_CONVERT;
            }
        }
    }

    // 获取 iv_len
    if (argc > 4 && argv[4] != NULL) {
        iv_len = atoi(argv[4]);
        iv_enc = malloc(sizeof(uint8_t) * iv_len);
        iv_mac = malloc(sizeof(uint8_t) * iv_len);
    }

    // 获取 iv
    if (argc > 5 && argv[5] != NULL) {
        if (iv_len > 0) {
            iv_enc = hex_to_bytes(argv[5]);
            memcpy(iv_mac, iv_enc, iv_len);

            if (iv_enc == NULL) {
                log_warn("Error: Conversion of iv failed\n");
                free(key_cipher);
                free(kek);
                return LD_ERR_KM_CONVERT;
            }
        }
    }
    // log_buf(LOG_WARN, "iv", iv_mac, iv_len);

    // 获取校验值
    if (argc > 8 && argv[6] != NULL && argv[7] >= 0 && argv[8] != NULL) {
        // 获取校验算法
        check_algo = argv[6];

        // 获取校验值长度
        check_len = atoi(argv[7]);

        // 获取校验值
        rcvd_chck_value = malloc(sizeof(uint8_t) * check_len);
        calc_chck_value = malloc(sizeof(uint8_t) * check_len);
        rcvd_chck_value = hex_to_bytes(argv[8]);

        // log_buf(LOG_WARN, "check", rcvd_chck_value, check_len);
    }
    // log_info("check algo %s\n", check_algo);

    // 导入密钥
    void *kek_handle;
    if (kek != NULL && km_import_key_with_kek(kek, kek_len, 1, &kek_handle) != LD_KM_OK) {
        log_warn("Error importing kek with kek\n");
        free(kek);
        free(key_cipher);
        free(iv_enc);
        free(iv_mac);
        return LD_ERR_KM_IMPORT_KEY_WITH_KEK;
    }

    // 解密密钥
    uint8_t *key = malloc(sizeof(uint8_t) * key_len);
    if (key == NULL) {
        log_warn("Error: Memory allocation failed for key\n");
        free(kek);
        free(key_cipher);
        free(iv_enc);
        free(iv_mac);
        return LD_ERR_KM_MALLOC;
    }
    // log_buf(LOG_WARN, "keycipher", key_cipher, key_len);

    if (km_decrypt(kek_handle, ALGO_ENC_AND_DEC, iv_enc, key_cipher, key_len, key, &key_len) != LD_KM_OK) {
        log_warn("Error decrypting key\n");
        free(key);
        free(kek);
        free(key_cipher);
        free(iv_enc);
        free(iv_mac);
        return LD_ERR_KM_DECRYPT;
    }
    // log_buf(LOG_WARN, "decrypted key", key, key_len);

    /* 校验明文密钥完整性 */
    // 计算校验值
    if (km_mac(kek_handle, str_to_chck_algo(check_algo), iv_mac, key, key_len, calc_chck_value, &check_len) !=
        LD_KM_OK) {
        log_warn("Error in derive : SDF_CalculateMAC failed!\n");
    }
    // log_buf(LOG_WARN, "rcvd_chck_value", rcvd_chck_value, check_len);
    // log_buf(LOG_WARN, "calc_chck_value", calc_chck_value, check_len);

    // 对比校验值
    if (memcmp(rcvd_chck_value, calc_chck_value, check_len) != 0) {
        log_warn("Error in verify : key integrity  verified failed!\n");
        return LD_ERR_KM_KEY_VERIFY;
    }

    // 返回密钥明文和密钥长度
    result->key_len = key_len;
    result->key = malloc(result->key_len);
    if (result->key == NULL) {
        log_warn("Error: Memory allocation failed for result key\n");
        free(key);
        free(kek);
        free(key_cipher);
        free(iv_enc);
        free(iv_mac);
        free(rcvd_chck_value);
        free(calc_chck_value);
        return LD_ERR_KM_MALLOC;
    }
    memcpy(result->key, key, result->key_len);

    // 释放临时变量
    free(key);
    free(kek);
    free(key_cipher);
    free(iv_enc);
    free(iv_mac);
    free(rcvd_chck_value);
    free(calc_chck_value);
    return LD_KM_OK;
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
QueryResult_for_keyvalue *query_keyvalue(uint8_t *db_name, uint8_t *table_name, uint8_t *id) {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    uint8_t *key_cipher = NULL;
    QueryResult_for_keyvalue *result = malloc(sizeof(QueryResult_for_keyvalue));

    rc = sqlite3_open(db_name, &db); // 打开数据库
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        result->key_len = 0;
        result->key = NULL;
        return NULL;
    }

    // 构建 SQL 查询语句
    char sql[512];
    snprintf(sql, sizeof(sql),
             "SELECT kek_len, kek_cipher, key_len, key_cipher, iv_len, iv, chck_algo, check_len, chck_value  FROM %s WHERE id='%s' ORDER BY creatime DESC;",
             table_name, id);

    // 执行查询
    rc = sqlite3_exec(db, sql, callback_for_query_keyvalue, result, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        result->key_len = 0;
        result->key = NULL;
        return result;
    }

    sqlite3_close(db); // 关闭数据库

    return result;
}

QueryResult_for_keyvalue *query_keyvalue_by_owner(uint8_t *db_name, uint8_t *table_name, const char *owner1,
                                                  const char *owner2, enum KEY_TYPE key_type, enum STATE state)
{
    // query id
    QueryResult_for_queryid *qr = query_id(db_name, table_name, owner1, owner2, key_type, state);
    if (qr->count != 1)
    {
        log_warn("Query key-id failed, so that query keyvalue failed.\n");
        free_queryid_result(qr);
        return LD_ERR_KM_QUERY;
    }

    // query keyvalue
    QueryResult_for_keyvalue *result = query_keyvalue(db_name, table_name, qr->ids[0]);
    if (!result)
    {
        log_warn("Failed to query key from %s, table %s, id %s\n", db_name, table_name, qr->ids[0]);
        free_keyvalue_result(result);
        return NULL;
    }

    free_queryid_result(qr);
    return result;

}
/**
 * @brief 释放 QueryResult_for_keyvalue 结构体所占用的内存
 * @param[in] result 指向 QueryResult_for_keyvalue 结构体的指针
 */
void free_keyvalue_result(QueryResult_for_keyvalue *result) {
    if (result != NULL) {
        // 释放 key 指向的内存
        if (result->key != NULL) {
            free(result->key);
            result->key = NULL;
        }

        // 释放结构体本身的内存
        free(result);
    }
}

/* 查询随机数 */
QueryResult_for_rand *query_rand(const char *db_name, const char *table_name, const char *key_id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    QueryResult_for_rand *result = NULL;

    // 打开数据库
    if (sqlite3_open(db_name, &db) != SQLITE_OK) {
        fprintf(stderr, "无法打开数据库: %s\n", sqlite3_errmsg(db));
        return NULL;
    }

    // 准备 SQL 查询语句
    char sql[512];
    snprintf(sql, sizeof(sql), "SELECT rand, rand_len FROM %s WHERE key_id='%s';",
             table_name, key_id);

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "无法准备语句: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    // 绑定 id 参数
    sqlite3_bind_text(stmt, 1, key_id, -1, SQLITE_TRANSIENT);

    // 执行查询并处理结果
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = malloc(sizeof(QueryResult_for_rand));
        if (!result) {
            fprintf(stderr, "内存分配失败\n");
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return NULL;
        }

        // 提取随机数长度
        result->rand_len = sqlite3_column_int(stmt, 1);

        // 提取随机数
        uint8_t *rand_value = hex_to_bytes(sqlite3_column_text(stmt, 0));
        // printbuff("query rand", rand_value, result->rand_len);
        if (rand_value) {
            result->rand = malloc(result->rand_len);
            if (!result->rand) {
                fprintf(stderr, "内存分配失败\n");
                free(result);
                free(rand_value);
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                return NULL;
            }
            memcpy(result->rand, rand_value, result->rand_len);
            free(rand_value);
        } else {
            result->rand_len = 0;
            result->rand = NULL;
        }
    } else {
        fprintf(stderr, "未找到对应的记录\n");
    }

    // 清理
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return result;
}

/**
 * @brief 释放 QueryResult_for_rand 结构体所占用的内存
 * @param[in] result 指向 QueryResult_for_rand 结构体的指针
 */
void free_rand_result(QueryResult_for_rand *result) {
    if (result == NULL) {
        return; // 如果传入的指针为空，直接返回
    }

    // 释放动态分配的 rand 数组
    if (result->rand != NULL) {
        free(result->rand);
        result->rand = NULL; // 防止悬挂指针
    }

    // 释放结构体本身的内存
    free(result);
}

// 查询密钥拥有者的函数接口
QueryResult_for_owner *query_owner(uint8_t *db_name, uint8_t *table_name, uint8_t *id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    // 非空检查
    if (id == "" || *id == 0) {
        fprintf(stderr, "输入的id为空: %s\n", sqlite3_errmsg(db));
        return NULL;
    }
    // 打开数据库连接
    rc = sqlite3_open(db_name, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "无法打开数据库: %s\n", sqlite3_errmsg(db));
        return NULL;
    }

    QueryResult_for_owner *result = malloc(sizeof(QueryResult_for_owner));
    if (result == NULL) {
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }
    result->owner1 = NULL;
    result->owner2 = NULL;

    // 准备SQL查询语句
    char query_sql[256];
    snprintf(query_sql, sizeof(query_sql), "SELECT owner1, owner2 FROM %s WHERE id = ?", table_name);

    // 准备SQL语句
    rc = sqlite3_prepare_v2(db, query_sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL语句准备失败: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        free(result); // 释放 result 内存
        return NULL;
    }

    // 绑定id参数
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

    // 执行查询
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // 读取查询结果
        const unsigned char *owner1 = sqlite3_column_text(stmt, 0);
        const unsigned char *owner2 = sqlite3_column_text(stmt, 1);

        if (owner1) {
            result->owner1 = (uint8_t *) malloc(strlen((const char *) owner1) + 1);
            if (result->owner1) {
                strcpy((char *) result->owner1, (const char *) owner1);
            }
        }
        if (owner2) {
            result->owner2 = (uint8_t *) malloc(strlen((const char *) owner2) + 1);
            if (result->owner2) {
                strcpy((char *) result->owner2, (const char *) owner2);
            }
        }
    } else {
        fprintf(stderr, "未找到匹配记录: %s\n", sqlite3_errmsg(db));
        free(result->owner1); // 释放 owner1 内存
        free(result->owner2); // 释放 owner2 内存
        free(result);         // 释放 result 内存
        result = NULL;        // 设置 result 为 NULL
    }

    // 释放语句资源
    sqlite3_finalize(stmt);

    // 关闭数据库连接
    sqlite3_close(db);

    return result;
}

/**
 * @brief 释放 QueryResult_for_owner 结构体所占用的内存
 * @param[in] result 指向 QueryResult_for_owner 结构体的指针
 */
void free_owner_result(QueryResult_for_owner *result) {
    if (result != NULL) {
        // 释放 owner1 的内存
        if (result->owner1 != NULL) {
            free(result->owner1);
        }

        // 释放 owner2 的内存
        if (result->owner2 != NULL) {
            free(result->owner2);
        }

        // 释放结构体本身的内存
        free(result);
    }
}

// 查询子密钥id接口定义
QueryResult_for_subkey *query_subkey(uint8_t *db_name, uint8_t *table_name, uint8_t *id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    QueryResult_for_subkey *result = (QueryResult_for_subkey *) malloc(sizeof(QueryResult_for_subkey));
    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    result->count = 0;
    result->subkey_ids = NULL;
    result->key_types = NULL;

    // 打开数据库连接
    int rc = sqlite3_open((const char *) db_name, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        free(result);
        return NULL;
    }

    // 获取密钥类型
    enum KEY_TYPE key_type = query_keytype(db_name, table_name, id);

    // 准备查询语句
    uint8_t sql[SQL_QUERY_SIZE];
    if (key_type == ROOT_KEY) {
        snprintf((char *) sql,
                 SQL_QUERY_SIZE,
                 "SELECT id, key_type FROM %s WHERE owner1 = (SELECT owner1 FROM %s WHERE id = ?) AND id != ?",
                 table_name, table_name);
    } else if (key_type == MASTER_KEY_AS_GS) {
        snprintf((char *) sql,
                 SQL_QUERY_SIZE,
                 "SELECT id, key_type FROM %s WHERE owner1 = (SELECT owner1 FROM %s WHERE id = ?) AND owner2 = (SELECT owner2 FROM %s WHERE id = ?) AND id != ? AND key_type LIKE '%%SESSION%%'",
                 table_name, table_name, table_name);
    } else if (key_type == MASTER_KEY_AS_SGW) {
        snprintf((char *) sql,
                 SQL_QUERY_SIZE,
                 "SELECT id, key_type FROM %s WHERE owner1 = (SELECT owner1 FROM %s WHERE id = ?) AND id != ? AND (key_type LIKE '%%SESSION%%' or key_type = 'MASTER_KEY_AS_GS' or key_type = 'NH KEY')",
                 table_name, table_name);
    } else {
        sqlite3_close(db);
        free(result);
        return NULL;
    }

    // 准备SQL语句
    rc = sqlite3_prepare_v2(db, (const char *) sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare SQL statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        free(result);
        return NULL;
    }

    // 绑定参数
    sqlite3_bind_text(stmt, 1, (const char *) id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, (const char *) id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, (const char *) id, -1, SQLITE_STATIC);

    // 执行查询
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        result->count++;
        result->subkey_ids = realloc(result->subkey_ids, result->count * sizeof(char *));
        result->key_types = realloc(result->key_types, result->count * sizeof(char *));

        if (result->subkey_ids == NULL || result->key_types == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            // 释放之前分配的内存
            for (int i = 0; i < result->count - 1; i++) {
                free(result->subkey_ids[i]);
                free(result->key_types[i]);
            }
            free(result->subkey_ids);
            free(result->key_types);
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            free(result);
            return NULL;
        }

        // 获取查询结果
        result->subkey_ids[result->count - 1] = strdup((const char *) sqlite3_column_text(stmt, 0));
        result->key_types[result->count - 1] = strdup((const char *) sqlite3_column_text(stmt, 1));
    }

    // 释放资源
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return result;
}

// 释放 QueryResult_for_subkey 内存的函数
void free_query_result_for_subkey(QueryResult_for_subkey *result) {
    if (result == NULL) {
        return;
    }

    if (result->subkey_ids != NULL) {
        for (int i = 0; i < result->count; i++) {
            free(result->subkey_ids[i]);
        }
        free(result->subkey_ids);
    }

    if (result->key_types != NULL) {
        for (int i = 0; i < result->count; i++) {
            free(result->key_types[i]);
        }
        free(result->key_types);
    }

    free(result);
}

/**
 * @brief 查询密钥类型

 */
// Function to query key type
enum KEY_TYPE query_keytype(uint8_t *db_name, uint8_t *table_name, uint8_t *id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char *sql;
    int rc;
    enum KEY_TYPE key_type = -1;

    // 打开数据库连接
    rc = sqlite3_open(db_name, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return key_type;
    }

    // 构建查询语句
    asprintf(&sql, "SELECT key_type FROM %s WHERE id='%s'", table_name, id);

    // 准备查询
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        free(sql);
        return key_type;
    }

    // 执行查询
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char *key_type_str = (const char *) sqlite3_column_text(stmt, 0);
        if (key_type_str != NULL) {
            // 根据查询结果设置密钥类型枚举值
            key_type = str_to_ktype(key_type_str);
            // 可以根据实际情况继续添加其他密钥类型的判断
        }
    }

    // 清理资源
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    free(sql);

    return key_type;
}

enum STATE query_state(uint8_t *db_name, uint8_t *table_name, uint8_t *id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char *sql;
    int rc;
    enum STATE state = -1;

    // 打开数据库连接
    rc = sqlite3_open(db_name, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return state;
    }

    // 构建查询语句
    asprintf(&sql, "SELECT key_state FROM %s WHERE id='%s'", table_name, id);

    // 准备查询
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        free(sql);
        return state;
    }

    // 执行查询
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char *key_state_str = (const char *) sqlite3_column_text(stmt, 0);
        if (key_state_str != NULL) {
            // 根据查询结果设置密钥类型枚举值
            state = str_kstate(key_state_str);
            // 可以根据实际情况继续添加其他密钥状态的判断
        }
    }

    // 清理资源
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    free(sql);

    return state;
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
l_km_err alter_keyvalue(uint8_t *db_name, uint8_t *table_name, uint8_t *id, uint16_t key_len, uint8_t *key) {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;

    // 打开数据库
    rc = sqlite3_open(db_name, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return LD_ERR_KM_OPEN_DB;
    }

    // 构建 SQL UPDATE 语句
    char sql[1024];
    snprintf(sql, sizeof(sql), "UPDATE %s SET key_cipher=?, key_len=? WHERE id=?;", table_name);

    // 编译 SQL 语句
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return LD_ERR_KM_EXE_DB;
    }

    // 绑定参数
    rc = sqlite3_bind_text(stmt, 1, bytes_to_hex(key_len, key), -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return LD_ERR_KM_EXE_DB;
    }
    rc = sqlite3_bind_int(stmt, 2, key_len);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return LD_ERR_KM_EXE_DB;
    }
    rc = sqlite3_bind_text(stmt, 3, (char *) id, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return LD_ERR_KM_EXE_DB;
    }

    // 执行 SQL 语句
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
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

#endif
