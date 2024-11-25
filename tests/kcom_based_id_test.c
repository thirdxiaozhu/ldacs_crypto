#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "key_manage.h"
#include "kmdb.h"

// 错误码定义
#define LD_ERR_KM_QUERY -1

void compare_keys(const char *dbname1, const char *table1, const char *id1,
                  const char *dbname2, const char *table2, const char *id2);

int main()
{
    // 定义数据库名称、表名和密钥ID
    const char *gs_t_name = "GSt";
    const char *as_name = "Berry";
    const char *dbname = "keystore.db";
    const char *as_tablename = "as_keystore";
    const char *gs_s_tablename = "gs_s_keystore";
    const char *gs_t_tablename = "gs_t_keystore";
    QueryResult_for_queryid* qr_mk_1 = query_id(dbname, as_tablename, as_name, gs_t_name, SESSION_KEY_USR_INT, ACTIVE);
    if (qr_mk_1->count == 0)
    {
        log_warn("Query mkid1 failed.\n");
    }

    QueryResult_for_queryid* qr_mk_2 = query_id(dbname, gs_t_tablename, as_name, gs_t_name, SESSION_KEY_USR_INT, ACTIVE);
    if (qr_mk_2->count == 0)
    {
        log_warn("Query mkid1 failed.\n");
    }
    // 对比两个密钥值
    compare_keys(dbname, as_tablename, qr_mk_1->ids[0], dbname, gs_t_tablename, qr_mk_2->ids[0]);

    return 0;
}

void compare_keys(const char *dbname1, const char *table1, const char *id1,
                  const char *dbname2, const char *table2, const char *id2)
{
    // 查询第一个数据库中的密钥
    QueryResult_for_keyvalue *result1 = query_keyvalue(dbname1, table1, id1);
    if (!result1)
    {
        log_warn("Failed to query key from %s, table %s, id %s\n", dbname1, table1, id1);
        return;
    }

    // 查询第二个数据库中的密钥
    QueryResult_for_keyvalue *result2 = query_keyvalue(dbname2, table2, id2);
    if (!result2)
    {
        log_warn("Failed to query key from %s, table %s, id %s\n", dbname2, table2, id2);
        free(result1->key);
        free(result1);
        return;
    }

    // 比较两个密钥值
    if (result1->key_len == result2->key_len && memcmp(result1->key, result2->key, result1->key_len) == 0)
    {
        log_warn("[*OK*] The keys are identical.\n");
    }
    else
    {
        log_warn("[*Fail*] The keys are different.\n");
    }

    // 释放内存
    free(result1->key);
    free(result1);
    free(result2->key);
    free(result2);
}