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
    const char *dbname1 = "keystore.db";
    const char *table1 = "as_keystore";
    const char *id1 = "45a6fa56-19c1-4ebc-8e44-89dff41010d6";
    
    const char *dbname2 = "keystore.db";
    const char *table2 = "gs_t2_keystore";
    const char *id2 = "9666bf2d-b9dc-4715-bb5c-cff8ef2facbb";

    // 对比两个密钥值
    compare_keys(dbname1, table1, id1, dbname2, table2, id2);

    return 0;
}

void compare_keys(const char *dbname1, const char *table1, const char *id1,
                  const char *dbname2, const char *table2, const char *id2)
{
    // 查询第一个数据库中的密钥
    QueryResult_for_keyvalue *result1 = query_keyvalue(dbname1, table1, id1);
    if (!result1)
    {
        printf("Failed to query key from %s, table %s, id %s\n", dbname1, table1, id1);
        return;
    }

    // 查询第二个数据库中的密钥
    QueryResult_for_keyvalue *result2 = query_keyvalue(dbname2, table2, id2);
    if (!result2)
    {
        printf("Failed to query key from %s, table %s, id %s\n", dbname2, table2, id2);
        free(result1->key);
        free(result1);
        return;
    }

    // 比较两个密钥值
    if (result1->key_len == result2->key_len && memcmp(result1->key, result2->key, result1->key_len) == 0)
    {
        printf("[*OK*] The keys are identical.\n");
    }
    else
    {
        printf("[*Fail*] The keys are different.\n");
    }

    // 释放内存
    free(result1->key);
    free(result1);
    free(result2->key);
    free(result2);
}