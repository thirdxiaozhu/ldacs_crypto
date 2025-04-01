#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>  // for malloc, realloc
#include <sqlite3.h> // SQLite library

#define MAX_STRING_LEN 256
#include "key_manage.h"
#include "kmdb.h"

int main()
{
    // Example usage of query_id function

    uint8_t *db_name = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";

    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs_s = "GS1";
    uint8_t *sac_gs_t = "GSt";
    uint8_t *sac_as = "Berry";
    enum KEY_TYPE key_type = MASTER_KEY_AS_GS; // Assume KEY_TYPE is defined somewhere
    enum STATE state = SUSPENDED;

    // 调用 query_id 函数
    QueryResult_for_queryid *result = query_id(db_name, sgw_tablename, sac_as, sac_gs_s, key_type, state);
    if (result->count == 0)
    {
        log_warn("Query mkid failed, null id.\n");
    }
    else if (result->count > 1) // TODO: check ununique id
    {
        log_warn("Query mkid failed, id is not unique.\n");
    }

    // 处理查询结果
    if (result != NULL)
    {
        for (uint32_t i = 0; i < result->count; i++)
        {
            log_warn("ID: %s\n", result->ids[i]);
        }
        // 释放查询结果
    }
    else
    {
        log_warn("No results found or query failed.\n");
    }
    free_queryid_result(result);
    return 0;
}