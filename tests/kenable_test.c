#include <stdio.h>
#include "kmdb.h"
#include "key_manage.h"

int main()
{
    const char *dbname = "keystore.db";
    const char *sgw_tablename = "sgw_keystore";
    const char *as_tablename = "as_keystore";
    const char *sgw_name = "SGW";
    const char *as_name = "Berry";
    enum KEY_TYPE key_type = ROOT_KEY;

    // 激活sgw端根密钥
    QueryResult_for_queryid* query_result = query_id(dbname, sgw_tablename, as_name, sgw_name, key_type, PRE_ACTIVATION);
    if (query_result != NULL)
    {
        if (enable_key(dbname, sgw_tablename, query_result->ids[0]) != LD_KM_OK)
        {
            printf("enable key failed\n");
        }
    }
    else
    {
        printf("query failed. query count %d\n", query_result->count);
        return LD_ERR_KM_QUERY; // 查询失败
    }
    printf("enable sgw root key OK\n");

    // 激活as端根密钥
    QueryResult_for_queryid* query_result_as = query_id(dbname, as_tablename, as_name, sgw_name, key_type, PRE_ACTIVATION);
    if (query_result_as != NULL)
    {
        if (enable_key(dbname, as_tablename, query_result_as->ids[0]) != LD_KM_OK)
        {
            printf("enable key failed\n");
        }
    }
    else
    {
        printf("query failed. query count %d\n", query_result_as->count);
        return LD_ERR_KM_QUERY; // 查询失败
    }
    printf("enable as root key OK\n");

    return 0;
}