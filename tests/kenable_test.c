#include <stdio.h>
#include "kmdb.h"
#include "key_manage.h"

int main()
{
    const char *dbname = "keystore.db";
    const char *sgw_tablename = "sgw_keystore";
    const char *sgw_name = "SGW";
    const char *as_name = "Berry";
    enum KEY_TYPE key_type = ROOT_KEY;

 // 查询id
    QueryResult_for_queryid query_result = query_id(dbname, sgw_tablename, as_name, sgw_name, key_type, PRE_ACTIVATION);

    if (query_result.count == 1)
    {
       if(enable_key(dbname, sgw_tablename, query_result.ids[0]) != LD_KM_OK)
       {
        printf("enable key failed\n");
       }
    }
    else
    {
        printf("query failed. query count %d\n", query_result.count);
        return LD_ERR_KM_QUERY; // 查询失败
    }
    printf("enable key OK\n");

    return 0;
}