#include <stdio.h>
#include "kmdb.h"
#include "key_manage.h"

int activate_key(const char *dbname, const char *tablename, const char *name1, const char *name2, enum KEY_TYPE key_type)
{
    QueryResult_for_queryid *query_result = NULL;
    int ret = LD_KM_OK;

    query_result = query_id(dbname, tablename, name1, name2, key_type, PRE_ACTIVATION);
    if (query_result == NULL)
    {
        log_warn("query failed.\n");
        ret = LD_ERR_KM_QUERY;
        goto clean_up;
    }

    if (query_result->count == 0)
    {
        log_warn("query result count is 0.\n");
        ret = LD_ERR_KM_QUERY;
        goto clean_up;
    }

    if (enable_key(dbname, tablename, query_result->ids[0]) != LD_KM_OK)
    {
        log_warn("enable key failed\n");
        ret = LD_ERR_KEY;
        goto clean_up;
    }
    else
    {
        log_warn("enable key OK\n");
    }

clean_up:
    if (query_result != NULL)
    {
        free_queryid_result(query_result);
    }
    return ret;
}

int main()
{
    const char *dbname = "keystore.db";
    const char *sgw_tablename = "sgw_keystore";
    const char *as_tablename = "as_keystore";
    const char *sgw_name = "000010000";
    const char *as_name = "000010010";

    // 激活sgw端根密钥
    // if (activate_key(dbname, sgw_tablename, as_name, sgw_name, ROOT_KEY) != LD_KM_OK)
    // {
    //     return LD_ERR_KM_QUERY;
    // }

    // 激活as端根密钥
    // if (activate_key(dbname, as_tablename, as_name, sgw_name, ROOT_KEY) != LD_KM_OK)
    // {
    //     return LD_ERR_KM_QUERY;
    // }
    
    // 激活AS端组密钥
     if (activate_key(dbname, as_tablename, sgw_name, "", GROUP_KEY_BC) != LD_KM_OK)
    {
        return LD_ERR_KM_QUERY;
    }
    // 激活GS端组密钥同理
    
    return 0;
}