#include <stdio.h>
#include <string.h>
#include <stdlib.h> // 为了使用 free
#include "key_manage.h"
#include "kmdb.h"

int main()
{
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";

    uint8_t *sac_as = "Berry";
    uint8_t *sac_gs_s = "GS1";
    uint8_t *sac_gs_t = "GSt";
    enum KEY_TYPE type = SESSION_KEY_USR_ENC;
    int status = 0; // 记录错误状态

    QueryResult_for_queryid *qr_sk = NULL;
    QueryResult_for_keyvalue *result = NULL;
    QueryResult_for_queryid *qr = NULL;
    QueryResult_for_keyvalue *res = NULL;

    do
    {
        qr_sk = query_id(dbname, as_tablename, sac_as, sac_gs_t, type, ACTIVE);
        if (qr_sk == NULL || qr_sk->count == 0)
        {
            log_warn("Query rkid failed.\n");
            status = LD_ERR_KM_QUERY;
            break;
        }
        log_warn("outcome counts %d\n", qr_sk->count);
        log_warn("%s in table %s id %s\n", ktype_str(type), as_tablename, qr_sk->ids[0]);

        result = query_keyvalue(dbname, as_tablename, qr_sk->ids[0]);
        if (!result)
        {
            log_warn("Key not found or error occurred.\n");
            status = LD_ERR_KM_QUERY;
            break;
        }
        printbuff("key value ", result->key, result->key_len);

        qr = query_id(dbname, gs_t_tablename, sac_as, sac_gs_t, type, ACTIVE);
        if (qr->count != 1)
        {
            log_warn("Query rkid failed.\n");
            status = LD_ERR_KM_QUERY;
            break;
        }

        res = query_keyvalue(dbname, gs_t_tablename, qr->ids[0]);
        if (!res)
        {
            log_warn("Key not found or error occurred.\n");
            status = LD_ERR_KM_QUERY;
            break;
        }
        log_warn("%s in table %s id %s\n", ktype_str(type), gs_t_tablename, qr->ids[0]);
        printbuff("key value ", res->key, res->key_len);

        // 对比两个密钥值是否相同
        if (result->key_len == res->key_len && memcmp(result->key, res->key, result->key_len) == 0)
        {
            log_warn("[*OK*] The keys are identical.\n");
        }
        else
        {
            log_warn("[*Fail*] The keys are different.\n");
        }

    } while (0); // 只执行一次

    // 释放内存
    if (result != NULL)
    {
        free_keyvalue_result(result);
    }
    if (res != NULL)
    {
        free_keyvalue_result(res);
    }
    if (qr_sk != NULL)
    {
        free_queryid_result(qr_sk);
    }
    if (qr != NULL)
    {
        free_queryid_result(qr);
    }

    // 如果发生错误，清理未释放的内存
    if (status != 0)
    {
        // 这里可以添加错误处理的代码
    }

    return status; // 返回错误状态
}