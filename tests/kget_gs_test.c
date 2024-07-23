/**
 * 20240717 by wencheng 密钥查询
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

int main()
{
    uint8_t *dbname = "keystore.db";
    uint8_t *gs_tablename = "gs_t_keystore";
    uint8_t *primary_key = "id";
    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs_s = "GS1";
    uint8_t *sac_gs_t = "GSt";
    uint8_t *sac_as = "Berry";
    enum KEY_TYPE type = SESSION_KEY_USR_ENC;

    QueryResult_for_queryid* qr_sk = query_id(dbname, gs_tablename, sac_as, sac_gs_t, type, ACTIVE);
    if (qr_sk->count != 1)
    {
        printf("Query rkid failed.\n");
        return LD_ERR_KM_QUERY;
    }

    QueryResult_for_keyvalue* result = query_keyvalue(dbname, gs_tablename, qr_sk->ids[0]);
    if (!result)
    {
        printf("Key not found or error occurred.\n");
        return LD_ERR_KM_QUERY;
    }

    printf("%s ", ktype_str(type));
    printbuff("value ", result->key, result->key_len);
}