/**
 * @brief 密钥撤销测试
 * @date 2024/06/17
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

int main()
{
    uint8_t *dbname = "keystore.db";
    uint8_t *tablename = "as_keystore";
    enum KEY_TYPE type = SESSION_KEY_USR_ENC;
    QueryResult_for_queryid* qr = query_id(dbname, tablename, "Berry", "GS1", type, ACTIVE);
    do
    {
        if (qr == NULL)
        {
            printf("Query failed.\n");
            break;
        }

        if (km_revoke_key(dbname, tablename, qr->ids[0]) != LD_KM_OK)
        {
            printf("key %s revoke failed\n", qr->ids[0]);
            break;
        }
        printf("revoke %s %s and it's subkey OK\n",ktype_str(type), qr->ids[0]);
    } while (0);
}