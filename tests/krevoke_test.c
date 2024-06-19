/**
 * @brief 密钥撤销测试
 * @date 2024/06/17
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "database.h"

int main()
{
    uint8_t *dbname = "keystore.db";
    uint8_t *tablename = "test_key";
    QueryResult_for_queryid qr = query_id(dbname, tablename, "Berry", "GS1", MASTER_KEY_AS_GS);
    do
    {
        if (qr.count != 1)
        {
            printf("Query failed.\n");
            break;
        }

        if (km_revoke_key(dbname, tablename, qr.ids[0]) != LD_KM_OK)
        {
            printf("key %s revoke failed\n", qr.ids[0]);
            break;
        }
    } while (0);
}