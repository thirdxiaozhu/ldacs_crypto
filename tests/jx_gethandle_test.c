/**
 * 调试 get key from handle
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>  // for malloc, realloc
#include <sqlite3.h> // SQLite library

#define MAX_STRING_LEN 256
#include "key_manage.h"
#include "kmdb.h"

l_km_err key_get_handle(const char *table_name, const char *owner1, const char *owner2, enum KEY_TYPE key_type,
                        KEY_HANDLE *handle)
{
    l_km_err err;
    uint8_t *sgw_tablename = "sgw_keystore";

    QueryResult_for_queryid *qr_mk = query_id(sgw_tablename, table_name, owner1, owner2, key_type, ACTIVE);
    if (qr_mk->count == 0)
    {
        log_error("Query mkid failed.\n");
        return LD_ERR_KM_QUERY;
    }

    log_warn("%s", qr_mk->ids[0]);

    if ((err = get_handle_from_db(sgw_tablename, table_name, qr_mk->ids[0], handle)) != LD_KM_OK)
    {
        log_error("Can not get handle");
        return err;
    }
    return LD_KM_OK;
}

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
    enum STATE state = ACTIVE;

    return 0;
}