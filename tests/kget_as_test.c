/**
 * 20240717 by wencheng 密钥查询 AS端
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

int main() {
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *gs_t_2tablename = "gs_t2_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";

    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs_s = "GS1";
    uint8_t *sac_gs_t = "GSt";
    uint8_t *sac_gs_t_2 = "GSt2";
    uint8_t *sac_as = "Berry";

    enum KEY_TYPE type = MASTER_KEY_AS_SGW;
    QueryResult_for_queryid *qr_sk = query_id(dbname, as_tablename, sac_as, sac_sgw, type, ACTIVE);
    if (qr_sk == NULL) {
        log_warn("Query rkid failed.\n");
        return LD_ERR_KM_QUERY;
    }
    log_warn("id %s\n", qr_sk->ids[0]);

    QueryResult_for_keyvalue *result = query_keyvalue(dbname, as_tablename, qr_sk->ids[0]);
    if (!result) {
        log_warn("Key not found or error occurred.\n");
        return LD_ERR_KM_QUERY;
    }
    log_warn("%s ", ktype_str(type));
    //printbuff("value ", result->key, result->key_len);
}