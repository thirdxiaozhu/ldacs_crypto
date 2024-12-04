/**
 * @author wencheng
 * @version 2024/06/25
 * @brief data handle and database test
 */

#include "key_manage.h"
#include "kmdb.h"

int main() {
    uint8_t *dbname = "keystore.db";
    uint8_t *primary_key = "id";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";

    uint8_t *sac_gs_s = "GS1";
    uint8_t *sac_gs_t = "GSt";
    const char *sgw_name = "000010000";
    const char *as_name = "000010010";

    // 查询密钥值
    QueryResult_for_queryid *query_result = NULL;
    int ret = LD_KM_OK;
    query_result = query_id(dbname, as_tablename, sgw_name, "", GROUP_KEY_BC, PRE_ACTIVATION);
    if (query_result == NULL) {
        log_warn("query failed.\n");
    }
    log_warn("query keyvalue where id =  %s....\n", query_result->ids[0]);

    QueryResult_for_keyvalue *result = query_keyvalue(dbname, as_tablename, query_result->ids[0]);
    if (!result) {
        log_warn("Key not found or error occurred.\n");
    }
    log_buf(LOG_INFO, "key value", result->key, result->key_len);
    free_keyvalue_result(result);
}
