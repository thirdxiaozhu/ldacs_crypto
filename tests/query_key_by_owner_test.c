/**
 * @author wencheng
 * @version 2025/01/02
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

    uint8_t *sac_gs_s = "000010000";
    uint8_t *sac_gs_t = "GSt";
    const char *sgw_name = "000010000";
    const char *as_name = "000010010";

    // 调用接口函数
    QueryResult_for_keyvalue *result = query_keyvalue_by_owner(dbname, sgw_tablename, as_name, sac_gs_s,
                                                               MASTER_KEY_AS_SGW, ACTIVE);

    // 检查结果
    if (result->key != NULL) {
        printf("Query successful!\n");
        //log_buf(LOG_INFO, "Result data \n", result->key, result->key_len);
    } else {
        printf("Query failed with status");
    }

    // 释放资源
    free_keyvalue_result(result);
}
