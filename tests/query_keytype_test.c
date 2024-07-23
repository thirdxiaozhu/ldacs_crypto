/**
 * @author wencheng
 * @version 2024/06/25
 * @brief data handle and database test
 */

#include "key_manage.h"
#include "kmdb.h"

int main()
{

    uint8_t *dbname = "keystore.db";
    uint8_t *primary_key = "id";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";

    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs_s = "GS1";
    uint8_t *sac_gs_t = "GSt";
    uint8_t *sac_as = "Berry";

    // 查询根密钥id
    QueryResult_for_queryid* qr_mk = query_id(dbname, sgw_tablename, sac_as, sac_sgw, MASTER_KEY_AS_SGW, ACTIVE);
    if (qr_mk->count != 1)
    {
        printf("Query rkid failed.\n");
        return LD_ERR_KM_QUERY;
    }

    // 查询密钥类型
    printf("kid =  %s, ktype %s\n", qr_mk->ids[0], ktype_str(query_keytype(dbname, sgw_tablename, qr_mk->ids[0])));
}
