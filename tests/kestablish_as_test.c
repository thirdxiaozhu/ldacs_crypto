/**
 * 20240717 by wencheng
 * 根密钥预置完成后，密钥建立过程：AS
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"
#include <uuid/uuid.h>

int main()
{

    int ret;
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *primary_key = "id";
    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs = "GS1";
    uint8_t *sac_as = "Berry";

    /**************************************************
     *                    AS端                        *
     **************************************************/
    // 生成共享信息shareinfo
    uint32_t sharedinfo_len = 32;
    uint8_t sharedinfo[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // 查询根密钥id
    QueryResult_for_queryid *qr_rk = query_id(dbname, as_tablename, sac_as, sac_sgw, ROOT_KEY, ACTIVE);
    if (qr_rk->count != 1)
    {
        printf("Query rkid failed.\n");
        free_queryid_result(qr_rk);
        return LD_ERR_KM_QUERY;
    }

    // 派生主密钥
    uint32_t len_kassgw = 16;
    if (km_derive_key(dbname, as_tablename, qr_rk->ids[0], len_kassgw, sac_gs, sharedinfo, sharedinfo_len) != LD_KM_OK)
    {
        printf("[**sgw derive_key kas-sgw error**]\n");
        free_queryid_result(qr_rk);
        return 0;
    }

    // 查询AS-GS之间主密钥
    QueryResult_for_queryid *qr_mk = query_id(dbname, as_tablename, sac_as, sac_gs, MASTER_KEY_AS_GS, ACTIVE);
    if (qr_mk == NULL)
    {
        printf("Query rkid failed.\n");
        free_queryid_result(qr_rk);
        return LD_ERR_KM_QUERY;
    }

    // 派生会话密钥
    uint32_t rand_len = 16;
    uint8_t rand[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint32_t len_sessionkey = 16;
    if (km_derive_key(dbname, as_tablename, qr_mk->ids[0], len_sessionkey, sac_gs, rand, rand_len) != LD_KM_OK)
    {
        printf("[**sgw derive_key kas-sgw error**]\n");
        free_queryid_result(qr_rk);
        free_queryid_result(qr_mk);
        return 0;
    }

    free_queryid_result(qr_rk);
    free_queryid_result(qr_mk);

    return 0;
}