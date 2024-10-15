#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"
#include <uuid/uuid.h>

static km_field_desc km_fields[] = {
    {ft_uuid, 0, "id", NULL},
    {ft_enum, 0, "key_type", NULL},
    {ft_uint8t_pointer, 0, "owner1", NULL},
    {ft_uint8t_pointer, 0, "owner2", NULL},
    {ft_uint8t_pointer, 0, "key_cipher", NULL},
    {ft_uint32t, 0, "key_len", NULL},
    {ft_enum, 0, "key_state", NULL},
    {ft_timet, 128, "creatime", NULL},
    {ft_uint16t, 0, "updatecycle", NULL},
    {ft_uint32t, 0, "kek_len", NULL},
    {ft_uint8t_pointer, 0, "kek_cipher", NULL},
    {ft_uint8t_pointer, 0, "iv", NULL},
    {ft_uint16t, 0, "iv_len", NULL},
    {ft_enum, 0, "chck_algo", NULL},
    {ft_uint16t, 0, "check_len", NULL},
    {ft_uint8t_pointer, 0, "chck_value", NULL},
    {ft_uint16t, 0, "update_count", NULL},
    {ft_end, 0, NULL, NULL},
};

struct_desc static test_km_desc = {"km_pkg", km_fields};

int main()
{
    int ret = 0;
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_tablename = "gs_s_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";
    uint8_t *primary_key = "id";
    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs = "GS1";
    uint8_t *sac_as = "Berry";

    QueryResult_for_queryid *qr_rk = NULL;
    QueryResult_for_queryid *qr_mk = NULL;
    QueryResult_for_keyvalue *result = NULL;

    /**************************************************
     *                    SGW端                        *
     **************************************************/
    // 生成共享信息shareinfo
    uint32_t sharedinfo_len = 32;
    uint8_t sharedinfo[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                              0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                              0x0e, 0x0f};

    // 查询根密钥id
    qr_rk = query_id(dbname, sgw_tablename, sac_as, sac_sgw, ROOT_KEY, ACTIVE);
    if (qr_rk->count == 0)
    {
        printf("Query rkid failed.\n");
        ret = LD_ERR_KM_QUERY;
        goto cleanup;
    }
    else
    {
        // 打印结果
        printf("ID Count: %u\n", qr_rk->count);
        for (uint32_t i = 0; i < qr_rk->count; ++i)
        {
            printf("ID %u: %s\n", i, qr_rk->ids[i]);
        }
    }

    // 派生主密钥
    uint32_t len_kassgw = 16;
    if (km_derive_key(dbname, sgw_tablename, qr_rk->ids[0], len_kassgw, sac_gs, sharedinfo, sharedinfo_len) != LD_KM_OK)
    {
        printf("[**sgw derive master key error**]\n");
        ret = 0;
        goto cleanup;
    }

    // 查询AS-GS之间主密钥
    qr_mk = query_id(dbname, sgw_tablename, sac_as, sac_gs, MASTER_KEY_AS_GS, ACTIVE);
    if (qr_mk->count == 0)
    {
        printf("Query mkid failed.\n");
        ret = LD_ERR_KM_QUERY;
        goto cleanup;
    }

    result = query_keyvalue(dbname, sgw_tablename, qr_mk->ids[0]);
    if (!result)
    {
        printf("Key not found or error occurred.\n");
        ret = LD_ERR_KM_QUERY;
        goto cleanup;
    }

    printbuff("sgw send master key to gs", result->key, result->key_len);

cleanup:
    if (qr_rk) free_queryid_result(qr_rk);
    if (qr_mk) free_queryid_result(qr_mk);
    if (result) free_keyvalue_result(result);

    return ret;
}