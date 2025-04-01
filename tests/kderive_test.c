/**
 * 20240514 by wencheng
 * 根密钥预置完成后，密钥建立过程样例：AS GS SGW的密钥生成和分发
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"
#include <uuid/uuid.h>

static km_field_desc km_fields[] = {
    // 密钥结构体字段描述
    {km_ft_uuid, 0, "id", NULL},
    {km_ft_enum, 0, "key_type", NULL},
    {km_ft_uint8t_pointer, 0, "owner1", NULL},
    {km_ft_uint8t_pointer, 0, "owner2", NULL},
    {km_ft_uint8t_pointer, 0, "key_cipher", NULL},
    {km_ft_uint32t, 0, "key_len", NULL},
    {km_ft_enum, 0, "key_state", NULL},
    {km_ft_timet, 128, "creatime", NULL},
    {km_ft_uint16t, 0, "updatecycle", NULL},
    {km_ft_uint32t, 0, "kek_len", NULL},
    {km_ft_uint8t_pointer, 0, "kek_cipher", NULL},
    {km_ft_uint8t_pointer, 0, "iv", NULL},
    {km_ft_uint16t, 0, "iv_len", NULL},
    {km_ft_enum, 0, "chck_algo", NULL},
    {km_ft_uint16t, 0, "check_len", NULL},
    {km_ft_uint8t_pointer, 0, "chck_value", NULL},
    {km_ft_uint16t, 0, "update_count", NULL},
    {km_ft_end, 0, NULL, NULL},
};

struct_desc static test_km_desc = {"km_pkg", km_fields};

int main()
{

    int ret;
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_tablename = "gs_s_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";
    uint8_t *primary_key = "id";
    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs = "GS1";
    uint8_t *sac_as = "Berry";

    /**************************************************
     *                    SGW端                        *
     **************************************************/
    // 生成共享信息shareinfo
    uint32_t sharedinfo_len = 32;
    uint8_t sharedinfo[sharedinfo_len];
    ret = km_generate_random(sharedinfo, sharedinfo_len); // 用随机数填充
    if (ret != LD_KM_OK)
    {
        fprintf(stderr, "[**sgw generate sharedinfo error**]\n");
        return 0;
    }

    // 查询根密钥id
    QueryResult_for_queryid qr_rk = query_id(dbname, sgw_tablename, sac_as, sac_sgw, ROOT_KEY, ACTIVE);
    if (qr_rk.count != 1)
    {
        fprintf(stderr, "Query rkid failed.\n");
        return LD_ERR_KM_QUERY;
    }

    // 派生主密钥
    uint32_t len_kassgw = 16;
    if (km_derive_key(dbname, sgw_tablename, qr_rk.ids[0], len_kassgw, sac_gs, sharedinfo, sharedinfo_len) != LD_KM_OK)
    {
        fprintf(stderr, "[**sgw derive_key kas-sgw error**]\n");
        return 0;
    }

    // 查询AS-GS之间主密钥
    QueryResult_for_queryid qr_mk = query_id(dbname, sgw_tablename, sac_as, sac_gs, MASTER_KEY_AS_GS, ACTIVE);
    if (qr_mk.count != 1)
    {
        fprintf(stderr, "Query rkid failed.\n");
        return LD_ERR_KM_QUERY;
    }

    // 派生会话密钥
    uint32_t len_sessionkey = 16;
    if (km_derive_key(dbname, sgw_tablename, qr_mk.ids[0], len_kassgw, sac_gs, sharedinfo, sharedinfo_len) != LD_KM_OK)
    {
        fprintf(stderr, "[**sgw derive_key kas-sgw error**]\n");
        return 0;
    }
    return 0;
}