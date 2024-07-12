/**
 * 20240514 by wencheng
 * 根密钥预置完成后，密钥建立过程样例：AS GS SGW的密钥生成和分发
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"
#include <uuid/uuid.h>

static field_desc km_fields[] = {
    // 密钥结构体字段描述
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

    int ret;
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_tablename = "gs_s_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";
    uint8_t *primary_key = "id";
    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs = "GS1";
    uint8_t *sac_as = "Berry";

    // 创建表
    create_table_if_not_exist(&test_km_desc, dbname, as_tablename, primary_key);  // 根据描述创建表
    create_table_if_not_exist(&test_km_desc, dbname, gs_tablename, primary_key);  // 根据描述创建表
    create_table_if_not_exist(&test_km_desc, dbname, sgw_tablename, primary_key); // 根据描述创建表

    /**************************************************
     *                    SGW端                        *
     **************************************************/
    // 生成共享信息shareinfo
    uint32_t sharedinfo_len = 32;
    uint8_t *sharedinfo = {0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04};

    // 生成随机数N3,用于后续密钥派生
    uint16_t rand_len = 16;
    uint8_t *rand = {0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04};

    // 获取根密钥
    QueryResult_for_queryid rk_id = query_id(dbname, sgw_tablename, sac_as, sac_sgw, ROOT_KEY, ACTIVE);
    if (rk_id.count == 0)
    {
        printf("NULL Query.\n");
        return 0;
    }
    else if (rk_id.count > 1)
    {
        printf("query id not unique.\n");
        return 0;
    }

    // 派生主密钥：密钥KAS-SGW=KDF(rootkey,sharedinfo)派生
    uint16_t len_kassgw = 16; // 主密钥长度
    if (km_derive_key(dbname, sgw_tablename, rk_id.ids[0], MASTER_KEY_AS_SGW, len_kassgw, NULL, sharedinfo, sharedinfo_len) != LD_KM_OK)
    {
        printf("[**sgw derive_key kas-sgw error**]\n");
        return 0;
    }

    // 获取主密钥id
    QueryResult_for_queryid mk_assgw_id = query_id(dbname, sgw_tablename, sac_as, sac_sgw, MASTER_KEY_AS_SGW, ACTIVE);
    if (mk_assgw_id.count == 0)
    {
        printf("NULL Query.\n");
        return 0;
    }
    else if (mk_assgw_id.count > 1)
    {
        printf("query id not unique.\n");
        return 0;
    }

    // 密钥KAS-GS派生 和AS同理：NH = KDF(KAS-SGW,rand)
    uint16_t len_kasgs = 16; // 主密钥长度
    if (km_derive_key(dbname, sgw_tablename, rk_id.ids[0], MASTER_KEY_AS_GS, len_kasgs, NULL, sharedinfo, sharedinfo_len) != LD_KM_OK)
    {
        printf("[**sgw derive_key kas-gs error**]\n");
        return 0;
    }

    // 查询密钥id
    QueryResult_for_queryid qr = query_id(dbname, sgw_tablename, sac_as, sac_gs, MASTER_KEY_AS_GS, ACTIVE);
    if (qr.count == 0)
    {
        printf("NULL Query.\n");
        return 0;
    }
    else if (qr.count > 1)
    {
        printf("query id not unique.\n");
        return 0;
    }

    // 查询密钥值
    QueryResult_for_keyvalue result = query_keyvalue(dbname, sgw_tablename, qr.ids[0]);
    if (!result.key)
    {
        printf("Key not found or error occurred.\n");
        return 0;
    }
    
    // 省略：给GS分发KAS-GS rand rand_len
    printf("SGW sending kas-gs to GS.........,key value:%s\n", result.key);

    return 0;
}