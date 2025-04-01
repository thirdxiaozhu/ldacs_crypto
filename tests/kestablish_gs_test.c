/**
 * 20240717 by wencheng
 * 根密钥预置完成后，密钥建立过程：GS
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

// 用于创建随机数种子索引表时的描述
static km_field_desc km_create_randseeds_table_fields[] = {
    // 密钥结构体字段描述
    {km_ft_uint32t, 0, "seeds_id", NULL},
    {km_ft_uuid, 0, "key_id", NULL},
    {km_ft_uint16t, 0, "rand_len", NULL},
    {km_ft_uint8t_pointer, 0, "rand", NULL},
    {km_ft_end, 0, NULL, NULL},
};
struct_desc static km_seeds_desc = {"km_seed", km_create_randseeds_table_fields};

int main()
{

    int ret;
    uint8_t *dbname = "keystore.db";
    uint8_t *gs_tablename = "gs_s_keystore";
    uint8_t *primary_key = "id";
    uint8_t *sgw_name = "SGW"; // 测试本地标识
    uint8_t *gs_name = "GS1";
    uint8_t *as_name = "Berry";

    /**************************************************
     *                    GS端                        *
     **************************************************/

    // 安装主密钥 派生会话密钥 随机数和密钥来自于报文
    uint32_t key_len = 16;
    uint32_t rand_len = 16;
    uint8_t key[16] = {0xB6, 0x6E, 0x39, 0x49, 0xBC, 0xC4, 0xB0, 0xB1, 0x67, 0xAE, 0x7E, 0x46, 0x7E, 0xC4, 0xEA, 0xE8};
    uint8_t rand[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    if (km_install_key(dbname, gs_tablename, key_len, key, as_name, gs_name, rand_len, rand) != LD_KM_OK)
    {
        log_warn("gs install key failed\n");
    }
    log_warn("gs install key ok\n");

    /* 把随机数保存 可以用于密钥更新 */
    // 创建随机数种子表
    const char *db_name = "keystore.db";
    const char *randseeds_table_name = "gs_s_randseeds_store";
    uint8_t *rs_primary_key = "seeds_id";
    const char *foreign_table = "gs_s_keystore";
    uint8_t *foreign_key = "key_id";
    l_km_err result = create_table_if_not_exist(&km_seeds_desc, db_name, randseeds_table_name, rs_primary_key, foreign_table, foreign_key, TRUE);
    if (result != LD_KM_OK)
    {
        printf("Failed to create table gs_s_randseeds_store.\n");
    }

    // 查询AS-GS之间主密钥
    QueryResult_for_queryid *qr_mk = query_id(dbname, gs_tablename, as_name, gs_name, MASTER_KEY_AS_GS, ACTIVE);
    if (qr_mk == NULL)
    {
        log_warn("Query rkid failed.\n");
        free_queryid_result(qr_mk);
        return LD_ERR_KM_QUERY;
    }

    // 存储随机数 和主密钥有外键关联
    l_km_err store_result = store_rand(db_name, randseeds_table_name, qr_mk->ids[0], rand_len, rand);
    if (store_result != LD_KM_OK)
    {
        printf("store_rand failed with error code: %d\n", store_result);
    }

    free_queryid_result(qr_mk);

    return 0;
}