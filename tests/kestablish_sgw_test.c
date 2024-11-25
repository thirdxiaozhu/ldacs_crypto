#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"
#include <uuid/uuid.h>

static km_field_desc km_fields[] = {
        {ft_uuid,           0,   "id",           NULL},
        {ft_enum,           0,   "key_type",     NULL},
        {ft_uint8t_pointer, 0,   "owner1",       NULL},
        {ft_uint8t_pointer, 0,   "owner2",       NULL},
        {ft_uint8t_pointer, 0,   "key_cipher",   NULL},
        {ft_uint32t,        0,   "key_len",      NULL},
        {ft_enum,           0,   "key_state",    NULL},
        {ft_timet,          128, "creatime",     NULL},
        {ft_uint16t,        0,   "updatecycle",  NULL},
        {ft_uint32t,        0,   "kek_len",      NULL},
        {ft_uint8t_pointer, 0,   "kek_cipher",   NULL},
        {ft_uint8t_pointer, 0,   "iv",           NULL},
        {ft_uint16t,        0,   "iv_len",       NULL},
        {ft_enum,           0,   "chck_algo",    NULL},
        {ft_uint16t,        0,   "check_len",    NULL},
        {ft_uint8t_pointer, 0,   "chck_value",   NULL},
        {ft_uint16t,        0,   "update_count", NULL},
        {ft_end,            0, NULL,             NULL},
};

struct_desc static test_km_desc = {"km_pkg", km_fields};

// 用于创建随机数种子索引表时的描述
static km_field_desc km_create_randseeds_table_fields[] = {
        // 密钥结构体字段描述
        {ft_uint32t,        0, "seeds_id", NULL},
        {ft_uuid,           0, "key_id",   NULL},
        {ft_uint16t,        0, "rand_len", NULL},
        {ft_uint8t_pointer, 0, "rand",     NULL},
        {ft_end,            0, NULL,       NULL},
};
struct_desc static km_seeds_desc = {"km_seed", km_create_randseeds_table_fields};

int main() {
    int ret = 0;
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_tablename = "gs_s_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";
    uint8_t *primary_key = "id";
    uint8_t *sgw_name = "SGW"; // 测试本地标识
    uint8_t *gs_name = "GS1";
    uint8_t *as_name = "Berry";

    QueryResult_for_queryid *qr_rk = NULL;
    QueryResult_for_queryid *qr_mk = NULL;
    QueryResult_for_keyvalue *result = NULL;

    /**************************************************
     *                    SGW端                        *
     **************************************************/
    // 生成随机数 【此处本应随机数生成 通过协议分发 为测试方便 暂时写死】
    uint32_t rand_len = 16;
    uint8_t rand[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // 保存一下随机数 密钥更新的时候可以用这个随机数
    // 创建随机数种子表
    const char *db_name = "keystore.db";
    const char *randseeds_table_name = "sgw_randseeds_store";
    uint8_t *rs_primary_key = "seeds_id";
    const char *foreign_table = "sgw_keystore";
    uint8_t *foreign_key = "key_id";
    l_km_err tag = create_table_if_not_exist(&km_seeds_desc, db_name, randseeds_table_name, rs_primary_key,
                                             foreign_table, foreign_key, TRUE);
    if (tag != LD_KM_OK) {
        printf("Failed to create table as_randseeds_store.\n");
    }

    // 生成共享信息shareinfo 【此处没有按照协议设计基于随机数计算，届时请替换】
    uint32_t sharedinfo_len = 32;
    uint8_t sharedinfo[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                              0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                              0x0e, 0x0f};

    // 查询根密钥id
    qr_rk = query_id(dbname, sgw_tablename, as_name, sgw_name, ROOT_KEY, ACTIVE);
    if (qr_rk->count == 0) {
        log_warn("Query rkid failed.\n");
        ret = LD_ERR_KM_QUERY;
        goto cleanup;
    } else {
        // 打印结果
        log_warn("ID Count: %u\n", qr_rk->count);
        for (uint32_t i = 0; i < qr_rk->count; ++i) {
            log_warn("ID %u: %s\n", i, qr_rk->ids[i]);
        }
    }



    // 派生主密钥
    uint32_t len_kassgw = 16;
    if (km_derive_key(dbname, sgw_tablename, qr_rk->ids[0], len_kassgw, gs_name, sharedinfo, sharedinfo_len) !=
        LD_KM_OK) {
        log_warn("[**sgw derive master key error**]\n");
        ret = 0;
        goto cleanup;
    }

    // 查询AS-GS之间主密钥
    qr_mk = query_id(dbname, sgw_tablename, as_name, gs_name, MASTER_KEY_AS_GS, ACTIVE);
    if (qr_mk->count == 0) {
        log_warn("Query mkid failed.\n");
        ret = LD_ERR_KM_QUERY;
        goto cleanup;
    }

    result = query_keyvalue(dbname, sgw_tablename, qr_mk->ids[0]);
    if (!result) {
        log_warn("Key not found or error occurred.\n");
        ret = LD_ERR_KM_QUERY;
        goto cleanup;
    }

    //printbuff("sgw send master key to gs", result->key, result->key_len);

    // 存储随机数 和主密钥有外键关联
    l_km_err store_result = store_rand(db_name, randseeds_table_name, qr_mk->ids[0], rand_len, rand);
    if (store_result != LD_KM_OK) {
        printf("store_rand failed with error code: %d\n", store_result);
    }

    cleanup:
    if (qr_rk)
        free_queryid_result(qr_rk);
    if (qr_mk)
        free_queryid_result(qr_mk);
    if (result)
        free_keyvalue_result(result);

    return ret;
}