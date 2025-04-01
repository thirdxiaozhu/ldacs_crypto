/**
 * 20240717 by wencheng
 * 根密钥预置完成后，密钥建立过程：AS
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"
#include <uuid/uuid.h>

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

    int ret;
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *primary_key = "id";
    uint8_t *sgw_name = "SGW"; // 测试本地标识
    uint8_t *gs_name = "GS1";
    uint8_t *as_name = "Berry";

    /**************************************************
     *                    AS端                        *
     **************************************************/
    // 生成共享信息shareinfo
    uint32_t sharedinfo_len = 32;
    uint8_t sharedinfo[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                              0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                              0x0e, 0x0f};

    // 查询根密钥id
    QueryResult_for_queryid *qr_rk = query_id(dbname, as_tablename, as_name, sgw_name, ROOT_KEY, ACTIVE);
    if (qr_rk->count != 1) {
        fprintf(stderr, "Query rkid failed.\n");
        free_queryid_result(qr_rk);
        return LD_ERR_KM_QUERY;
    }

    // 派生主密钥
    uint32_t len_kassgw = 16;
    if (km_derive_key(dbname, as_tablename, qr_rk->ids[0], len_kassgw, gs_name, sharedinfo, sharedinfo_len) !=
        LD_KM_OK) {
        fprintf(stderr, "[**sgw derive_key kas-sgw error**]\n");
        free_queryid_result(qr_rk);
        return 0;
    }

    // 查询AS-GS之间主密钥
    QueryResult_for_queryid *qr_mk = query_id(dbname, as_tablename, as_name, gs_name, MASTER_KEY_AS_GS, ACTIVE);
    if (qr_mk == NULL) {
        fprintf(stderr, "Query rkid failed.\n");
        free_queryid_result(qr_rk);
        return LD_ERR_KM_QUERY;
    }

    // 派生会话密钥 随机数来源：认证过程产生的randv
    uint32_t rand_len = 16;
    uint8_t rand[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint32_t len_sessionkey = 16;
    if (km_derive_key(dbname, as_tablename, qr_mk->ids[0], len_sessionkey, gs_name, rand, rand_len) != LD_KM_OK) {
        fprintf(stderr, "[**sgw derive_key kas-sgw error**]\n");
        free_queryid_result(qr_rk);
        free_queryid_result(qr_mk);
        return 0;
    }

    // 保存一下随机数 密钥更新的时候可以用这个随机数
    // 创建随机数种子表
    const char *db_name = "keystore.db";
    const char *randseeds_table_name = "as_randseeds_store";
    uint8_t *rs_primary_key = "seeds_id";
    const char *foreign_table = "as_keystore";
    uint8_t *foreign_key = "key_id";
    l_km_err result = create_table_if_not_exist(&km_seeds_desc, db_name, randseeds_table_name, rs_primary_key,
                                                foreign_table, foreign_key, TRUE);
    if (result != LD_KM_OK) {
        printf("Failed to create table as_randseeds_store.\n");
    }
    // 存储随机数 和主密钥有外键关联
    l_km_err store_result = store_rand(db_name, randseeds_table_name, qr_mk->ids[0], rand_len, rand);
    if (store_result != LD_KM_OK) {
        printf("store_rand failed with error code: %d\n", store_result);
    }

    free_queryid_result(qr_rk);
    free_queryid_result(qr_mk);

    return 0;
}