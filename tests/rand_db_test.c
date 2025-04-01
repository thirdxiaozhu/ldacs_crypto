/*
@author wencheng
@date 2024/20/31
@brief Description 测试密钥库中随机数的增和查
*/
#include "key_manage.h"

#include "kmdb.h"

void uint8_array_to_hex_string(uint8_t *array, size_t array_len, char *output) {
    for (size_t i = 0; i < array_len; i++) {
        sprintf(output + (i * 2), "%02X", array[i]);
    }
}

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
    const char *db_name = "keystore.db";
    const char *randseeds_table_name = "sgw_randseeds_store";
    uint8_t *primary_key = "seeds_id";
    const char *foreign_table = "sgw_keystore";
    uint8_t *foreign_key = "key_id";
    uint8_t key_id[] = "5fc2f839-3616-450b-a1a0-e8ada0e086c5";
    uint32_t rand_len = 16;
    uint8_t rand[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    // 测试 创建随机数种子表
    l_km_err result = create_table_if_not_exist(&km_seeds_desc, db_name, randseeds_table_name, primary_key,
                                                foreign_table, foreign_key, TRUE);
    if (result == LD_KM_OK) {
        printf("Table created successfully.\n");
    } else {
        printf("Failed to create table.\n");
    }

    // 测试 存储随机数
    l_km_err store_result = store_rand(db_name, randseeds_table_name, key_id, rand_len, rand);
    if (store_result != LD_KM_OK) {
        printf("store_rand failed with error code: %d\n", store_result);
        return -1;
    }
    printf("store_rand succeeded\n");

    // 测试 查询随机数
    QueryResult_for_rand *query_result = query_rand(db_name, randseeds_table_name, key_id);
    if (query_result == NULL) {
        printf("query_rand failed\n");
        return -1;
    }
    printf("query_rand succeeded\n");

    // 验证查询结果

    //log_buf(LOG_INFO, "expected",rand, rand_len);
    //log_buf(LOG_INFO, "got", query_result->rand, query_result->rand_len);


    // 测试 free_rand_result
    free_rand_result(query_result);
    printf("free_rand_result succeeded\n");
}