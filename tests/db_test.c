/**
 * @author wencheng
 * @version 2024/05/29
 * @brief data handle and database test
 */

#include "key_manage.h"
#include "kmdb.h"
static km_field_desc test_km_fields[] = {
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

struct_desc static test_km_desc = {"km_pkg", test_km_fields};
int main()
{

    struct KeyMetaData mt = {
        // 指定该密钥的信息 封装成结构体keypkg
        .length = 16,
        .owner_1 = "AS1",     // 管理员指定
        .owner_2 = "Sec-GW1", // 管理员指定
        .state = PRE_ACTIVATION,
        .key_type = ROOT_KEY,
        .update_cycle = 365,
    };
    uuid_t uuid;
    uuid_generate(uuid); // 生成ID
    uuid_copy(mt.id, uuid);

    struct KeyPkg pkg = {
        .meta_data = &mt,
        .kek_cipher = {0x02, 0x02, 0x02, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20},
        .kek_cipher_len = 16,
        .key_cipher = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
        .iv = {0x03, 0x03, 0x03, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20},
        .iv_len = 16,
        .chck_alg = ALGO_ENC_AND_DEC,
        .chck_value = {0x04, 0x04, 0x04, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20, 0x02, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20},
        .chck_len = 32,
    };

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

    // 创建密钥表
    // create_table_if_not_exist(&test_km_desc, dbname, tablename, primary_key);

    // 新增一个密钥
    /*
    int ret = store_key(dbname, tablename, &pkg, &test_km_desc);
        if (ret != LD_KM_OK)
        {
            printf("store_key failed: %d\n", ret);
            return 0;
        }
    */

    // 测试枚举转字符串
    /*
    enum KEY_TYPE keytype =  str_to_ktype("ROOT_KEY");
    printf("ktype %s\n", ktype_str(keytype));
    */

    // 查询子密钥id
    /*
     QueryResult_for_subkey result = query_subkey(dbname, tablename, id);
    // 打印查询结果
    printf("Number of subkeys found: %d\n", result.count);
    for (int i = 0; i < result.count; i++) {
        printf("Subkey ID %d: %s, Key Type: %s\n", i + 1, result.subkey_ids[i], result.key_types[i]);
        free(result.subkey_ids[i]);
        free(result.key_types[i]);
    }
    free(result.subkey_ids);
    free(result.key_types);
    */

    // 查询所有者
    /*
    QueryResult_for_owner result = query_owner(dbname, tablename, id);
    // 打印查询结果
    if (result.owner1)
        printf("Owner1: %s\n", result.owner1);
    if (result.owner2)
        printf("Owner2: %s\n", result.owner2);

    // 释放查询结果的内存
    if (result.owner1)
        free(result.owner1);
    if (result.owner2)
        free(result.owner2);
    */

    // 查询kek
    /*
    QueryResult_for_kekhandle result = query_kekhandle(dbname, tablename, id);
    if (result.kek_handle == NULL)
    {
        printf("Key not found or error occurred.\n");
        return 0;
    }
    */

    // 查询密钥

    // 修改密钥值
    /*
    uint16_t key_len = 16;
    uint8_t key[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02};
    alter_keyvalue(dbname, tablename, id, key_len, key);
    */

    // 获取密钥句柄

    /*
    void *handle;
        int ret = get_handle_from_db(dbname, tablename, id, &handle);
        if (ret != LD_KM_OK)
        {
            printf("get_handle_from_db failed: %d\n", ret);
            return 0;
        }
    */

    // 更改密钥状态
    // alter_keystate(dbname, tablename, id, ACTIVE);

    // 密钥更新计数 + 1
    /*
    ret = increase_updatecount(dbname, tablename, id);
    if (ret != LD_KM_OK)
    {
        printf("Increase update count failed.\n");
    }
    */

    // 根据id查询密钥更新信息
    /*
    QueryResult_for_pdate result = query_for_update(dbname, tablename, id);
    if (result.key_len <= 0 || result.update_cycle <= 0 || result.update_count < 0)
    {
        printf("Query failed.\n");
    }
    else
    {
        printf("keylen: %d, update cycle: %d ,update count: %d \n", result.key_len, result.update_cycle, result.update_count);
    }
    */

    return 0;
}