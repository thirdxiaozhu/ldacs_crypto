/**
 * @author wencheng
 * @version 2024/06/25
 * @brief data handle and database test
 */

#include "key_manage.h"
#include "database.h"

int main()
{
    static field_desc test_km_fields[] = {
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

    // 查询密钥值
    uint8_t *id = "c10ef786-c694-4798-becf-27f5c0f19980";
    printf("query keyvalue where id =  %s....\n",id);
    QueryResult_for_keyvalue result = query_keyvalue(dbname, as_tablename, id);
    if (!result.key)
    {
        printf("Key not found or error occurred.\n");
    }
    printbuff("key value", result.key, result.key_len);
}
