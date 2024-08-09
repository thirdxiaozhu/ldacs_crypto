/**
 * @brief GS端安装密钥
 * @author wencheng
 * @date 2024/06/18
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
    uint32_t key_len = 16;
    km_keymetadata_t *md = km_key_metadata_new("sac_gs", "sac_as", MASTER_KEY_AS_GS, key_len, 365); // TODO: 更新周期待确定
    uint8_t key[16];
    do
    {

        if (km_generate_random(key, key_len) != LD_KM_OK)
        {
            printf("km generate random key err\n");
            break;
        }
        // printbuff("key", key, key_len);

        uint32_t nonce_len = 16;
        uint8_t nonce[nonce_len];
        if (km_generate_random(nonce, nonce_len) != LD_KM_OK)
        {
            printf("km generate random nonce err\n");
            break;
        }
        // printbuff("nonce", nonce, nonce_len);

        uint8_t *dbname = "keystore.db";
        uint8_t *tablename = "GS_test_key";
        uint8_t *primary_key = "id";

        // 创建密钥表
        if (create_table_if_not_exist(&test_km_desc, dbname, tablename, primary_key) != LD_KM_OK)
        {
            printf("create table err\n");
            break;
        }
        printf("create table OK\n");

        // 派生会话密钥     

        if (km_install_key(dbname, tablename, key_len, key, "sac_as", "sac_gs", nonce_len, nonce) != LD_KM_OK)
        {
            printf("km install key err\n");
            break;
        }

        return 0;

    } while (0);

    return -1;
}