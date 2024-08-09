//
// Created by wencheng on 2024/07/01
//
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

static km_field_desc km_fields[] = {
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
    // 网关端根密钥生成
    unsigned int rootkey_len = 16;

    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";

    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs_s = "GS1";
    uint8_t *sac_gs_t = "GSt";
    uint8_t *sac_as = "Berry";

    km_keymetadata_t *key_data = km_key_metadata_new(sac_as, sac_sgw, ROOT_KEY, rootkey_len, 365);
    uint8_t root_key[rootkey_len];
    km_generate_random(root_key, rootkey_len);
    printbuff("root key: ", root_key, rootkey_len);
    km_keypkg_t *rk_rawpkg = km_key_pkg_new(key_data, root_key, FALSE); // 明文

    // 导出根密钥到文件
    uint8_t *export_dir = "/home/wencheng/key_management/build/rootkey.bin";
    delete_file(export_dir); // 清除已有文件
    write_keypkg_to_file(export_dir, rk_rawpkg);
    print_key_pkg(rk_rawpkg);
    
    // 文件到密码卡
    km_writefile_to_cryptocard(export_dir, "rootkey.bin");

    // 存储根密钥
    km_keypkg_t *keypkg = km_key_pkg_new(key_data, root_key, TRUE);
    keypkg->meta_data->state = ACTIVE; // 激活密钥
    print_key_pkg(keypkg);
    uint8_t *primary_key = "id";
    create_table_if_not_exist(&test_km_desc, dbname, sgw_tablename, primary_key);
    store_key(dbname, sgw_tablename, keypkg, &test_km_desc);

    key_pkg_free(keypkg);

    return 0;
}
