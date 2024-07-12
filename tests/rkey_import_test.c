
/**
 * @brief AS side rootkey prestore
 * @author wencheng
 * @date 2024/07/01
 */

#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

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
    // root key import
    uint8_t *local_rkdir = "/home/wencheng/crypto/ldacs/ldacs_stack-main/rkstore/rootkey.txt";
    km_readfile_from_cryptocard("rootkey.bin", local_rkdir);
    km_keypkg_t *raw_pkg = read_keypkg_from_file(local_rkdir);
    delete_file(local_rkdir);
    remove(local_rkdir);
    print_key_pkg(raw_pkg);

    // root key store
    km_keypkg_t *keypkg = km_key_pkg_new(raw_pkg->meta_data, raw_pkg->key_cipher, TRUE);
    keypkg->meta_data->state = ACTIVE; // 激活密钥
    print_key_pkg(keypkg);
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *primary_key = "id";
    create_table_if_not_exist(&test_km_desc, dbname, as_tablename, primary_key);
    store_key(dbname, as_tablename, keypkg, &test_km_desc);
}