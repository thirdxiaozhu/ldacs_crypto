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
    uint8_t *gs_tablename = "gs_s_keystore";
    uint8_t *primary_key = "id";
    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs = "GS1";
    uint8_t *sac_as = "Berry";

    /**************************************************
     *                    GS端                        *
     **************************************************/

    // 安装主密钥 派生会话密钥
    uint32_t key_len = 16;
    uint32_t rand_len = 16;
    uint8_t key[16] = {0x48, 0x8B, 0x83, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x0B, 0x0F, 0xB7, 0x93, 0xC0};
    uint8_t rand[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    if (km_install_key(dbname, gs_tablename, key_len, key, sac_as, sac_gs, rand_len, rand) != LD_KM_OK)
    {
        printf("gs install key failed\n");
        return 0;
    }


    return 0;
}