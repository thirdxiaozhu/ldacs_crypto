/**
 * @brief 新建密钥包测试
 */
#include "key_manage.h"

int main()
{
    uint32_t key_len = 16;
    km_keymetadata_t *md = km_key_metadata_new("sac_gs", "sac_as", MASTER_KEY_AS_GS, key_len, 365); // TODO: 更新周期待确定
    uint8_t key[key_len];
    km_generate_random(key, key_len);
    printbuff("key plaintext", key, key_len);
    km_keypkg_t *pkg = km_key_pkg_new(md, key);
    print_key_pkg(pkg);
}