/**
 * by wencheng 20240419
*/
#include <stdio.h>
#include <stdlib.h>
#include <key_manage.h>

int main()
{
    // 生成根密钥
    uint32_t len = 16;
    uint8_t rootkey[len];
    generate_random(len, rootkey);
    HANDLE rootkey_handle;
    import_key(rootkey, len, &rootkey_handle);

    // 主密钥派生
    int ret;
    uint32_t key_asswg_len = 16;
    uint8_t *shared_info = "shareinfo_hashshareinfo_hash";
    uint8_t *owner1 = "AS1";
    uint8_t *owner2 = "SGW1";
    uint8_t shared_info_len = strlen(shared_info);
    void *masterkey_handle;
    // struct KeyPkg *pkg = malloc(sizeof(struct KeyPkg));
    struct KeyPkg pkg;
    ret = derive_key(rootkey_handle, MASTER_KEY_AS_SGW, key_asswg_len, owner1, owner2, shared_info, shared_info_len, &masterkey_handle, &pkg);
    if (ret == LD_KM_OK)
    {
        printf("Key as-sgw syccessfully derived!---------------\n");
        // printf("key handle %p\n", masterkey_handle);
        // print_key_pkg(pkg);
        // print_key_pkg(&pkg);
    }
    else
    {
        printf("Key derivation failed.\n");
    }

    // 会话完整性密钥派生
    uint8_t rand2[16];
    uint8_t rand2_len = 16;
    generate_random(rand2_len, rand2);
    HANDLE sessionkey_handle;
    struct KeyPkg sessionkey_pkg;
    int result = derive_key(masterkey_handle, SESSION_KEY_USR_INT, 16, owner1, owner2, rand2, rand2_len, &sessionkey_handle, &sessionkey_pkg);
    if (result == LD_KM_OK)
    {
        printf("session Key syccessfully derived!the Handle is %p\n", sessionkey_handle);
        // printf("sessionkey is as followed:\n");
        // print_key_pkg(&sessionkey_pkg);
    }
    else
    {
        printf("Key derivation failed.ret %d\n", result);
    }

    // 更新主密钥及其会话密钥
    
    

}