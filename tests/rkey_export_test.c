//
// Created by wencheng on 5/12/24.
//
#include <stdio.h>
#include <string.h>
#include "key_manage.h"

int main() {
    // 网关端根密钥生成和导出
    unsigned int rootkey_len = 16;
    km_keymetadata_t *key_data = km_key_metadata_new("Berry", "SGW",
                                                     ROOT_KEY, rootkey_len, 365);
    km_keypkg_t *keypkg = km_export_rootkey(key_data,
                                            "/home/wencheng/crypto/key_management/keystore/rootkey.bin",
                                            "/home/wencheng/crypto/key_management/keystore/rootkey.txt"
    ); // 根密钥存入文件
    if (keypkg == NULL) {
        printf("km_export_rootkey WRONG\n");
    } else {
        printf("[**SGW**]export rootkey OK=======================\n");
//        print_key_metadata(keypkg->meta_data);
//        print_key_pkg(keypkg);
    }

    key_pkg_free(keypkg);

    return 0;
}
