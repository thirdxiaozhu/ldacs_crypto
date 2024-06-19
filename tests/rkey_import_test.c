//
// Created by jiaxv on 5/16/24.
//

#include <stdio.h>
#include <string.h>
#include "key_manage.h"

int main() {
    void *rootkey_handle;
// struct KeyPkg *root_pkg = malloc(sizeof(struct KeyPkg));
    l_km_err err;
    km_keypkg_t *root_keypkg = km_import_rootkey(&rootkey_handle,
                                                 "/home/wencheng/crypto/key_management/keystore/rootkey.bin",
                                                 "/home/wencheng/crypto/key_management/keystore/rootkey.txt"
    ); // AS预置根密钥：存储于AS端密码卡
    if (root_keypkg == NULL) {
        printf("rootkey has NOT been stored in pcie\n");
    } else {
        printf("[**AS**]import OK,rootkey has been stored in pcie. handle %p\n", rootkey_handle);
//        print_key_metadata(root_keypkg->meta_data);
//        print_key_pkg(root_keypkg);
    }
}