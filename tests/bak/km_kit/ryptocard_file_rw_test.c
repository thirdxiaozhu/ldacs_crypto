#include <stdio.h>
#include <stdlib.h>
#include "key_manage.h"

/**
 * wirtefile_to_cryptocard 适用于将根密钥文件导入密码卡
 */

int main()
{
    uint8_t *file_path = "/home/wencheng/crypto/key_management/keystore/rootkey.bin";
    uint8_t *filename = "rootkey.bin";
    int status;

    status = writefile_to_cryptocard(file_path, filename);
    if (status != LD_KM_OK)
    {
        printf("writefile_to_cryptocard EORR\n");
    }

    uint8_t *storage_path = "/home/wencheng/crypto/key_management/keystore/rootkey.txt";
    status = readfile_from_cryptocard(filename, storage_path);
    return 0;
}
