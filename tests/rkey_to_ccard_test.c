/**
 * @author wencheng
 * @date 2024/07/17
 * @brief rkey from file to crypto card
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

int main()
{

    // 导出根密钥到文件
    uint8_t *export_dir = "/home/wencheng/crypto/key_management/keystore/rootkey.bin";

    // 文件到密码卡
    if(km_writefile_to_cryptocard(export_dir, "rootkey.bin") != LD_KM_OK)
    {
        printf("Error writing to ccard \n");
    }

    return 0;
}
