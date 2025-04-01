/**
 * @author wencheng
 * @date 2024/07/17
 * @brief rkey from file to crypto card
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

int main() {

    // 导出根密钥到文件
    // uint8_t *export_dir = "/root/ldacs/stack_new/ldacs_stack/resources/keystore/rootkey.bin";
    const char *export_dir = "../keystore/rootkey.bin"; // 导出根密钥到密码卡

    // 文件到密码卡
    if (km_writefile_to_cryptocard(export_dir, "rootkey.bin") != LD_KM_OK) {
        fprintf(stderr, "Error writing to ccard \n");
    }

    return 0;
}
