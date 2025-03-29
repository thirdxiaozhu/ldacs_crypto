/**
 * @author wencheng
 * @date 2024/07/17
 * @brief group key from file to crypto card
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

int main()
{

    // 导出根密钥到文件
    const char *export_bc_dir =  "../keystore/groupkey_bc.bin";  // kbc文件
    const char *export_cc_dir =  "../keystore/groupkey_cc.bin";  // kcc文件
    const char *kbc_filename = "kbc.bin";                  // 密码卡中的kbc文件
    const char *kcc_filename = "kcc.bin";                  // 密码卡中的kcc文件
    size_t file_size = 512;

    // kbc文件到密码卡
    if (km_create_ccard_file(kbc_filename, file_size) != LD_KM_OK)
    {
        log_warn("Error create kbc file in ccard \n");
    }
    if (km_writefile_to_cryptocard(export_bc_dir, kbc_filename) != LD_KM_OK)
    {
        log_warn("Error writing kbc to ccard \n");
    }

    // kcc文件到密码卡
    if (km_create_ccard_file(kcc_filename, file_size) != LD_KM_OK)
    {
        log_warn("Error create kbc file in ccard \n");
    }
    if (km_writefile_to_cryptocard(export_cc_dir, kcc_filename) != LD_KM_OK)
    {
        log_warn("Error writing kcc to ccard \n");
    }
    return 0;
}
