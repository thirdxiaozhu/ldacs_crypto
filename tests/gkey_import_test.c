
/**
 * @brief AS side rootkey import and store
 * @author wencheng
 * @date 2024/12/04
 */

#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

int main()
{
    const char *dbname = "keystore.db";
    const char *as_tablename = "as_keystore";
    const char *kbc_filename = "kbc.bin";                  // 密码卡中的kbc文件
    const char *kcc_filename = "kcc.bin";                  // 密码卡中的kcc文件


    // 导入kbc
    if (km_key_import(dbname, as_tablename, kbc_filename) != LD_KM_OK)
    {
        log_warn("kbc key import failed\n");
        return -1;
    }
    // 导入kcc
    if (km_key_import(dbname, as_tablename, kcc_filename) != LD_KM_OK)
    {
        log_warn("kcc key import failed\n");
        return -1;
    }
    return 0;
}