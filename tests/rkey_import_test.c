
/**
 * @brief AS side rootkey import and store
 * @author wencheng
 * @date 2024/07/01
 */

#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

int main()
{
    const char *dbname = "keystore.db";
    const char *as_tablename = "as_keystore";

    // root key import
    const char *rkey_filename_in_ccard = "rootkey.bin";
    if (km_rkey_import(dbname, as_tablename, rkey_filename_in_ccard) != LD_KM_OK)
    {
        log_warn("root key import failed\n");
        return -1;
    }
    return 0;
}