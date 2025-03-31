/**
 * @author wencheng
 * @date 2024/07/01
 * @brief rkey gen and export to file
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

int main()
{
    // 网关端根密钥生成
    const char *dbname = "keystore1.db";
    const char *sgw_tablename = "sgw_keystore";
    const char *sgw_name = "000010000";
    const char *as_name = "000010010";
    uint32_t rootkey_len = 16;
    const char *export_dir = "../keystore/rootkey.bin"; // 导出根密钥到文件
    // const char *export_dir = "/root/ldacs/stack_new/ldacs_stack/resources/keystore/rootkey.bin"; // 导出根密钥到文件";
    uint32_t validity_period = 365; // 更新周期365天

    if (km_rkey_gen_export(as_name, sgw_name, rootkey_len, validity_period, dbname, sgw_tablename, export_dir))
    {
        log_warn("根密钥生成、保存和导出失败。\n");
    }

    log_warn("OK\n");

    return 0;
}
