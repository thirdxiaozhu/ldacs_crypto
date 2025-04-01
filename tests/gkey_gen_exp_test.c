/**
 * @author wencheng
 * @date 2024/12/04
 * @brief 网关端生成和导出组密钥 group gen and export to file
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

int main()
{
    // 网关端生成组密钥kbc和kcc
    const char *dbname = "keystore.db";
    const char *sgw_tablename = "sgw_keystore";
    const char *owner_1 = "000010000"; // gs的标识，暂且用网关的做测试
    const char *owner_2 = "";
    uint32_t key_len = 16;
    const char *export_kbc_dir = "../keystore/groupkey_bc.bin"; // 导出根密钥到文件
    const char *export_kcc_dir = "../keystore/groupkey_cc.bin"; // 导出根密钥到文件

    uint32_t validity_period = 365; // 更新周期365天

    if (km_key_gen_export(owner_1, owner_2, GROUP_KEY_BC, key_len, validity_period, dbname, sgw_tablename, export_kbc_dir))
    {
        fprintf(stderr, "kbc生成、保存和导出失败。\n");
        return -1;
    }

    if (km_key_gen_export(owner_1, owner_2, GROUP_KEY_CC, key_len, validity_period, dbname, sgw_tablename, export_kcc_dir))
    {
        fprintf(stderr, "kbc生成、保存和导出失败。\n");
        return -1;
    }
    fprintf(stderr, "OK\n");

    return 0;
}
