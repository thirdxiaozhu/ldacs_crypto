//
// Created by wencheng on 2024/07/01
//
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"


int main()
{
    // 网关端根密钥生成
    const char *dbname = "keystore.db";
    const char *sgw_tablename = "sgw_keystore";
    const char *sgw_name = "SGW";
    const char *as_name = "Berry";
    uint32_t rootkey_len = 16;
    const char *export_dir = "/home/wencheng/key_management/build/rootkey.bin"; // 导出根密钥到文件
    uint32_t validity_period = 365;                                          // 更新周期365天

    if (root_key_gen(as_name, sgw_name, rootkey_len, validity_period, dbname, sgw_tablename, export_dir))
    {
        printf("根密钥生成、保存和导出失败。\n");
    }

    return 0;
}
