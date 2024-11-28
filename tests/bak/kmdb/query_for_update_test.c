#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>  // for malloc, realloc
#include <sqlite3.h> // SQLite library

#define MAX_STRING_LEN 256
#include "key_manage.h"
#include "kmdb.h"

int main()
{
    // Example usage of query_id function

    uint8_t *db_name = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";

    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs_s = "GS1";
    uint8_t *sac_gs_t = "GSt";
    uint8_t *sac_as = "Berry";
    enum KEY_TYPE key_type = MASTER_KEY_AS_GS; // Assume KEY_TYPE is defined somewhere
    enum STATE state = ACTIVE;

    // 调用接口函数
    uint8_t* id = "628c13a8-d94f-49f6-941f-22bf0230257d";
    QueryResult_for_update *result = query_for_update(db_name, sgw_tablename, id);
    
    if (result != NULL) {
        // 处理和输出查询结果
        printf("查询结果:\n");
        printf("密钥长度: %u\n", result->key_len);
        printf("更新周期: %u\n", result->update_cycle);
        printf("更新次数: %u\n", result->update_count);
        
        // 释放查询结果占用的内存
        free(result);
    } else {
        printf("查询失败，返回结果为 NULL。\n");
    }
    
    return 0;
}