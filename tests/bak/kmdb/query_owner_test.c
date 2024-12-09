/**
 * @author wencheng
 * @version 2024/06/25
 * @brief data handle and database test
 */

#include "key_manage.h"
#include "kmdb.h"

int main()
{

    uint8_t *dbname = "keystore.db";
    uint8_t *primary_key = "id";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";

    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs_s = "GS1";
    uint8_t *sac_gs_t = "GSt";
    uint8_t *sac_as = "Berry";

   // 调用查询函数
   uint8_t* id = "5b790a0a-15bb-4ac0-ad24-e739dfe08d0f";
    QueryResult_for_owner *result = query_owner(dbname, sgw_tablename, id);
    
    if (result != NULL) {
        // 处理查询结果
        if (result->owner1 != NULL) {
            printf("Owner 1: %s\n", result->owner1);
        } else {
            printf("Owner 1: Not found\n");
        }

        if (result->owner2 != NULL) {
            printf("Owner 2: %s\n", result->owner2);
        } else {
            printf("Owner 2: Not found\n");
        }

        // 释放查询结果
        // free_owner_result(result);
    } else {
        printf("Query failed or no owners found.\n");
    }
    
    return 0;
}
