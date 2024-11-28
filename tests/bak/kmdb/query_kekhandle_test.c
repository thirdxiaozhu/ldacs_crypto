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
    uint8_t *id = "e95050ac-08be-493a-85dc-4e6f37136f51";

    // 调用查询函数
    QueryResult_for_kekhandle *result = query_kekhandle(dbname, sgw_tablename, id);
    
    if (result != NULL) {
        // 处理查询结果
            printf("KEK Handle: %p\n", result->kek_handle);

    } else {
        printf("No KEK handles found or query failed.\n");
    }
    
    return 0;
}
