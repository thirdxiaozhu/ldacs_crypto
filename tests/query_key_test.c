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

    // 查询密钥值
    uint8_t *id = "1b686bba-bc08-4b7e-ae00-adf169d109f3";
    printf("query keyvalue where id =  %s....\n", id);
    QueryResult_for_keyvalue *result = query_keyvalue(dbname, sgw_tablename, id);
    if (!result)
    {
        printf("Key not found or error occurred.\n");
    }
    printbuff("key value",result->key,result->key_len);
    free_keyvalue_result(result);

}
