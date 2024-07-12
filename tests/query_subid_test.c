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

    // 查询子密钥id
    uint8_t *id = "51f3abd5-8ce2-4536-986f-9658e622d247";
    enum KEY_TYPE key_type = MASTER_KEY_AS_SGW;
    QueryResult_for_subkey result = query_subkey(dbname, as_tablename, id, key_type);
    // 打印查询结果
    printf("%s %s ,%d subkeys is founded.\n", ktype_str(key_type), id, result.count);
    for (int i = 0; i < result.count; i++)
    {
        printf("Subkey ID %d: %s, Key Type: %s\n", i + 1, result.subkey_ids[i], result.key_types[i]);
        free(result.subkey_ids[i]);
        free(result.key_types[i]);
    }
    free(result.subkey_ids);
    free(result.key_types);
}
