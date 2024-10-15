#include "key_manage.h"
#include "kmdb.h"

int main()
{
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";

    uint8_t *sgw_name = "SGW"; // 测试本地标识
    uint8_t *gs_s_name = "GS1";
    uint8_t *gs_t_name = "GSt";
    uint8_t *as_name = "Berry";
    uint8_t* id = "dc3ad0c5-2919-4f06-84b2-c0dac85f9b42";

    uint8_t rand[16];                         // 移到循环外
    QueryResult_for_queryid *qr_mkid = NULL;  // 移到循环外
    QueryResult_for_keyvalue *result = NULL;  // 移到循环外
    QueryResult_for_queryid *qr_gskid = NULL; // 移到循环外

    if (km_generate_random(rand, 16) != LD_KM_OK)
    {
        printf("Error generating random. \n");
        return LD_ERR_KM_GENERATE_RANDOM;
    }

    do
    {
        /* 网关端密钥更新 */
        if (sgw_update_master_key(dbname, sgw_tablename, id, sgw_name, gs_t_name, sizeof(rand), rand) != LD_KM_OK)
        {
            printf("sgw update masterkey failed\n");
            break;
        }
        printf("[**sgw update key OK. **]\n");

        // 查询新密钥id
        qr_mkid = query_id(dbname, sgw_tablename, as_name, gs_t_name, MASTER_KEY_AS_GS, ACTIVE);
        if (qr_mkid == NULL)
        {
            printf("NULL Query.\n");
            break;
        }
        else if (qr_mkid->count > 1)
        {
            printf("id isn't unique\n");
            break;
        }

        // 查询密钥值(发送给GS)
        result = query_keyvalue(dbname, sgw_tablename, qr_mkid->ids[0]);
        if (!result)
        {
            printf("Key not found or error occurred.\n");
            break;
        }

        /* AS端密钥更新 */
        if (km_update_masterkey(dbname, as_tablename, sgw_name, gs_s_name, gs_t_name, as_name, sizeof(rand), rand) != LD_KM_OK)
        {
            printf("as update masterkey failed\n");
            break;
        }
        printf("[**as update key OK. **]\n");

        /* 源GS端撤销密钥 */
        qr_gskid = query_id(dbname, gs_s_tablename, as_name, gs_s_name, MASTER_KEY_AS_GS, ACTIVE);
        if (qr_gskid == NULL)
        {
            printf("Query NULL or more than one.\n");
            break;
        }

        if (km_revoke_key(dbname, gs_s_tablename, qr_gskid->ids[0]) != LD_KM_OK)
        {
            printf("gs revoke key err\n");
            break;
        }
        printf("[**source gs revoke key OK. **]\n");

        /* 目标GS端接收密钥 */
        if (km_install_key(dbname, gs_t_tablename, result->key_len, result->key, as_name, gs_t_name, sizeof(rand), rand) != LD_KM_OK)
        {
            printf("target gs install key err\n");
            break;
        }
        printf("[**gs install key OK. **]\n");

    } while (0);

    // 释放资源
    if (qr_mkid)
        free(qr_mkid); // 假设 query_id() 需要手动释放
    if (result)
        free(result); // 假设 query_keyvalue() 需要手动释放
    if (qr_gskid)
        free(qr_gskid); // 假设 query_id() 需要手动释放

    return 0;
}