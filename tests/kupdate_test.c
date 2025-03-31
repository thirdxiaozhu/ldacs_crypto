#include "key_manage.h"
#include "kmdb.h"

int main()
{
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";
    const char *randseeds_table_name = "sgw_randseeds_store";

    uint8_t *sgw_name = "SGW"; // 测试本地标识
    uint8_t *gs_s_name = "GS1";
    uint8_t *gs_t_name = "GSt";
    uint8_t *as_name = "Berry";

    uint8_t rand[16];
    QueryResult_for_queryid *qr_sgw_kid = NULL;
    QueryResult_for_keyvalue *result = NULL;
    QueryResult_for_queryid *qr_gs_kid = NULL;
    QueryResult_for_queryid *qr_as_kid = NULL;
    QueryResult_for_rand *query_rst_rand = NULL;
    QueryResult_for_queryid *qr_mk = NULL;
    do
    {
        // 网关端查询待更新密钥id
        qr_mk = query_id(dbname, sgw_tablename, as_name, gs_s_name, MASTER_KEY_AS_GS, ACTIVE);
        if (qr_mk == NULL)
        {
            log_warn("Query rkid failed.\n");
            free_queryid_result(qr_mk);
            return LD_ERR_KM_QUERY;
        }

        // 网关端查询随机数 AS GS端同理
        query_rst_rand = query_rand(dbname, randseeds_table_name, qr_mk->ids[0]);
        if (query_rst_rand == NULL)
        {
            printf("query_rand failed\n");
            free_rand_result(query_rst_rand);
            return -1;
        }

        /* 网关端密钥更新 */
        if (sgw_update_master_key(dbname, sgw_tablename, qr_mk->ids[0], sgw_name, gs_t_name, query_rst_rand->rand_len, query_rst_rand->rand) != LD_KM_OK)
        {
            log_warn("sgw update masterkey failed\n");
            break;
        }
        log_warn("[**sgw update key OK. **]\n");

        // 查询新密钥id
        qr_sgw_kid = query_id(dbname, sgw_tablename, as_name, gs_t_name, MASTER_KEY_AS_GS, ACTIVE);
        if (qr_sgw_kid == NULL)
        {
            log_warn("NULL Query.\n");
            break;
        }
        else if (qr_sgw_kid->count > 1)
        {
            log_warn("id isn't unique\n");
            break;
        }

        // 将随机数与更新的主密钥进行映射
        l_km_err store_result = store_rand(dbname, randseeds_table_name, qr_sgw_kid->ids[0], query_rst_rand->rand_len, query_rst_rand->rand);
        if (store_result != LD_KM_OK)
        {
            log_warn("store_rand failed with error code: %d\n", store_result);
            break;
        }

        // 查询密钥值(发送给GS)
        result = query_keyvalue(dbname, sgw_tablename, qr_sgw_kid->ids[0]);
        if (!result)
        {
            log_warn("Key not found or error occurred.\n");
            break;
        }

        /* AS端密钥更新 */
        // 查询新密钥id
        qr_as_kid = query_id(dbname, as_tablename, as_name, gs_s_name, MASTER_KEY_AS_GS, ACTIVE);
        if (qr_as_kid == NULL)
        {
            log_warn("NULL Query.\n");
            break;
        }
        else if (qr_as_kid->count > 1)
        {
            log_warn("id isn't unique\n");
            break;
        }

        if (km_update_masterkey(dbname, as_tablename, qr_as_kid->ids[0], sgw_name, gs_s_name, gs_t_name, as_name, query_rst_rand->rand_len, query_rst_rand->rand) != LD_KM_OK)
        {
            log_warn("as update masterkey failed\n");
            break;
        }
        log_warn("[**as update key OK. **]\n");

        /* 源GS端撤销密钥 */
        qr_gs_kid = query_id(dbname, gs_s_tablename, as_name, gs_s_name, MASTER_KEY_AS_GS, ACTIVE);
        if (qr_gs_kid == NULL)
        {
            log_warn("Query NULL or more than one.\n");
            break;
        }

        if (km_revoke_key(dbname, gs_s_tablename, qr_gs_kid->ids[0]) != LD_KM_OK)
        {
            log_warn("gs revoke key err\n");
            break;
        }
        log_warn("[**source gs revoke key OK. **]\n");

        /* 目标GS端接收密钥 */
        if (km_install_key(dbname, gs_t_tablename, result->key_len, result->key, as_name, gs_t_name, query_rst_rand->rand_len, query_rst_rand->rand) != LD_KM_OK)
        {
            log_warn("target gs install key err\n");
            break;
        }
        log_warn("[**gs install key OK. **]\n");

    } while (0);

    // 释放资源
    if (qr_sgw_kid)
        free(qr_sgw_kid); // 假设 query_id() 需要手动释放
    if (result)
        free(result); // 假设 query_keyvalue() 需要手动释放
    if (qr_gs_kid)
        free(qr_gs_kid); // 假设 query_id() 需要手动释放
    if (query_rst_rand)
        free_rand_result(query_rst_rand);
    if (qr_mk)
        free_queryid_result(qr_mk);
    if (qr_as_kid)
       free_queryid_result(qr_as_kid);
    return 0;
}