/**
 * @author wencheng
 * @version 2024/09/04 二次更新
 * @brief 主密钥更新测试 三端
 */

#include "key_manage.h"
#include "kmdb.h"

int main()
{
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    // uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *gs_t_2tablename = "gs_t2_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";

    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    // uint8_t *sac_gs_s = "GS";
    uint8_t *sac_gs_t = "GSt";
    uint8_t *sac_gs_t_2 = "GSt2";
    uint8_t *sac_as = "Berry";

    do
    {
        uint32_t rand_len = 16;
        uint8_t rand[rand_len];
        if (km_generate_random(rand, 16) != LD_KM_OK)
        {
            log_warn("Error generating random. \n");
            return LD_ERR_KM_GENERATE_RANDOM;
        }
        // printbuff("rand", rand, rand_len);

        /* 网关端密钥更新 */

        if (km_update_masterkey(dbname, sgw_tablename, sac_sgw, sac_gs_t, sac_gs_t_2, sac_as, rand_len, rand) != LD_KM_OK)
        {
            log_warn("sgw update masterkey failed\n");
            break;
        }
        log_warn("[**sgw update key OK. **]\n");

        // break; // 多次更新测试停靠点

        // 查询新密钥id
        QueryResult_for_queryid *qr_mkid = query_id(dbname, sgw_tablename, sac_as, sac_gs_t_2, MASTER_KEY_AS_GS, ACTIVE);
        if (qr_mkid == NULL)
        {
            log_warn("NULL Query.\n");
            break;
        }
        else if (qr_mkid->count > 1)
        {
            log_warn("id isn't unique\n");
            break;
        }
        // log_warn("[**sgw query_id OK. **]\n");
        // 查询密钥值(发送给GS)
        QueryResult_for_keyvalue *result = query_keyvalue(dbname, sgw_tablename, qr_mkid->ids[0]);
        if (!result)
        {
            log_warn("Key not found or error occurred.\n");
            break;
        }
        // log_warn("[**sgw  query keyvalue OK]\n");

        /* AS端密钥更新 */
        if (km_update_masterkey(dbname, as_tablename, sac_sgw, sac_gs_t, sac_gs_t_2, sac_as, rand_len, rand) != LD_KM_OK)
        {
            log_warn("sgw update masterkey failed\n");
            break;
        }
        log_warn("[**as update key OK. **]\n");

        /* 源GS端撤销密钥 */
        QueryResult_for_queryid *qr_gskid = query_id(dbname, gs_t_tablename, sac_as, sac_gs_t, MASTER_KEY_AS_GS, ACTIVE);
        if (qr_gskid == NULL)
        {
            log_warn("Query NULL or more than one.\n");
            break;
        }
        // log_warn("s-gs masterkey id: %s\n", id_gs);
        if (km_revoke_key(dbname, gs_t_tablename, qr_gskid->ids[0]) != LD_KM_OK)
        {
            log_warn("gs revoke key err\n");
            break;
        }
        log_warn("[**source gs revoke key OK. **]\n");

        /* 目标GS端接收密钥 */
        if (km_install_key(dbname, gs_t_2tablename, result->key_len, result->key, sac_as, sac_gs_t_2, rand_len, rand) != LD_KM_OK)
        {
            log_warn("target gs install key err\n");
            break;
        }
        log_warn("[**gs install key OK. **]\n");

    } while (0);
}