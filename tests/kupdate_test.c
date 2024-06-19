/**
 * @author wencheng
 * @version 2024/06/07
 * @brief 主密钥更新测试
 */

#include "key_manage.h"
#include "database.h"

int main()
{
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";

    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs_s = "GS1";
    uint8_t *sac_gs_t = "GSt";
    uint8_t *sac_as = "Berry";

    do
    {
        uint32_t rand_len = 16;
        uint8_t rand[rand_len];
        km_generate_random(rand, 16);

        /* 网关端密钥更新 */
        /*
        if (km_update_masterkey(dbname, sgw_tablename, sac_sgw, sac_gs_s, sac_gs_t, sac_as, rand_len, rand) != LD_KM_OK)
        {
        printf("sgw update masterkey failed\n");
        break;
        }
        printf("[**sgw update key OK. **]\n");
        */

        // 查询新密钥id
        QueryResult_for_queryid qr_mkid = query_id(dbname, sgw_tablename, sac_as, sac_gs_t, MASTER_KEY_AS_GS);
        if (qr_mkid.count == 0)
        {
            printf("NULL Query.\n");
            break;
        }
        else if (qr_mkid.count > 1)
        {
            printf("id isn't unique\n");
            break;
        }
        // printf("[**sgw query_id OK. **]\n");

        // 查询密钥值
        QueryResult_for_keyvalue result = query_keyvalue(dbname, sgw_tablename, qr_mkid.ids[0]);
        if (!result.key)
        {
            printf("Key not found or error occurred.\n");
            break;
        }
        // printf("[**sgw  query keyvalue OK]\n");

        /* AS端密钥更新 */
        /*
        if (km_update_masterkey(dbname, as_tablename, sac_sgw, sac_gs_s, sac_gs_t, sac_as, rand_len, rand) != LD_KM_OK)
        {
            printf("sgw update masterkey failed\n");
            break;
        }
        printf("[**as update key OK. **]\n");
        */

        /* 源GS端撤销密钥 */
        /*
        // 查询密钥id
        QueryResult_for_queryid qr_gskid = query_id(dbname, gs_s_tablename, sac_gs_s, sac_as, MASTER_KEY_AS_GS);
        if (qr_gskid.count != 1)
        {
            printf("Query NULL or more than one.\n");
            break;
        }
        // printf("s-gs masterkey id: %s\n", id_gs);

        if (km_revoke_key(dbname, gs_s_tablename, qr_gskid.ids[0]) != LD_KM_OK)
        {
            printf("gs revoke key err\n");
            break;
        }
        printf("[**source gs revoke key OK. **]\n");
        */

        /* 目标GS端接收密钥 */
        
        if (km_install_key(dbname, gs_t_tablename, result.key_len, result.key, sac_as, sac_gs_t, rand_len, rand) != LD_KM_OK)
        {
            printf("target gs install key err\n");
            break;
        }
        printf("[**gs install key OK. **]\n");
        
    } while (0);
}