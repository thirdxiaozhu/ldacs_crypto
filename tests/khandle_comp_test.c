/**
 * 2024/09/09 by wencheng 密钥句柄对比
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

int main()
{
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *gs_t_2tablename = "gs_t2_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";

    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs_s = "GS1";
    uint8_t *sac_gs_t = "GSt";
    uint8_t *sac_gs_t_2 = "GSt2";
    uint8_t *sac_as = "Berry";

    enum KEY_TYPE type = MASTER_KEY_AS_GS;

    // hmac 测试kdk handle是否相同
    uint32_t hmac_len;
    uint8_t hmac_value[32] = {0};
    int ret_hmac = km_hmac_with_keyhandle(handle_mk, "0123456789abcdef", sizeof("0123456789abcdef"), hmac_value, &hmac_len);
    if (ret_hmac != LD_KM_OK)
    {
        printf("Error in hmac_with_keyhandle\n, ret", ret_hmac);
        return LD_ERR_KM_HMAC;
    }
}