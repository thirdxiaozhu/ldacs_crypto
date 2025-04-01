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
    uint8_t *id = "dbe03c58-8507-423c-aeba-6c4620acac43";

    // 定义输出参数
    void * key_handle = NULL;

    // 调用接口函数
    l_km_err result = get_handle_from_db(dbname, sgw_tablename, id, &key_handle);

    // 处理返回值
    if (result == LD_KM_OK)
    {
        printf("成功获取密钥句柄。%p\n",key_handle);
    }
    else
    {
        printf("获取密钥句柄失败，错误码: %d\n", result);
    }

    return 0;
}
