#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"
#include <uuid/uuid.h>
/* 
* @date 20250225
* @brief 密钥导入和获取句柄性能测试
* @author wencheng
*/
int main(void)
{
    uint8_t *dbname = "keystore1.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_tablename = "gs_s_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";
    uint8_t *primary_key = "id";
    uint8_t *sac_sgw = "000010000"; // 测试本地标识
    uint8_t *sac_gs = "GS1";
    uint8_t *sac_as = "000010010";
    uint8_t *id = "e0fd50ed-fe01-4d39-afd0-4accd4791cbd";

    void *handle;

    clock_t start, end;
    double cpu_time_used;
    start = clock();

    if (get_handle_from_db(dbname, sgw_tablename, id, &handle) != LD_KM_OK)
    {
        fprintf(stderr, "[** get_handle error**]\n");
        return LD_ERR_KM_GET_HANDLE;
    }

     end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("获取句柄的时间为: %f seconds\n", cpu_time_used);
}