#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"
int main()
{
    // 运行测试
    // 测试数据
    uint8_t db_name[] = "keystore.db";
    uint8_t table_name[] = "gs_t_keystore";
    uint8_t id[] = "eb5f7490-36f4-4ac7-88d9-055fe2242611";
    uint16_t key_len = 0; // 密钥长度为0，表示密钥值为空
    uint8_t *key = NULL;  // 密钥指针为NULL

    // 调用接口
    l_km_err result = alter_keyvalue(db_name, table_name, id, key_len, key);
    if (result != LD_KM_OK)
    {
        printf("Test Failed: alter_keyvalue failed to set key to empty. Error code: %d\n", result);
    }
    return 0;
}
