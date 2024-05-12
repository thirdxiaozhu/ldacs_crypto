// 20240420 by wencheng test hmac生成和校验时间
#include <stdio.h>
#include <string.h>
#include "key_manage.h"

int main()
{
    void *DeviceHandle, *pSessionHandle, *phKeyHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &pSessionHandle); // 打开会话句柄
    // uint8_t data[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    //                     0x29, 0xbe, 0xe1, 0xd6, 0x52, 0x49, 0xf1, 0xe9, 0xb3, 0xdb, 0x87, 0x3e, 0x24, 0x0d, 0x06, 0x47};
    // unsigned int data_len = 32;
    uint8_t hmac_data[32]; // 分配足够的空间来存储 HMAC 数据
    uint32_t hmac_data_len;
    uint32_t hmac_key_len = 16;
    uint8_t hmac_key[16];
    void *keyhandle;
    int ret = SDF_GenerateRandom(pSessionHandle, 16, hmac_key);
    if (ret != 0)
    {
        printf("Error in SDF_GenerateRandom,return : %d\n", ret);
    }

    SDF_ImportKey(pSessionHandle, hmac_key, hmac_key_len, &keyhandle);

    unsigned int data_len = 1024;
    uint8_t data[data_len];
    // 生成数据
    generate_random(data_len, data);

    // 1000次取平均
    clock_t start, end;
    double avg_cpu_time_used;
    double total_cpu_time_used = 0;
    for (int i = 0; i < 1000; i++)
    {
        start = clock(); // 记录开始时间
        ret = hmac_with_keyhandle(keyhandle, data, data_len, hmac_data, &hmac_data_len);
        end = clock();                                                            // 记录结束时间
        total_cpu_time_used += ((double)(end - start)) * 1000000.0 / CLOCKS_PER_SEC; // 计算执行时间，单位为毫秒
    }
    avg_cpu_time_used = total_cpu_time_used / 1000; // 计算平均执行时间，单位为毫秒
    printf("HMAC 1000次 %d字节数据，平均每次执行时间：%.3f 毫秒, 速度%.3fMb/s\n", data_len, avg_cpu_time_used, data_len *8 / avg_cpu_time_used);
    // if (ret == 0)
    // {
    //     printbuff("data", data, data_len);
    //     printbuff("hmac", hmac_data, hmac_data_len);
    // }
    // else
    // {
    //     printf("Error in sm3_hmac,return : %d\n", ret);
    // }
}