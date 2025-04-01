//
// Created by jiaxv on 5/30/24. 随机数生成测试
//
#include "key_manage.h"

int main()
{
    uint8_t rand[64] = {0};

    int count = 1024;
    int key_len = 32;
    clock_t start, end;
    double cpu_time_used;

    start = clock();

    // 密钥生成代码
    for (int i = 0; i < count; i++)
    {
        km_generate_random(rand, key_len);
        // printbuff("rand", rand, 16);
    }

    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;

    printf("生成长度为%d的密钥的时间为: %f seconds\n", key_len, cpu_time_used / 1024);
}