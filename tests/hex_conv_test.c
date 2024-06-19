/**
 * @brief 字节流转16进制 16进制转回字节流
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// void hex_to_bytes(const char *hex_str, uint8_t *bytes)
// {
//     size_t len = strlen(hex_str);
//     for (size_t i = 0; i < len; i += 2)
//     {
//         sscanf(hex_str + i, "%2hhX", &bytes[i / 2]);
//     }
// }
uint8_t *hex_to_bytes(const char *hex_str)
{

    size_t len = strlen(hex_str);
    uint8_t *bytes = malloc(sizeof(uint8_t) * len / 2); // 原始字节数据的长度是字符串长度的一半
    for (size_t i = 0; i < len; i += 2)
    {
        sscanf(hex_str + i, "%2hhX", &bytes[i / 2]);
    }
    return bytes;
}

uint8_t *bytes_to_hex(uint8_t *bytes, uint16_t bytes_len)
{
    uint8_t *hex_str;
    hex_str = malloc(sizeof(uint8_t) * bytes_len * 2);
    for (int i = 0; i < bytes_len; i++)
    {
        sprintf(hex_str + i * 2, "%02X", bytes[i]);
    }
    return hex_str;
}

int main()
{

    uint8_t cipher[16] = {0x03, 0x03, 0x03, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint16_t len = 16;
    uint8_t *kek_cipher;
    kek_cipher = bytes_to_hex(cipher, len);
    printf("kek cipher string :%s\n", kek_cipher);

    // 分配足够的空间来存储原始数据
    uint8_t *buff;
    // 将十六进制字符串转换回字节
    buff = hex_to_bytes((char *)kek_cipher);

    // 输出结果
    printf("Original data: ");
    for (int i = 0; i < len; i++)
    {
        printf("%02X ", buff[i]);
    }
    printf("\n");

    return 0;
}
