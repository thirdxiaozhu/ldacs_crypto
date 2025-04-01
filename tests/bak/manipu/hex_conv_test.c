/**
 * @brief 字节流转16进制 16进制转回字节流
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <key_manage.h>

// void hex_to_bytes(const char *hex_str, uint8_t *bytes)
// {
//     size_t len = strlen(hex_str);
//     for (size_t i = 0; i < len; i += 2)
//     {
//         sscanf(hex_str + i, "%2hhX", &bytes[i / 2]);
//     }
// }
// uint8_t *hex_to_bytes(const char *hex_str)
// {

//     size_t len = strlen(hex_str);
//     uint8_t *bytes = malloc(sizeof(uint8_t) * len / 2); // 原始字节数据的长度是字符串长度的一半
//     for (size_t i = 0; i < len; i += 2)
//     {
//         sscanf(hex_str + i, "%2hhX", &bytes[i / 2]);
//     }
//     return bytes;
// }

// uint8_t *bytes_to_hex(uint8_t *bytes, uint16_t bytes_len)
// {
//     uint8_t *hex_str;
//     hex_str = malloc(sizeof(uint8_t) * bytes_len * 2);
//     for (int i = 0; i < bytes_len; i++)
//     {
//         sprintf(hex_str + i * 2, "%02X", bytes[i]);
//     }
//     return hex_str;
// }

/**
 * @brief 将字节数组转换为十六进制字符串
 * @param[in] buff 输入的字节数组
 * @param[in] len 字节数组的长度
 * @param[out] hex_str 输出的十六进制字符串
 * @param[in] hex_str_len 十六进制字符串的长度
 * @return 转换是否成功
 */
int bytes_to_hex_str(uint8_t *buff, uint16_t len, char *hex_str, uint16_t hex_str_len) {
    // 检查输入参数
    if (hex_str_len < len * 2 + 1) {
        return -1;  // 如果目标字符串长度不足，返回错误
    }

    for (int i = 0; i < len; i++) {
        // 每个字节转换为两个十六进制字符
        snprintf(hex_str + i * 2, 3, "%02X", buff[i]); // 使用 3 来确保不会越界
    }
    hex_str[len * 2] = '\0';  // 确保字符串以 '\0' 结尾

    return 0;  // 成功
}

int main() {
    // 定义输入的字节数组和长度
    uint8_t input_buff[] = {0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F};
    uint16_t input_len = sizeof(input_buff);

    // 定义输出字符串的长度
    uint16_t hex_str_len = input_len * 2 + 1;
    char hex_str[hex_str_len];

    // 调用接口进行转换
    int result = bytes_to_hex_str(input_buff, input_len, hex_str, hex_str_len);

    // 检查转换结果
    if (result == 0) {
        printf("转换成功，十六进制字符串: %s\n", hex_str);
    } else {
        printf("转换失败，目标缓冲区长度不足。\n");
    }

    return 0;
}

/*
int main()
{

    uint8_t cipher[16] = {0x03, 0x03, 0x03, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x20};
    uint16_t len = 16;
    uint8_t *kek_cipher;
    kek_cipher = bytes_to_hex(cipher, len);
    log_warn("kek cipher string :%s\n", kek_cipher);

    // 分配足够的空间来存储原始数据
    uint8_t *buff;
    // 将十六进制字符串转换回字节
    buff = hex_to_bytes((char *)kek_cipher);

    // 输出结果
    log_warn("Original data: ");
    for (int i = 0; i < len; i++)
    {
        log_warn("%02X ", buff[i]);
    }
    log_warn("\n");

    return 0;
}
*/