#include "kup_packet.h"
#include <stdio.h>

// 初始化 buffer_t 结构体
void buffer_init(buffer_t *buffer, size_t len, uint8_t *data)
{
    if (buffer == NULL)
        return;
    buffer->len = len;
    buffer->total = len;
    buffer->free = 0;
    if (data)
    {
        buffer->ptr = (uint8_t *)malloc(len);
        if (buffer->ptr)
        {
            memcpy(buffer->ptr, data, len);
        }
        else
        {
            fprintf(stderr, "Error: memory allocation for buffer_t failed\n");
        }
    }
    else
    {
        buffer->ptr = NULL;
    }
}

struct KupdateRemind
{
    uint16_t g_type;
    uint16_t ver;
    uint16_t sac_as;
    uint16_t element_type;
    uint16_t sac_gs_s;
    uint16_t sac_gs_t;
};

struct KupdateRemind *kupdate_remind_new(uint16_t g_type, uint16_t ver, uint16_t sac_as, uint16_t element_type, uint16_t sac_gs_s, uint16_t sac_gs_t)
{
    // 动态分配内存
    struct KupdateRemind *kr = (struct KupdateRemind *)malloc(sizeof(struct KupdateRemind));

    // 检查内存分配是否成功
    if (kr == NULL)
    {
        fprintf(stderr, "Error: memory allocation failed\n");
        return NULL;
    }

    // 变量赋值
    kr->g_type = g_type;
    kr->ver = ver;
    kr->sac_as = sac_as;
    kr->element_type = element_type;
    kr->sac_gs_s = sac_gs_s;
    kr->sac_gs_t = sac_gs_t;

    return kr;
}

static km_field_desc kupdate_remind_field[] = {
    // 密钥更新提醒字段描述
    {ft_enum, 8, "G_TYPE", NULL},
    {ft_enum, 4, "VER", NULL},
    {ft_set, 12, "SAC_AS", NULL},
    {ft_enum, 4, "Element_Type", NULL},
    {ft_set, 12, "SAC_GSS", NULL},
    {ft_set, 12, "SAC_GST", NULL},
    {ft_end, 0, NULL, NULL},
};

struct KupdateRequest
{
    uint16_t s_type;
    uint16_t ver;
    uint16_t pid;
    uint16_t sac_as;
    uint16_t key_type;
    uint16_t sac_gs_s;
    uint16_t sac_gs_t;
    buffer_t ncc;
    buffer_t nonce;
};

// 新建并初始化 KupdateRequest 的接口
struct KupdateRequest *kupdate_request_new(uint16_t s_type, uint16_t ver, uint16_t pid, uint16_t sac_as, uint16_t key_type, uint16_t sac_gs_s,
                                           uint16_t sac_gs_t, size_t ncc_len, uint8_t *ncc_data, size_t nonce_len, uint8_t *nonce_data)
{
    // 动态分配内存
    struct KupdateRequest *kr = (struct KupdateRequest *)malloc(sizeof(struct KupdateRequest));

    // 检查内存分配是否成功
    if (kr == NULL)
    {
        fprintf(stderr, "Error: memory allocation failed\n");
        return NULL;
    }

    // 初始化结构体成员
    kr->s_type = s_type;
    kr->ver = ver;
    kr->pid = pid;
    kr->sac_as = sac_as;
    kr->key_type = key_type;
    kr->sac_gs_s = sac_gs_s;
    kr->sac_gs_t = sac_gs_t;

    // 初始化嵌套的 buffer_t 结构体
    buffer_init(&kr->ncc, ncc_len, ncc_data);
    buffer_init(&kr->nonce, nonce_len, nonce_data);

    return kr;
}

static km_field_desc kupdate_request_field[] = {
    // 密钥更新请求字段描述
    {ft_enum, 8, "S_TYPE", NULL},
    {ft_enum, 4, "VER", NULL},
    {ft_enum, 2, "PID", NULL},
    {ft_set, 12, "SAC_AS", NULL},
    {ft_enum, 4, "KEY_TYPE", NULL},
    {ft_set, 12, "SAC_GSS", NULL},
    {ft_set, 12, "SAC_GST", NULL},
    {ft_str, 16, "NCC", NULL},
    {ft_str, 128, "NONCE", NULL},
    {ft_end, 0, NULL, NULL},
};

struct KupdateResponse
{
    uint16_t s_type;
    uint16_t ver;
    uint16_t pid;
    uint16_t sac_as;
    uint16_t key_type;
    uint16_t sac_gs_t;
    buffer_t ncc;
};

static km_field_desc kupdate_response_field[] = {
    // 密钥更新响应字段描述
    {ft_enum, 8, "S_TYPE", NULL},
    {ft_enum, 4, "VER", NULL},
    {ft_enum, 2, "PID", NULL},
    {ft_set, 12, "SAC_AS", NULL},
    {ft_enum, 4, "KEY_TYPE", NULL},
    {ft_set, 12, "SAC_GST", NULL},
    {ft_str, 16, "NCC", NULL},
    {ft_end, 0, NULL, NULL},
};

struct KupdateTransport
{
    uint16_t g_type;
    uint16_t ver;
    uint16_t sac_as;
    uint16_t element_type;
    uint16_t element_length;
    uint16_t key_type;
    buffer_t key;
    buffer_t nonce;
};

static km_field_desc kupdate_keytransport_field[] = {
    // 密钥更新-下发密钥字段描述
    {ft_enum, 8, "G_TYPE", NULL},
    {ft_enum, 4, "VER", NULL},
    {ft_set, 12, "SAC_AS", NULL},
    {ft_enum, 4, "Element_Type", NULL},
    {ft_len, 4, "Element_Length", NULL},
    {ft_enum, 4, "KEY_TYPE", NULL},
    {ft_str, 128, "KEY", NULL},
    {ft_str, 128, "NONCE", NULL},
    {ft_end, 0, NULL, NULL},
};

struct_desc_t static test_pdu_desc = {"kupdate_remind_packet", kupdate_remind_field};

int main()
{
    /* 新建并初始化结构体KupdateRemind */
    /*
    struct KupdateRemind *kr = kupdate_remind_new(1, 2, 3, 4, 5, 6);
    // 检查结构体指针是否为空
    if (kr == NULL)
    {
        fprintf(stderr, "Error: kupdate_remind_new failed\n");
        // 输出结构体成员以验证初始化
        printf("g_type: %u\n", kr->g_type);
        printf("ver: %u\n", kr->ver);
        printf("sac_as: %u\n", kr->sac_as);
        printf("element_type: %u\n", kr->element_type);
        printf("sac_gs_s: %u\n", kr->sac_gs_s);
        printf("sac_gs_t: %u\n", kr->sac_gs_t);
        return -1;
    }
    // 释放内存
    free(kr);
    */

    /*新建并初始化结构体KupdateRequest */
    // 示例数据
    uint8_t ncc_data[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t nonce_data[] = {0xAA, 0xBB, 0xCC, 0xDD};
    struct KupdateRequest *kr = kupdate_request_new(
        1, 2, 3, 4, 5, 6, 7,
        sizeof(ncc_data), ncc_data,
        sizeof(nonce_data), nonce_data);

    // 检查结构体指针是否为空
    if (kr == NULL)
    {
        fprintf(stderr, "Error: kupdate_request_new failed\n");
        return 1;
    }

    // 输出结构体成员以验证初始化
    printf("s_type: %u\n", kr->s_type);
    printf("ver: %u\n", kr->ver);
    printf("pid: %u\n", kr->pid);
    printf("sac_as: %u\n", kr->sac_as);
    printf("key_type: %u\n", kr->key_type);
    printf("sac_gs_s: %u\n", kr->sac_gs_s);
    printf("sac_gs_t: %u\n", kr->sac_gs_t);
    printf("ncc: len = %zu, total = %zu, free = %zu, ptr = %p\n", kr->ncc.len, kr->ncc.total, kr->ncc.free, (void *)kr->ncc.ptr);
    printf("nonce: len = %zu, total = %zu, free = %zu, ptr = %p\n", kr->nonce.len, kr->nonce.total, kr->nonce.free, (void *)kr->nonce.ptr);

    // 释放内存
    if (kr->ncc.ptr)
        free(kr->ncc.ptr);
    if (kr->nonce.ptr)
        free(kr->nonce.ptr);
    free(kr);

    return 0;
}