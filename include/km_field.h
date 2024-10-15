/**
 * @author wencheng
 * @date 2024/7/9
 */

#ifndef UNTITLED_PACKET_H
#define UNTITLED_PACKET_H

/*
 * 需要考虑更具体的数据类型
 */
enum km_field_type // 字段类型
{
    // key management related fields
    ft_uuid,           // 密钥id的类型
    ft_uint8t_pointer, // 指针类型
    ft_enum,           // 枚举类型
    ft_uint32t,        // uint32类型
    ft_timet,          // 时间类型
    ft_uint16t,        // uint16类型
    ft_end,            // 结束符
};

typedef struct km_field_desc
{
    enum km_field_type km_field_type;             // 字段类型
    const int size; /* size, in bits, of field */ // 字段大小
    const char *name;                             // 字段名称
    const void *desc;                             /* enum_names for enum or char *[] for bits */
} km_field_desc;

#endif /* UNTITLED_PACKET_H */