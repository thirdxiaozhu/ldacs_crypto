/**
 * @author wencheng
 * @date 2024/7/9
 */

#ifndef UNTITLED_PACKET_H
#define UNTITLED_PACKET_H

/*
 * 需要考虑更具体的数据类型
 */
enum km_field_type
{
    // key management related fields
    ft_uuid,
    ft_uint8t_pointer,
    ft_enum,
    ft_uint32t,
    ft_timet,
    ft_uint16t,
    ft_end,
};

typedef struct km_field_desc
{
    enum km_field_type km_field_type;
    const int size; /* size, in bits, of field */
    const char *name;
    const void *desc; /* enum_names for enum or char *[] for bits */
} km_field_desc;

#endif /* UNTITLED_PACKET_H */