/**
 * @author wencheng
 * @date 2024/7/9
*/


#ifndef UNTITLED_PACKET_H
#define UNTITLED_PACKET_H


/*
 * 需要考虑更具体的数据类型
 */
enum field_type
{
    ft_mbz,  /* must be zero, abort */
    ft_set,  /* bits representing set */
    ft_enum, /* value from an enumeration*/
    ft_plen, /* record pdu length */
    /* when len field is plen(a.k.a record whole pdu length), use this tag.
     * When using this tag, make sure the desc dields of fp is the pointer of size_t
     * which identifying the length after this field  */
    ft_p_raw,
    ft_slen, /* record sdu length */
    ft_len,  /* km length tag*/
    ft_fix,
    ft_sqn,
    ft_mac,
    ft_time,
    /* only can be used when str (has / can be calculated) a fix length */
    ft_str,
    ft_pad, /* bits padding to octet*/
    ft_crc,
    ft_end, /* end of field list */
    
    // key management related fields
    ft_uuid,
    ft_uint8t_pointer,
    // ft_enum,
    ft_uint32t,
    ft_timet,
    ft_uint16t,
    // ft_end,
};

typedef struct field_desc
{
    enum field_type field_type;
    const int size; /* size, in bits, of field */
    const char *name;
    const void *desc; /* enum_names for enum or char *[] for bits */
} field_desc;

#endif /* UNTITLED_PACKET_H */