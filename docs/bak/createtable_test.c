#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// 定义枚举类型表示字段类型
enum FieldType
{
    ft_uuid,
    ft_enum,
    ft_uint8t_pointer,
    ft_uint32t,
    ft_timet,
    ft_uint16t,
    ft_end
};

// 定义字段描述结构体
typedef struct
{
    enum FieldType type;
    int size;
    const char *name;
    const char *extra;
} field_desc;

// 函数：根据字段类型返回对应的 SQL 类型字符串
const char *sql_type(enum FieldType type)
{
    switch (type)
    {
    case ft_uuid:
        return "VARCHAR(256)";
    case ft_enum:
        return "INT";
    case ft_uint8t_pointer:
        return "VARCHAR(128)";
    case ft_uint32t:
        return "INT";
    case ft_timet:
        return "INT";
    case ft_uint16t:
        return "INT";
    default:
        return "";
    }
}

// 函数：创建 SQL 数据表语句并保存到 query 中
void create_table_query(const field_desc *fields)
{
    uint8_t *query = NULL;
    size_t query_size = 0;
    FILE *stream = open_memstream((char **)&query, &query_size);

    fprintf(stream, "CREATE TABLE IF NOT EXISTS table_name (\n");
    int i = 0;
    while (fields[i].type != ft_end)
    {
        fprintf(stream, "    %s %s", fields[i].name, sql_type(fields[i].type));
        if (fields[i].extra != NULL)
        {
            fprintf(stream, " %s", fields[i].extra);
        }
        fprintf(stream, ",\n");
        i++;
    }
    fprintf(stream, "    PRIMARY KEY (id)\n"); // 假设 id 为主键
    fprintf(stream, ");\n");

    fclose(stream);

    printf("Query:\n%s\n", query);
    
    free(query);    // 释放内存

}

int main()
{
    // 定义示例结构体数组
    field_desc test_km_fields[] = {
        {ft_uuid, 256, "id", NULL},
        {ft_enum, 64, "key_type", NULL},
        {ft_uint8t_pointer, 128, "owner1", NULL},
        {ft_uint8t_pointer, 128, "owner2", NULL},
        {ft_uint32t, 256, "key_len", NULL},
        {ft_enum, 64, "key_state", NULL},
        {ft_timet, 128, "creatime", NULL},
        {ft_timet, 128, "updatecycle", NULL},
        {ft_uint32t, 64, "kek_len", NULL},
        {ft_uint8t_pointer, 128, "kek_cipher", NULL},
        {ft_uint8t_pointer, 128, "iv", NULL},
        {ft_uint16t, 64, "iv_len", NULL},
        {ft_uint16t, 64, "chck_algo", NULL},
        {ft_uint16t, 64, "check_len", NULL},
        {ft_uint8t_pointer, 128, "chck_value", NULL},
        {ft_end, 0, NULL, NULL},
    };

    // 调用函数创建 SQL 数据表语句并保存到 query 中
    create_table_query(test_km_fields);

    return 0;
}
