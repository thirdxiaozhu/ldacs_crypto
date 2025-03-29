#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum km_field_type
{
    /*
     * key management relevant
     */
    ft_uuid,
    ft_uint8t_pointer,
    ft_enum,
    ft_uint32t,
    ft_timet,
    ft_uint16t,
    ft_end,
};

// 定义结构体描述字段
typedef struct km_field_desc
{ // struct field descriptor
    enum km_field_type km_field_type;
    const int size; /* size, in bits, of field */
    const char *name;
    const void *desc; /*未使用： enum_names for enum or char *[] for bits */
} km_field_desc;

typedef struct struct_desc_s
{
    const char *name;
    struct km_field_desc *fields;
} struct_desc;

static km_field_desc test_km_fields[] = {
    // 密钥结构体字段描述
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
    {ft_enum, 64, "chck_algo", NULL},
    {ft_uint16t, 64, "check_len", NULL},
    {ft_uint8t_pointer, 128, "chck_value", NULL},
    {ft_end, 0, NULL, NULL},
};

struct_desc static test_km_desc = {"km_pkg", test_km_fields};

// struct FieldDescription
// {
//     char fieldName[50];
//     char fieldType[20];
//     char fieldValue[100];
// };

// 定义函数：根据字段描述生成 SQL 插入语句
char *constructInsertSQL(struct_desc *sd, const char *tableName)
{
    int maxSQLLength = 1024;

    const km_field_desc *current_field = sd->fields;
    // 分配内存存储 SQL 语句
    char *sql = (char *)malloc(maxSQLLength * sizeof(char));
    if (sql == NULL)
    {
        fprintf(stderr, "Memory allocation error\n");
        exit(1);
    }

    // 构建 INSERT INTO 语句
    sprintf(sql, "INSERT INTO %s (", tableName);

    // 添加字段名
    const km_field_desc *next_field;
    while (current_field->km_field_type != ft_end)
    {
        next_field = current_field;
        next_field++; // 指向下一个描述域
        strcat(sql, current_field->name);
        if (next_field->km_field_type != ft_end)
        {
            strcat(sql, ", ");
        }
        current_field++;
    }

    // 添加字段值
    current_field = sd->fields;
    strcat(sql, ") VALUES (");
    while (current_field->km_field_type != ft_end)
    {
        if (current_field->km_field_type == ft_uint16t)
        {
            strcat(sql, current_field->name); // TODO: 根据类型决定拷贝什么和类型判断
        }
        else // 字符串 添加引号
        {
            strcat(sql, "'");
            strcat(sql, current_field->name); // TODO: check
            strcat(sql, "'");
        }

        next_field = current_field;
        next_field++; // 指向下一个描述域
        if (next_field->km_field_type != ft_end)
        {
            strcat(sql, ", ");
        }
        current_field++;
    }
    strcat(sql, ");");

    return sql;
}
    
int main()
{

    // 调用函数构建 SQL 语句
    char *insertSQL = constructInsertSQL(&test_km_desc, "test_key");

    // 打印 SQL 语句
    log_warn("Generated SQL statement: %s\n", insertSQL);

    // 释放内存
    free(insertSQL);

    return 0;
}
