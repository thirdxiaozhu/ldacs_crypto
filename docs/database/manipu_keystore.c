#include <stdio.h>
#include <mysql/mysql.h>
#include <stdlib.h>
#include <string.h>
#include "key_manage.h"
#include <piico_pc/api.h>
#include <piico_pc/piico_define.h>
#include <piico_pc/piico_error.h>

// gcc -I /usr/include/mysql test_conn.c -L/usr/lib/mysql -lmysqlclient -o test_conn.exe
// 密钥池的增删查 封装成函数

/*
void insert_into_keystore(MYSQL *conn, char *table, void *data, size_t size, int kek_index)
{
    char query[512];
    if (strcmp(table, "key_pool") == 0)
    {
        printf("store into root_key_pool\n");
        snprintf(query, sizeof(query), "INSERT INTO %s (encrypted_key,kek_index) VALUES(?,%d)", table, kek_index);
    }
    else if (strcmp(table, "rand_pool") == 0)
    {
        printf("store one row into rand_pool\n");
        sprintf(query, "INSERT INTO %s (rand) VALUES (?)", table);
    }

    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (!stmt)
    {
        fprintf(stderr, "Failed to initialize statement: %s\n", mysql_error(conn));
        return;
    }

    if (mysql_stmt_prepare(stmt, query, strlen(query)) != 0)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return;
    }

    MYSQL_BIND bind;
    memset(&bind, 0, sizeof(bind));
    bind.buffer_type = MYSQL_TYPE_BLOB;
    bind.buffer = (void *)data;
    bind.buffer_length = size;

    if (mysql_stmt_bind_param(stmt, &bind) != 0)
    {
        fprintf(stderr, "Failed to bind parameter: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return;
    }

    if (mysql_stmt_execute(stmt) != 0)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return;
    }

    mysql_stmt_close(stmt);
}
*/

// 连接服务器 指定使用的数据库 use KMDB
int sql_init(MYSQL *mysql, char *host, char *usr, char *password, char *dbname, int port)
{
    // 连接服务器
    mysql_init(mysql);
    // mysql -h 192.168.136.136 -u admin -p
    if (!mysql_real_connect(mysql, host, usr, password, dbname, port, NULL, 0))
    {
        printf("连接失败");
        fprintf(stderr, "Failed to connect to database: Error: %s\n",
                mysql_error(mysql));
        return -1;
    }
    mysql_query(mysql, "set names utf8"); // 设置编码

    // 转换数据库
    char query_usedb[255];
    sprintf(query_usedb, "%s%s%s", "use ", dbname, ";");
    if (mysql_query(mysql, query_usedb))
    {
        fprintf(stderr, "Failed to use %s: Error: %s\n", dbname,
                mysql_error(mysql));
        return -1;
    }

    // 新建存储保护密钥表
    // 新建密钥分配表
    // 新建密钥表-被管设备端
}

// 存储-二级密钥加密密钥
int save_secondary_kek(MYSQL *conn, unsigned char *table, unsigned char *key, int key_len, int kek_index)
{
    // Create a query to insert binary data into the database
    char query[512];
    int id = 0;
    unsigned char *hex_key;
    hex_key = (unsigned char *)malloc(2 * key_len + 1); // Each byte is represented by two hex characters, plus one for null terminator
    int hex_key_len;
    encode_to_hex(key, key_len, hex_key, &hex_key_len);
    // printf("hex_key %s \n", hex_key);
    snprintf(query, sizeof(query), "INSERT INTO %s (id, encrypted_key, kek_index) VALUES (%d, '%s', %d);", table, id, hex_key, kek_index);
    printf("query: %s\n", query);

    // Execute the SQL query
    if (mysql_query(conn, query))
    {
        fprintf(stderr, "Failed to execute query: %s\n", mysql_error(conn));
        return -1;
    }

    // Clean up
    mysql_close(conn);
    free(hex_key);

    return 0;
}

// 存储根密钥
int save_root_key(MYSQL *conn, const char *table, struct KeyInfo *key_info, int kek_index)
{
    char query[512];        // 要执行的SQL查询语句
    char encrypted_key[33]; // 存储16进制的密文，需要2倍长度加1

    char key_info_check_value[3]; // 存储SM3哈希值的最高2字节，需要2倍长度加1

    // 将二进制密钥转换为16进制字符串

    // 计算SM3哈希值
    unsigned char sm3_output[32];
    char sm3_input[512]; // 存储所有密钥信息和密钥的拼接字符串
    snprintf(sm3_input, 512, "%u%u%u%u%u%s", 0, key_info->type, key_info->length, encrypted_key);

    if (sm3_hash((unsigned char *)sm3_input, strlen(sm3_input), sm3_output) != 0)
    {
        // 处理SM3哈希错误
        // 可以根据需求添加错误处理逻辑
    }

    // 将SM3哈希值的最高2字节存入key_info_check_value
    snprintf(key_info_check_value, 3, "%02X%02X", sm3_output[0], sm3_output[1]);

    // 构建SQL查询语句，将密钥信息存入数据库
    snprintf(query, 512, "INSERT INTO %s (key_type, length, encrypted_key, key_info_check_value) VALUES (%u, %u, %u, %u, '%s', '%s')",
             table, key_info->type, key_info->length, encrypted_key, key_info_check_value);

    if (mysql_query(conn, query) != 0)
    {
        // 处理SQL查询错误
        // 可以根据需求添加错误处理逻辑
    }
}

/*************
 * 密钥使用 *
 *************/

// 获取根密钥加密密钥句柄 默认使用1号二级密钥加密密钥加密根密钥
int get_root_kek_handle(MYSQL *conn, unsigned char *table, HANDLE *secondary_kek_handle)
{
    // 获取二级密钥加密密钥密文 和一级密钥加密密钥索引
    MYSQL_RES *res;
    MYSQL_ROW row;
    int id = 1; // Replace with your desired id
    char query[100];
    sprintf(query, "SELECT kek_index, encrypted_key FROM %s WHERE id = %d", table, id);
    if (mysql_query(conn, query))
    {
        fprintf(stderr, "%s\n", mysql_error(conn));
        mysql_close(conn);
        return 1;
    }
    res = mysql_use_result(conn);

    int first_class_kek_index;
    char encrypted_key[16];
    int encrypted_key_len;
    if ((row = mysql_fetch_row(res)) != NULL)
    {
        first_class_kek_index = atoi(row[0]);
        char *hex_encrypted_key = row[1];
        decode_from_hex(hex_encrypted_key, 32, encrypted_key, &encrypted_key_len);

        // printf("first_class_kek_index: %d\n", first_class_kek_index);
        // printf("hex_encrypted_key: %s\n", hex_encrypted_key);
        // printbuff("encrypted_key", encrypted_key, encrypted_key_len);
    }
    else
    {
        printf("No data found for id: %d\n", id);
        return -1;
    }
    mysql_free_result(res);

    HANDLE DeviceHandle, pSessionHandle, phKeyHandle;
    int ret;
    // 打开设备
    ret = SDF_OpenDevice(&DeviceHandle);
    if (ret != SR_SUCCESSFULLY)
    {
        printf("SDF_OpenDevice error!return is %08x\n", ret);
        return -1;
    }

    // 打开会话
    ret = SDF_OpenSession(DeviceHandle, &pSessionHandle);
    if (ret != SR_SUCCESSFULLY)
    {
        printf("SDF_OpenSession error!return is %08x\n", ret);
        ret = SDF_CloseSession(pSessionHandle);
        return -1;
    }
    SDF_ImportKeyWithKEK(pSessionHandle, SGD_SM4_ECB, first_class_kek_index, encrypted_key, encrypted_key_len, &phKeyHandle);
    memcpy(secondary_kek_handle, phKeyHandle, sizeof(phKeyHandle));
    unsigned char iv[16] = {0x40, 0xbb, 0x12, 0xdd, 0x6a, 0x82, 0x73, 0x86,
                           0x7f, 0x35, 0x29, 0xd3, 0x54, 0xb4, 0xa0, 0x26};
    unsigned char data[16] = {0x40, 0xbb, 0x12, 0xdd, 0x6a, 0x82, 0x73, 0x86,
                           0x7f, 0x35, 0x29, 0xd3, 0x54, 0xb4, 0xa0, 0x26};
    unsigned char encrypt_data[16];
    int len;
    SDF_Encrypt(pSessionHandle,phKeyHandle,SGD_SM4_CFB,iv,data,16,encrypt_data,&len);
    printbuff("phkeyhandle加密得到",encrypt_data,16);
    printf("phKeyHandle %p\n secondary_kek_handle%p\n", phKeyHandle,secondary_kek_handle);
}

// 输入密钥密文，输出密钥句柄
int get_key_handle(unsigned char *encrypted_key, int key_len, HANDLE *handle);
/*
// 删除指定密钥
int delete_from_key_pool(MYSQL *mysql, int index)
{
    char *str_delete = " DELETE FROM key_pool WHERE key_index = ";
    char query_delete[255];
    sprintf(query_delete, "%s%d%s", str_delete, index, ";");
    if (mysql_query(mysql, query_delete)) // 查询
    {
        fprintf(stderr, "Failed to delete: Error: %s\n",
                mysql_error(mysql));
        return -1;
    }
    return 0;
}

// 展示整个表 print输出 存入response
int show_table(MYSQL *mysql, char *response[], char *table)
{
    char query[512];
    snprintf(query, sizeof(query), "SELECT * FROM %s", table);
    char *buf = (char *)malloc(20);
    memset(buf, 0, 20);
    if (mysql_query(mysql, query)) // 查询
    {
        fprintf(stderr, "Failed to select: Error: %s\n",
                mysql_error(mysql));
        return -1;
    }
    else
    {
        MYSQL_RES *res = NULL; // 从堆区申请空间保存查询内容
        res = mysql_store_result(mysql);
        if (res != NULL)
        {
            MYSQL_ROW row;
            unsigned int num_fields; // 一行由多个字段组成
            unsigned int j = 0;
            num_fields = mysql_num_fields(res);
            while ((row = mysql_fetch_row(res))) // 依次输出每行
            {
                for (int i = 0; i < num_fields; i++)
                {
                    printf("%s ", row[i]); // 依次输出每行的每个字段（列）
                    strcpy(buf, row[i]);
                    response[j++] = row[i];
                    // printf("response[%d]=%s",j,response[i]);
                }
                printf("\n");
            }
            mysql_free_result(res); // 释放堆区空间
        }
        else
        {
            // 失败
            printf("show failed\n");
            return -1;
        }
        return 0;
    }
}


// 将密钥存入密钥池
void key_into_keystore(MYSQL *conn, const char *table, struct key_info *key_info, unsigned char key[16], int kek_index, void *data, size_t size)
{
    char query[512];
    if (strcmp(table, "key_pool") == 0)
    {
        printf("store into root_key_pool\n");
        snprintf(query, sizeof(query), "INSERT INTO %s (encrypted_key,kek_index) VALUES(?,%d)", table, kek_index);
    }

    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (!stmt)
    {
        fprintf(stderr, "Failed to initialize statement: %s\n", mysql_error(conn));
        return;
    }

    if (mysql_stmt_prepare(stmt, query, strlen(query)) != 0)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return;
    }

    MYSQL_BIND bind;
    memset(&bind, 0, sizeof(bind));
    bind.buffer_type = MYSQL_TYPE_BLOB;
    bind.buffer = (void *)data;
    bind.buffer_length = size;

    if (mysql_stmt_bind_param(stmt, &bind) != 0)
    {
        fprintf(stderr, "Failed to bind parameter: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return;
    }

    if (mysql_stmt_execute(stmt) != 0)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return;
    }

    mysql_stmt_close(stmt);
}

// 从数据库中检索出密钥
void retrieve_encrypted_key(MYSQL *conn, char *table)
{
    MYSQL_RES *res;
    MYSQL_ROW row;

    char query[512];
    snprintf(query, sizeof(query), "SELECT encrypted_key FROM %s", table);

    // Execute the SQL query
    if (mysql_query(conn, query))
    {
        fprintf(stderr, "Failed to execute query: %s\n", mysql_error(conn));
        return;
    }

    // Get the result set
    res = mysql_use_result(conn);

    // Retrieve and print the data
    while ((row = mysql_fetch_row(res)))
    {
        MYSQL_FIELD *field;
        unsigned long *lengths;

        lengths = mysql_fetch_lengths(res);
        field = mysql_fetch_field(res);
        printf(" Binary Data Length: %lu\n", lengths[0]);
        printbuff("row[0]", row[0], strlen(row[0]));
    }

    // Free the result set
    mysql_free_result(res);
}

*/