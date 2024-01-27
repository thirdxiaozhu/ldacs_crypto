#ifdef __cplusplus
extern "C"
{
#endif

#ifndef MENIPU_KEYSTORE_H
#define MENIPU_KEYSTORE_H

#include <stdio.h>
#include <string.h>
#include <mysql/mysql.h>
#include "key_manage.h"

	// 连接服务器 pool use KMDB
	int sql_init(MYSQL *mysql, char *host, char *usr, char *password, char *dbname, int port);

	// 存储-存储保护密钥
	int save_secondary_kek(MYSQL *conn, unsigned char *table, unsigned char *key, int key_len, int kek_index);
	// 存储-根密钥
	int save_root_key(MYSQL *conn, const char *table, struct KeyInfo *key_info, int kek_index);

	/*
	**********
	*密钥使用*
	**********
	*/
	// 获取根密钥加密密钥句柄 默认使用1号二级密钥加密密钥加密根密钥
	int get_root_kek_handle(MYSQL *conn, unsigned char *table, HANDLE *secondary_kek_handle);
	
	// 输入密钥密文，输出密钥句柄
	int get_key_handle(unsigned char *encrypted_key, int key_len, HANDLE *handle);

/*
	// 密钥明文存入密钥池
	void insert_into_keystore(MYSQL *conn, const char *table, const void *data, size_t size, int kek_index);
	// void key_into_keystore(MYSQL *conn, const char *table, struct key_info *key_info, unsigned char key[16],int kek_index);

	// 删除指定密钥
	int delete_from_key_pool(MYSQL *mysql, int index);

	// 查询数据表 返回结果保存在response
	int show_table(MYSQL *mysql, char *response[], char *table_name);

	// 从数据库中检索出密钥
	void retrieve_encrypted_key(MYSQL *conn, const char *table);
	void insert_into_rand_pool(MYSQL *conn, char *table, void *data, size_t size);
*/
#ifdef __cplusplus
}
#endif

#endif
