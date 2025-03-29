#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "key_manage.h"

void store_keypkg_to_db(sqlite3 *db, km_keypkg_t *keypkg) {
    sqlite3_stmt *stmt;
    char *sql = "INSERT INTO KeyPkg (id, owner_1, owner_2, key_type, length, state, creation_time, update_cycle, kek_cipher, kek_cipher_len, key_cipher, iv_len, iv, chck_len, chck_alg, chck_value) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    // Prepare the SQL statement
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    // Bind parameters
    sqlite3_bind_blob(stmt, 1, &keypkg->meta_data->id, sizeof(uuid_t), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, keypkg->meta_data->owner_1, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, keypkg->meta_data->owner_2, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, keypkg->meta_data->key_type);
    sqlite3_bind_int(stmt, 5, keypkg->meta_data->length);
    sqlite3_bind_int(stmt, 6, keypkg->meta_data->state);
    sqlite3_bind_int64(stmt, 7, keypkg->meta_data->creation_time);
    sqlite3_bind_int64(stmt, 8, keypkg->meta_data->update_cycle);
    sqlite3_bind_blob(stmt, 9, keypkg->kek_cipher, keypkg->kek_cipher_len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 10, keypkg->kek_cipher_len);
    sqlite3_bind_blob(stmt, 11, keypkg->key_cipher, MAX_KEY_CIPHER_LEN, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 12, keypkg->iv_len);
    sqlite3_bind_blob(stmt, 13, keypkg->iv, MAX_IV_LEN, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 14, keypkg->chck_len);
    sqlite3_bind_int(stmt, 15, keypkg->chck_alg);
    sqlite3_bind_blob(stmt, 16, keypkg->chck_value, MAX_CHCK_LEN, SQLITE_STATIC);

    // Execute the statement
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

    // Clean up
    sqlite3_finalize(stmt);
}

int main() {

    // Open connection to SQLite database
    sqlite3 *db;
    int rc = sqlite3_open("keystore.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    // 执行SQL语句以创建表
    uint8_t *create_table_sql = "CREATE TABLE IF NOT EXISTS KeyPkg ("
                                "id VARCHAR(64) PRIMARY KEY,"
                                "owner_1 TEXT,"
                                "owner_2 TEXT,"
                                "key_type INTEGER,"
                                "length INTEGER,"
                                "state INTEGER,"
                                "creation_time INTEGER,"
                                "update_cycle INTEGER,"
                                "kek_cipher BLOB,"
                                "kek_cipher_len INTEGER,"
                                "key_cipher BLOB,"
                                "iv_len INTEGER,"
                                "iv BLOB,"
                                "chck_len INTEGER,"
                                "chck_alg INTEGER,"
                                "chck_value BLOB"
                                ");";
    char *err_msg = 0;
    rc = sqlite3_exec(db, create_table_sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL错误: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    } else {
        log_warn("KeyPkg表创建成功\n");
    }

    // 变量初始化
    void *DeviceHandle, *pSessionHandle, *phKeyHandle;
    int ret;

    // 打开设备
    SDF_OpenDevice(&DeviceHandle);
    SDF_OpenSession(DeviceHandle, &pSessionHandle);

    // AS端获取根密钥
    void *rootkey_handle;
    uint8_t *filepath = "/home/wencheng/crypto/key_management/keystore/rootkey.bin";
    ret = km_get_rootkey_handle(&rootkey_handle, filepath);
    if (ret != LD_KM_OK) {
        log_warn("[**get rootkey handle error**]\n");
    } else {
        log_warn("[**get rootkey handle OK**]\n");
    }

    // 主密钥派生 指定所有者 shareinfo 密钥类型 派生主密钥
    uint32_t key_asswg_len = 16;
    uint8_t *sharedinfo = "shareinfo_hashshareinfo_hash";
    uint8_t *owner1 = "Berry";
    uint8_t *owner2 = "SGW";
    uint8_t shared_info_len = strlen(sharedinfo);
    void *masterkey_handle;
    enum KEY_TYPE key_type = MASTER_KEY_AS_SGW;
    struct KeyPkg *pkg;
    pkg = km_derive_key(rootkey_handle, key_type, key_asswg_len, owner1, owner2, sharedinfo, shared_info_len,
                        &masterkey_handle);
    if (ret == LD_KM_OK) {
        log_warn("[**Key as-sgw syccessfully derived**]==================\n");
        log_warn("key handle %p\n", masterkey_handle);
        // //print_key_pkg(&pkg); // 打印主密钥完整信息
        print_key_metadata(pkg->meta_data);
    } else {
        log_warn("Key derivation failed.\n");
    }
    store_keypkg_to_db(db, pkg); // Store KeyPkg to database

    // Close connection
    sqlite3_close(db);

    return 0;
}
