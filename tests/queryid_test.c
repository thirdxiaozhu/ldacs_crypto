#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>  // for malloc, realloc
#include <sqlite3.h> // SQLite library

#define MAX_STRING_LEN 256
#include "key_manage.h"
#include "database.h"

// Adjusted QueryResult structure
typedef struct
{
    uint8_t *ids[MAX_STRING_LEN];
    uint32_t count;
} QueryResult;

// Function implementation
QueryResult query_ids(uint8_t *db_name, uint8_t *table_name, uint8_t *owner1, uint8_t *owner2, enum KEY_TYPE key_type)
{
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    QueryResult results = {.count = 0}; // Initialize results with count as 0

    // Open the database
    rc = sqlite3_open((const char *)db_name, &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return results;
    }

    // Prepare SQL statement
    char sql_stmt[512];
    snprintf(sql_stmt, sizeof(sql_stmt),
             "SELECT id FROM %s WHERE owner1=? AND owner2=? AND key_type=?",
             table_name);

    // Prepare the query
    rc = sqlite3_prepare_v2(db, sql_stmt, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return results;
    }

    // Bind parameters
    rc = sqlite3_bind_text(stmt, 1, (const char *)owner1, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to bind parameter 1: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return results;
    }

    rc = sqlite3_bind_text(stmt, 2, (const char *)owner2, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to bind parameter 2: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return results;
    }

    rc = sqlite3_bind_text(stmt, 3, ktype_str(key_type), -1, SQLITE_STATIC);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to bind parameter 3: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return results;
    }

    // Execute the query
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        if (results.count < MAX_STRING_LEN)
        {
            // Allocate memory for each id
            results.ids[results.count] = malloc(MAX_STRING_LEN * sizeof(uint8_t));
            if (results.ids[results.count] == NULL)
            {
                fprintf(stderr, "Failed to allocate memory\n");
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                return results;
            }
            // Copy the id into the array
            strncpy((char *)results.ids[results.count], (const char *)sqlite3_column_text(stmt, 0), MAX_STRING_LEN);
            results.count++;
        }
        else
        {
            fprintf(stderr, "Exceeded maximum number of results\n");
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return results;
        }
    }

    // Check for errors or no results found
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "Error in fetching data: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return results;
    }

    // Finalize statement and close database
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return results;
}

int main()
{
    // Example usage of query_id function

    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_s_tablename = "gs_s_keystore";
    uint8_t *gs_t_tablename = "gs_t_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";

    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs_s = "GS1";
    uint8_t *sac_gs_t = "GSt";
    uint8_t *sac_as = "Berry";
    enum KEY_TYPE key_type = MASTER_KEY_AS_SGW; // Assume KEY_TYPE is defined somewhere

    QueryResult result = query_ids(dbname, sgw_tablename, sac_as, sac_gs_t, key_type);

    // Print results
    printf("Query found %u IDs:\n", result.count);
    for (uint32_t i = 0; i < result.count; ++i)
    {
        printf("ID %u: %s\n", i + 1, result.ids[i]);
        free(result.ids[i]); // Free allocated memory for each ID
    }

    return 0;
}