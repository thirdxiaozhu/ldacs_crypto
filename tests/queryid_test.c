#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>  // for malloc, realloc
#include <sqlite3.h> // SQLite library

#define MAX_STRING_LEN 256
#include "key_manage.h"
#include "kmdb.h"

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
    enum KEY_TYPE key_type = ROOT_KEY; // Assume KEY_TYPE is defined somewhere
    enum STATE state = PRE_ACTIVATION;
    QueryResult_for_queryid result = query_id(dbname, sgw_tablename, sac_as, sac_sgw, key_type, state);

    // Print results
    printf("Query found %u %s belongs to %s and %s which state is:%s\n", result.count, ktype_str(key_type), sac_as, sac_sgw, kstate_str(state));
    for (uint32_t i = 0; i < result.count; ++i)
    {
        printf("ID %u: %s\n", i + 1, result.ids[i]);
        free(result.ids[i]); // Free allocated memory for each ID
    }

    return 0;
}