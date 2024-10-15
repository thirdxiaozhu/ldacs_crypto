/**
 * 20240904by wencheng
 * kas-gs派生 抑或过程测试
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"

int main()
{
    const char *sac_gs = "GS1";
    uint32_t rand_len = 32;
    uint8_t rand[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // Allocate memory for the hash result
    uint8_t hash_output[rand_len];
    memset(hash_output, 0, sizeof(hash_output));

    // Calculate the hash of sac_gs using km_hash
    l_km_err hash_result = km_hash(ALGO_HASH, (uint8_t *)sac_gs, strlen(sac_gs), hash_output);
    if (hash_result != LD_KM_OK)
    {
        fprintf(stderr, "Hash function failed with error code %d\n", hash_result);
        return 1;
    }
    printbuff("hash output: ", hash_output, 32);
    
    // Allocate memory for the XOR result
    uint8_t *xor_result = malloc(rand_len);
    if (xor_result == NULL)
    {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    // Perform the XOR operation
    for (int i = 0; i < rand_len; i++)
    {
        xor_result[i] = hash_output[i] ^ rand[i];
    }

    // Print the result
    printbuff("xor_result", xor_result, rand_len);

    // Free the allocated memory
    free(xor_result);

    return 0;
}