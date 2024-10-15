/**
 * @author wencheng
 * @version 2024/09/20
 * @brief km_HMAC computation and database test
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "key_manage.h"
#include "kmdb.h"

int main()
{
    uint32_t nonce_len = 16;
    uint8_t nonce[nonce_len];
    uint32_t rand_len = 16;
    uint8_t rand[rand_len];
    uint8_t *sac_gs_t = "GSt456";

    if (km_generate_random(nonce, 16) != LD_KM_OK)
    {
        printf("Error generating random. \n");
        return LD_ERR_KM_GENERATE_RANDOM;
    }

    if (km_hmac(nonce, nonce_len, sac_gs_t, strlen(sac_gs_t), rand, &rand_len) !=
        LD_KM_OK) // rand = hmac(sacgs-t,nonce)
    {
        printf("km_hmac failed\n");
        return LD_ERR_KM_HMAC;
    }
}