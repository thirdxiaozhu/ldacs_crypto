//
// Created by 邹嘉旭 on 2025/4/1.
//

#include "cipher_util.h"

#ifdef UNUSE_CRYCARD
static void ld_sm3_hmac(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t mac[SM3_HMAC_SIZE]) {
    SM3_HMAC_CTX ctx;
    sm3_hmac_init(&ctx, key, key_len);
    sm3_hmac_update(&ctx, data, data_len);
    sm3_hmac_finish(&ctx, mac);
}
#endif


void calc_hmac_uint(uint8_t *udata, size_t data_len, void *key_med, uint8_t *mac_dst, size_t mac_limit) {
    uint8_t mac_buf[32] = {0};
#ifdef USE_CRYCARD
    uint32_t hmac_len = 0;
    km_hmac_with_keyhandle(key_med, udata, data_len, mac_buf, &hmac_len);
#elif UNUSE_CRYCARD
    buffer_t *key = key_med;
    ld_sm3_hmac(key->ptr, key->len, udata, data_len, mac_buf);
#endif

    memcpy(mac_dst, mac_buf, mac_limit);
}

bool verify_hmac_uint(void *key_med, uint8_t *to_verify, uint8_t *udata, size_t data_len, size_t mac_limit) {
    uint8_t mac_buf[32] = {0};
    calc_hmac_uint(udata, data_len, key_med, mac_buf, mac_limit);

    return !memcmp(to_verify, mac_buf, mac_limit);
}
