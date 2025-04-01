//
// Created by 邹嘉旭 on 2025/4/1.
//

#ifndef CIPHER_UTIL_H
#define CIPHER_UTIL_H

#include "ldacscrypto.h"

typedef void (*calc_hmac_func)(uint8_t *udata, size_t data_len, void *key_med, uint8_t *mac_dst, size_t mac_limit);

typedef bool (*verify_hmac_func)(void *key_med, uint8_t *to_verify, uint8_t *udata, size_t data_len, size_t mac_limit);


#endif //CIPHER_UTIL_H
