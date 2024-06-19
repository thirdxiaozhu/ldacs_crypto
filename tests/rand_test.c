//
// Created by jiaxv on 5/30/24.
//
#include "km/key_manage.h"

int main() {
    uint8_t rand[64] = {0};
    km_generate_random(rand, 64);

    printbuff("aaaaaaa", rand, 64);
}