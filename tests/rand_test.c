//
// Created by jiaxv on 5/30/24.
//
#include "key_manage.h"

int main()
{
    uint8_t rand[64] = {0};
    for (int i = 0; i < 10; i++)
    {
        km_generate_random(rand, 16);
        printbuff("rand", rand, 16);
    }
}