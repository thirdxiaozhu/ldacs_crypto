/**
 * @brief import key with kek test
 * @auther wencheng
 * @date 2024-6-14
 */
#include "key_manage.h"

int main()
{

    uint32_t kek_len = 16;
    CCARD_HANDLE handle;
    uint8_t kek_cipher[16];
    uint32_t cipher_len;
    CCARD_HANDLE handle2;
    do
    {
        if (km_generate_key_with_kek(1, kek_len, &handle, kek_cipher, &cipher_len) != LD_KM_OK)
        {
            printf("Error: Failed to generate kek\n");
            break;
        }
        printbuff("kek", kek_cipher, kek_len);
        if (km_import_key_with_kek(kek_cipher, kek_len, 1, &handle2) != LD_KM_OK)
        {
            printf("[query_callback_for_kekhandle] import key failed\n");
            break;
        }
    } while (0);
}
