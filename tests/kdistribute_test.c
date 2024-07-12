/**
 * 20240514 by wencheng
 * 根密钥预置完成后，单机版密钥建立过程样例：AS GS SGW的密钥生成和分发
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "db.h"
#include <uuid/uuid.h>

int main()
{

    int ret;

    /**************************************************
     *                    SGW端                        *
     **************************************************/
    // 生成共享信息
    uint32_t sharedinfo_len = 32;
    uint8_t sharedinfo[sharedinfo_len];
    ret = km_generate_random(sharedinfo, sharedinfo_len); // 用随机数填充
    if (ret != LD_KM_OK)
    {
        printf("[**sgw generate sharedinfo error**]\n");
        return 0;
    }

    uint8_t SAC_GS[16] = {0x12, 0x30}; // SAC为前12bit  后面视为填充

    // 主密钥KAS-SGW=KDF(rootkey,sharedinfo)派生
    CCARD_HANDLE handle_rootkey; // 根密钥句柄
    CCARD_HANDLE handle_kassgw;  // AS和SGW之间的主密钥
    struct KeyPkg *pkg_kassgw;   // 用于保存主密钥信息
    uint16_t len_kassgw = 16;    // 主密钥长度

    uint8_t *filepath = "/home/wencheng/crypto/key_management/keystore/rootkey.txt";
    ret = km_get_rootkey_handle(&handle_rootkey, filepath); // 获取根密钥
    if (ret != LD_KM_OK)
    {
        printf("[**sgw get_rootkey_handle error**]\n");
        return 0;
    }

    pkg_kassgw = km_derive_key(handle_rootkey, MASTER_KEY_AS_SGW, len_kassgw, "SGW", "Berry", sharedinfo, sharedinfo_len, &handle_kassgw);
    if (pkg_kassgw == NULL)
    {
        printf("[**sgw derive_key kas-sgw error**]\n");
        return 0;
    }
    else
    {
        printf("[**sgw derive_key KAS-SGW OK**]\n");
    }
    // 省略：构造AUC_RESP消息 用KAS-SGW计算消息校验值
    /**************************************************
     *                    AS端                         *
     **************************************************/
    printf("[**AS derive_key KAS-SGW OK **]\n");
    // 省略：和SGW同理 获取根密钥 派生主密钥KAS-SGW
    // 省略：密钥校验

    // 生成随机数N3
    uint16_t len_rand_3 = 16;
    uint8_t rand_3[len_rand_3];
    ret = km_generate_random(rand_3, len_rand_3);
    if (ret != LD_KM_OK)
    {
        printf("[**AS generate_random N3 error**]\n");
        return 0;
    }

    // 省略：构造密钥确认消息 计算校验值

    // 主密钥KAS-GS派生
    uint8_t NH[16]; // 中间变量 下一跳密钥
    uint16_t len_kasgs = 16;
    CCARD_HANDLE handle_NH;
    CCARD_HANDLE handle_kasgs;
    struct KeyPkg *pkg_NH;
    struct KeyPkg *pkg_kasgs;
    pkg_NH = km_derive_key(handle_kassgw, NH_KEY, len_kasgs, "Berry", "GS1", rand_3,
                           len_rand_3, &handle_NH); // NH = KDF(KAS-SGW,rand_3)
    if (ret != LD_KM_OK)
    {
        printf("[**AS derive_key NH error**]\n");
        return 0;
    }

    uint8_t xor_result[len_rand_3];
    uint16_t len_xor_res = len_rand_3;
    for (int i = 0; i < len_rand_3; i++)
    {
        xor_result[i] = SAC_GS[i] ^ rand_3[i]; // SAC_GS^N3
    }
    pkg_kasgs = km_derive_key(handle_NH, MASTER_KEY_AS_GS, len_kasgs, "Berry", "GS1", xor_result,
                              len_xor_res, &handle_kasgs); // KAS-GS=KDF(NH,SAC_GS^N3
    if (ret != LD_KM_OK)
    {
        printf("[**AS derive_key KAS-GS error**]\n");
        return 0;
    }
    else
    {
        printf("[**AS derive_key KAS-GS OK  **]\n");
    }

    // 会话密钥派生 以用户数据加密密钥为例
    uint16_t len_session_key = 16;
    CCARD_HANDLE handle_session_key;
    struct KeyPkg *pkg_session_key;
    pkg_session_key = km_derive_key(handle_kasgs, SESSION_KEY_USR_ENC, len_session_key, "Berry", "GS1",
                     rand_3, len_rand_3, &handle_session_key); // KU-ENC=KDF(KAS-GS,rand3)
    if (ret != LD_KM_OK)
    {
        printf("[**AS derive_key KU-ENC error**]\n");
        return 0;
    }
    else
    {
        printf("[**AS derive_key KU-ENC OK  **]\n");
    }
    /**************************************************
     *                    SGW端                        *
     **************************************************/

    // 密钥校验
    // 密钥KAS-GS派生 和AS同理：NH = KDF(KAS-SGW,rand_3)
    printf("[**SGW derive_key KAS-GS OK  **]\n");
    // 给GS分发KAS-GS rand_3
    printf("SGW sending kas-gs to GS.........\n");

    /**************************************************
     *                    GS端                        *
     **************************************************/
    // 会话密钥派生 和AS同理 KU-ENC=KDF(KAS-GS,rand3) KAS-GS=KDF(NH,SAC_GS^N3) , AS和GS之间主-会话密钥建立完成
    printf("[**GS derive_key KU-ENC OK  **]\n");
    return 0;
}