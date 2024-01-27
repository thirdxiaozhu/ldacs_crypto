
#ifndef _SDF_KEYTYPE_H_
#define _SDF_KEYTYPE_H_

#include "sdf-basetype.h"

// ##############################################
// GM/T 0018 5.4 RSA 密钥数据结构定义
#define RSAref_MAX_BITS     2048
#define RSAref_MAX_LEN      ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS    ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN     ((RSAref_MAX_PBITS + 7) / 8)

#undef S10PUBPARA
//#define S10PUBPARA

#ifndef S10PUBPARA
typedef struct RSArefPublicKey_st {
    unsigned int    bits                        ;
    unsigned char   m[RSAref_MAX_LEN]           ;
    unsigned char   e[RSAref_MAX_LEN]           ;
} RSArefPublicKey;
typedef struct RSArefPrivateKey_st {
    unsigned int    bits                        ;
    unsigned char   m[RSAref_MAX_LEN]           ;
    unsigned char   e[RSAref_MAX_LEN]           ;
    unsigned char   d[RSAref_MAX_LEN]           ;
    unsigned char   prime[2][RSAref_MAX_PLEN]   ;
    unsigned char   pexp[2][RSAref_MAX_PLEN]    ;
    unsigned char   coef[RSAref_MAX_PLEN]       ;
} RSArefPrivateKey;
#else //S10PUBPARA
typedef struct RSArefPublicKey_st {
    unsigned int    bits                        ;
    unsigned char   m[RSAref_MAX_LEN]			;
    unsigned char   e[RSAref_MAX_LEN]			;

    unsigned char   rrmodn[RSAref_MAX_LEN]   	;
    unsigned char   n0inv[RSAref_MAX_LEN]    	;
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st {
    unsigned int    bits                        ;
    unsigned char   m[RSAref_MAX_LEN]			;
    unsigned char   e[RSAref_MAX_LEN]			;
    unsigned char   d[RSAref_MAX_LEN]			;
    unsigned char   prime[2][RSAref_MAX_LEN/2]  ;
    unsigned char   pexp[2][RSAref_MAX_LEN/2]	;
    unsigned char   coef[RSAref_MAX_LEN/2]	    ;

    unsigned char   rrmodn[RSAref_MAX_LEN]   	;
    unsigned char   ssmodp[RSAref_MAX_LEN]   	;
    unsigned char   ssmodq[RSAref_MAX_LEN]   	;
    unsigned char   pinvq[RSAref_MAX_LEN]    	;
    unsigned char   n0inv[RSAref_MAX_LEN]    	;
} RSArefPrivateKey;
#endif//S10PUBPARA

// ##############################################
// GM/T 0018 5.5 ECC密钥数据结构定义
#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN ((ECCref_MAX_BITS + 7) / 8)
typedef struct ECCrefPublicKey_st {
    unsigned int    bits                    ;
    unsigned char   x[ECCref_MAX_LEN]       ;
    unsigned char   y[ECCref_MAX_LEN]       ;
} ECCrefPublicKey;
typedef struct ECCrefPrivateKey_st {
    unsigned int    bits                    ;
    unsigned char   K[ECCref_MAX_LEN]       ;
} ECCrefPrivateKey;

// ##############################################
// GM/T 0018 5.6 ECC加密数据结构定义
typedef struct ECCCipher_st {
    unsigned char   x[ECCref_MAX_LEN]       ;
    unsigned char   y[ECCref_MAX_LEN]       ;
    unsigned char   M[32]                   ;
    unsigned int    L                       ;
    unsigned char   C[1]                    ;
} ECCCipher;

// ##############################################
// GM/T 0018 5.7 ECC签名数据结构定义
typedef struct ECCSignature_st {
    unsigned char   r[ECCref_MAX_LEN]       ;
    unsigned char   s[ECCref_MAX_LEN]       ;
} ECCSignature;

#if 0
// ##############################################
// GM/T 0018 5.8 ECC加密密钥对保护结构
typedef struct SDF_ENVELOPEDKEYBLOB {
    unsigned int    uiAsymmAlgID            ;
    unsigned int    uiSymmAlgID             ;
    ECCCipher       ECCCipherBlob           ;
    ECCrefPublicKey PubKey                  ;
    unsigned char   cbEncryptedPriKey[64]   ;
} ENVELOPEDKEYBLOB, * PENVELOPEDKEYBLOB;
#endif

// ##############################################
// Ext Type
typedef enum KeyType_en {
    SGD_MAIN_KEY            = 0x00000101,
    SGD_DEVICE_KEYS         = 0x00000102,
    SGD_USER_KEYS           = 0x00000103,
    SGD_KEK                 = 0x00000104,
    SGD_SESSION_KEY         = 0x00000105,
    SGD_PRIKEY_PASSWD       = 0x00000106,
    SGD_COMPARTITION_KEY    = 0x00000107,

    SGD_KEY_UNKNOWN         = 0x00000200,
    SGD_KEY_ECC             = 0x00000201,
    SGD_KEY_RSA             = 0x00000202,
    SGD_KEY_SYM             = 0x00000203,

    SGD_USER_SIG_KEYS       = 0x00000108,
    SGD_USER_ENC_KEYS       = 0x00000109,
}KeyType;

enum KEY_ALG {
    RSAKEY      = 1,
    SM2KEY      = 2,
    SYMKEY      = 3,
    RSASIGKEY   = 4,
    RSAENCKEY   = 5,
    SM2SIGKEY   = 6,
    SM2ENCKEY   = 7,
    NULLKEY     = 8,
};

typedef struct Bytes_st {
    unsigned int    L           ;  //数据长度
    unsigned char*  C           ;  //数据
} SGD_Bytes;

#if 0
typedef struct KeyInfo_st {
    unsigned int    key_type    ;
    unsigned int    key_length  ;
    unsigned int    key_index   ;
} KEYInfo;
#endif

#endif//_SDF_KEYTYPE_H_

