
#ifndef _SDF_EXFUNC_H_
#define _SDF_EXFUNC_H_
#ifdef __cplusplus
extern "C"{
#endif
int
SDFE_Encrypt(
        void*               hSessionHandle  ,
        unsigned char*      pucKey          ,
        unsigned int        uiKeyLen        ,
        unsigned int        uiAlgID         ,
        unsigned char*      pucIV           ,
        unsigned char*      pucData         ,
        unsigned int        uiDataLength    ,
        unsigned char*      pucEncData      ,
        unsigned int*       puiEncDataLength);

int
SDFE_Decrypt(
        void*               hSessionHandle  ,
        unsigned char*      pucKey          ,
        unsigned int        uiKeyLen        ,
        unsigned int        uiAlgID         ,
        unsigned char*      pucIV           ,
        unsigned char*      pucEncData      ,
        unsigned int        uiEncDataLength ,
        unsigned char*      pucData         ,
        unsigned int*       puiDataLength   );

int
SDFE_CalculateMAC(
        void*               hSessionHandle  ,
        unsigned char*      pucKey          ,
        unsigned int        uiKeyLen        ,
        unsigned int        uiAlgID         ,
        unsigned char*      pucIV           ,
        unsigned char*      pucData         ,
        unsigned int        uiDataLength    ,
        unsigned char*      pucMAC          ,
        unsigned int*       puiMACLength    );

int
SDFE_ExportSessionKeyCipher(
        void*               hSessionHandle  ,
        void*               hKeyHandle      ,
        unsigned char*      pucKeyCipher    ,
        unsigned int*       puiKeyLength    );

int
SDFE_ImportSessionKeyCipher(
        void*               hSessionHandle  ,
        unsigned char*      pucKeyCipher    ,
        unsigned int        uiKeyLength     ,
        void**              phKeyHandle     );

int
SDFE_InternalEncrypt_ECC(
        void*               hSessionHandle  ,
        unsigned int        uiAlgID         ,
        unsigned int        uiKeyIndex      ,
        unsigned char*      pucData         ,
        unsigned int        uiDataLength    ,
        ECCCipher*          pucEncData      );

int
SDFE_InternalDecrypt_ECC(
        void*               hSessionHandle  ,
        unsigned int        uiAlgID         ,
        unsigned int        uiKeyIndex      ,
        ECCCipher*          pucEncData      ,
        unsigned char*      pucData         ,
        unsigned int*       puiDataLength   );

// ##############################################
// 扩展函数，打印密钥信息
int SDFE_DumpECCrefPublicKey(   ECCrefPublicKey     *pucPublicKey   );
int SDFE_DumpECCrefPrivateKey(  ECCrefPrivateKey    *pucPrivateKey  );
int SDFE_DumpECCSignature(      ECCSignature        *pucSignature   );
int SDFE_DumpECCCipher(         ECCCipher           *pucEncData     );
int SDFE_DumpRSArefPublicKey(   RSArefPublicKey     *pucPublicKey   );
int SDFE_DumpRSArefPrivateKey(  RSArefPrivateKey    *pucPrivateKey  );
#ifdef __cplusplus
    }
#endif
#endif//_SDF_EXFUNC_H_

