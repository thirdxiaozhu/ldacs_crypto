
#ifndef _SDFE_FUNC_H_
#define _SDFE_FUNC_H_

#include "../sdf/sdf-basetype.h"
#include "../sdf/sdf-keytype.h"

#include "sdfe-type.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C"{
#endif
// ##############################################
// 扩展类设备管理相关函数
int
SDFE_OpenDevice(
        void**          phDeviceHandle  ,
        unsigned int    adapterid       );

int
SDFE_CloseDevice(
        void*           hDeviceHandle   );

int
SDFE_OpenSession(
        void*           hDeviceHandle   ,
        void**          phSessionHandle );

int
SDFE_CloseSession(
        void*           hSessionHandle  );

int
SDFE_InitDevice(
        void*               hSessionHandle  ,
        unsigned int        uiFlag          );

int
SDFE_SetSN(
        void            *hDeviceHandle  ,
        char            *pucSN          ,
        unsigned int    uiSNLen         );

int
SDFE_GetState(
        void*               hSessionHandle  ,
        DevStatus*          pDevStatus      );

int
SDFE_UpdateFirmware(
        void*               hSessionHandle  ,
        char*               filepath        );

int
SDFE_Backup(
        void*               hSessionHandle  ,
        unsigned char*      pucPIN          ,
        uint32_t            uiPINLen        ,
        unsigned char*      buf             ,
        uint32_t            bufsize         );

int
SDFE_Restore(
        void*               hSessionHandle  ,
        unsigned char*      pucPIN          ,
        uint32_t            uiPINLen        ,
        unsigned char*      buf             ,
        uint32_t            bufsize         );

int
SDFE_LoadKey(
        void*               hSessionHandle  );

int
SDFE_LoadUser(
        void*               hSessionHandle  );

// ##############################################
// 扩展类用户管理相关函数
int
SDFE_AddUser(
        void*               hSessionHandle  ,
        unsigned int        uiUserType      ,
        unsigned int        uiUserIndex     ,
        void*               pstECCPubKey    ,
        unsigned char*      pucUkeyPIN      ,
        unsigned int        uiUkeyPINLen    ,
        unsigned char*      pucPassword     ,
        unsigned int        uiPwdLength     );

int
SDFE_DelUser(
        void*               hSessionHandle  ,
        unsigned int        uiUserType      ,
        unsigned int        uiUserIndex     );

int
SDFE_EnumUser(
        void*               hSessionHandle  ,
        void*               pUserData       ,
        unsigned int*       puiUserCount    );

int
SDFE_LoginUser(
        void*               hSessionHandle  ,
        unsigned int        uiUserType      ,
        unsigned int        uiUserIndex     ,
        void*               pstECCPubKey    ,
        unsigned char*      pucPassword     ,
        unsigned int        uiPwdLength     );

int
SDFE_LogoutUser(
        void*               hSessionHandle  ,
        unsigned int        uiUserType      ,
        unsigned int        uiUserIndex     );

int
SDFE_SetUserPIN(
        void*               hSessionHandle  ,
        unsigned int        uiUserType      ,
        unsigned int        uiUserIndex     ,
        void*               pECCPubKey      ,
        unsigned char*      pucOldPassword  ,
        unsigned int        uiOldPwdLength  ,
        unsigned char*      pucNewPassword  ,
        unsigned int        uiNewPwdLength  );

// ##############################################
// 扩展类密钥管理相关函数
int
SDFE_GenerateKeyPair_ECC(
        void*               hSessionHandle  ,
        unsigned int        uiKeyBits       ,
        unsigned int        uiKeyIndex      ,
        unsigned int        uiKeyType       ,
		unsigned char		*pucPIN			,
        unsigned int        uiPINLEN      	);

int
SDFE_GenerateKeyPair_RSA(
        void*               hSessionHandle  ,
        unsigned int        uiKeyBits       ,
        unsigned int        uiKeyIndex      ,
        unsigned int        uiKeyType       ,
		unsigned char       *pucPIN			,
        unsigned int        uiPINLEN      	);

int
SDFE_GenerateKEK(
        void*               hSessionHandle  ,
        unsigned int        uiKeyBits       ,
        unsigned int        uiKeyIndex      );

int
SDFE_ImportKeyPair_ECC(
        void*               hSessionHandle  ,
        unsigned int        uiKeyIndex      ,
        unsigned int        uiKeyType       ,
		unsigned char		*pucPIN			,
        unsigned int        uiPINLen      	,
        ECCrefPublicKey*    pPubkey         ,
        ECCrefPrivateKey*   pPrikey         );

int
SDFE_ImportKeyPair_RSA(
        void*               hSessionHandle  ,
        unsigned int        uiKeyIndex      ,
        unsigned int        uiKeyType       ,
		unsigned char       *pucPIN			,
        unsigned int        uiPINLen      	,
        RSArefPublicKey*    pPubkey         ,
        RSArefPrivateKey*   pPrikey         );

int
SDFE_ImportKEK(
        void*               hSessionHandle  ,
        unsigned int        uiKeyIndex      ,
        void*               pucKey          ,
        unsigned int        uiKeyLen        );

int
SDFE_ExportKeyPair_ECC(
        void*               hSessionHandle  ,
        unsigned int        uiKeyIndex      ,
        unsigned int        uiKeyType       ,
        ECCrefPublicKey*    pPubkey         ,
        ECCrefPrivateKey*   pPrikey         );

int
SDFE_ExportKeyPair_RSA(
        void*               hSessionHandle  ,
        unsigned int        uiKeyIndex      ,
        unsigned int        uiKeyType       ,
        RSArefPublicKey*    pPubkey         ,
        RSArefPrivateKey*   pPrikey         );

int
SDFE_ExportKEK(
        void*               hSessionHandle  ,
        unsigned int        uiKeyIndex      ,
        void*               pucKey          ,
        unsigned int*       puiKeyLen       );

int
SDFE_EnumUserKey(
        void*               hSessionHandle  ,
        void*               pKeyData        ,
        unsigned int*       puiKeyCount     );

int
SDFE_DelUserKey(
        void*               hSessionHandle  ,
        unsigned int        uiKeyAlg        ,
        unsigned int        uiKeyIndex      ,
        unsigned int        uiKeyType       );

int
SDFE_SetUserKeyPIN(
        void*               hSessionHandle  ,
        unsigned int        uiKeyAlg        ,
        unsigned int        uiKeyIndex      ,
        unsigned int        uiKeyType       ,
        unsigned char       *pucPIN			,
        unsigned int        uiPINLen      	);

// ##############################################
// HIK管理工具类
int
SDF_Tool_GenerateDeviceKey(
        void *          hSessionHandle  ,
        unsigned int    uiKeyBits       );

int
SDF_Tool_DestoryDeviceKey(
        void *          hSessionHandle  );

int
SDF_Tool_GenerateUsrKey(
        void *          hSessionHandle  ,
        unsigned int    uiKeyBits       ,
        unsigned int    uiAlgID         ,
        unsigned int *  KeyIndex        );

int
SDF_Tool_EnumUsrKey(
        void *          hSessionHandle      ,
        void **         hKeyIDArrayHandle   ,
        void **         hKeyTypeArrayHandle ,
        unsigned int*   KeyNum              );

int
SDF_Tool_DestoryUsrKey(
	void *              hSessionHandle      ,
	unsigned int        KeyIndex            ,
	unsigned int        KeyType             );

int
SDF_Tool_ImportUsrKey_RSA(
	void *              hSessionHandle  ,
	RSArefPublicKey *   encPublicKey    ,
	RSArefPrivateKey *  encPrivateKey   ,
	RSArefPublicKey *   signPublicKey   ,
	RSArefPrivateKey *  signPrivateKey  ,
	unsigned int        uiKeyIndex      );

int
SDF_Tool_ImportUsrKey_ECC(
	void *              hSessionHandle  ,
	ECCrefPublicKey *   encPublicKey    ,
	ECCrefPrivateKey *  encPrivateKey   ,
	ECCrefPublicKey *   signPublicKey   ,
	ECCrefPrivateKey *  signPrivateKey  ,
	unsigned int        uiKeyIndex      );
	
int SDF_Tool_EnumKEK(
	void* hSessionHandle,
	void** KeyArrayHandle,
	unsigned int* KeyNum);
	
int SDF_Tool_GenerateKEK(
	void *hSessionHandle,
	unsigned int* KeyIndex);
	
int SDF_Tool_DestoryKEK(
	void *hSessionHandle,
	unsigned int KeyIndex);

int SDFE_Hmac(
        void*               hSessionHandle  ,
        unsigned char*      key             ,
        uint32_t            uikeyLen        ,
        unsigned char*      indata          ,
        uint32_t            indataLen       ,
        unsigned char*      hashdata        ,
        uint32_t*           hashLen         );
#ifdef __cplusplus
    }
#endif
#endif//_SDFE_FUNC_H_

