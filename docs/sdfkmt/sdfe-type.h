
#ifndef _SDFE_TYPE_H_
#define _SDFE_TYPE_H_

#define MAX_PIN_LEN		(16)
#define MANAGER_COUNT   5
#define OPERATOR_COUNT  3

#include <stdint.h>
//typedef unsigned int uint32_t;
//typedef unsigned char uint8_t;

typedef struct UserInfo_st {
    uint32_t index;
    uint32_t type;
    uint32_t stat;
} UserInfo;

typedef struct UserStore_st {
    uint32_t        type    ;
    uint32_t        status  ;
    uint32_t        pinlen              ;
    uint8_t         pindat[MAX_PIN_LEN] ;
    uint8_t         ukeysn[32]  ;
    ECCrefPublicKey pubkey  ;
    uint32_t        index   ;
} UserStore;

typedef struct VFUserStore_st {
    UserStore   userstore[MANAGER_COUNT+OPERATOR_COUNT];
} VFUserStore;

typedef struct KeyInfo_st {
    uint32_t vfnum;
    uint32_t index;
    uint32_t type;
    uint32_t bits;
    uint32_t stat;
} KeyInfo;

enum
{
#if 1
    USER_TYPE_MANAGER,
    USER_TYPE_OPERATOR,
    USER_TYPE_AUDITOR,
    USER_TYPE_ADMIN,
    USER_TYPE_NULL,
#else
    USER_TYPE_ADMIN,
    USER_TYPE_OPERATOR,
    USER_TYPE_AUDITOR,
    USER_TYPE_MANAGER,
    USER_TYPE_NULL,
#endif
};

enum
{
    USER_STATUS_LOGIN   = 0,
    USER_STATUS_LOGOUT  = 1,
    USER_STATUS_NULL    = 2,
};

typedef enum SDG_DeviceState_en
{
    SDF_DEVICE_STATE_INIT   = 0,
    SDF_DEVICE_STATE_READY  = 1,
    SDF_DEVICE_STATE_ADMIN  = 2,
    SDF_DEVICE_STATE_LOCK   = 3,
    SDF_DEVICE_STATE_NOCTL_LOGIN    = 4,
    SDF_DEVICE_STATE_NOCTL_LOGOUT   = 5,
}SGD_DeviceState;

typedef enum SDFKeyState_en {
    SDF_KEYSTATE_NULL           = 0x00,
    
    SDF_KEYSTATE_HAVERIGHT      = 0x01,
    SDF_KEYSTATE_NORIGHT        = 0x02,
    
    SDF_KEYSTATE_UNKNOWN        = 0x03,
} SDFKeyState;

typedef struct DevStatus_st {
    uint32_t    magic   ;
    uint32_t    status  ;
    uint8_t     SN[16]  ;
    uint8_t     padding[8];
} DevStatus;

#endif//_SDFE_TYPE_H_

