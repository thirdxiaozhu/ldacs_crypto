
#ifndef _SDF_DEVINFO_H_
#define _SDF_DEVINFO_H_

#include "sdf-basetype.h"

// ##############################################
// GM/T 0018 5.2 设备信息定义
typedef struct DeviceInfo_st {
    unsigned char   IssuerName[40];
    unsigned char   DeviceName[16];
    unsigned char   DeviceSerial[16];
    unsigned int    DeviceVersion;
    unsigned int    StandardVersion;
    unsigned int    AsymAlgAbility[2];
    unsigned int    SymAlgAbility;
    unsigned int    HashAlgAbility;
    unsigned int    BufferSize;
} DEVICEINFO;

#endif//_SDF_DEVINFO_H_

