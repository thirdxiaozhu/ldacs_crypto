#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "piico_define.h"
#include "piico_error.h"
#include "api.h"

void printbuff(const char *printtitle, unsigned char *buff, int len)
{
    int i;
    printf("%s:\n",printtitle);
    for(i=0; i<len; i++){
        printf("%02x ",buff[i]);
        if( (i+1)%16 == 0 ) printf("\n");
    }
    
    if((i%16)==0){
        printf("-----------------------------\n");
    } else {
        printf("\n-----------------------------\n");
    }
}

/*******************************************************
*
* Function name:    sm2Encryption
* Description:      SM2�ӽ�������
* Return:           0 success  ,  other fail
**********************************************************/
int sm3_hash(){
    /* SM3 HASH ��׼����ϣ���� */
    unsigned char bHashData[64] =  {0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                    0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                    0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                    0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64};
    /* SM3 HASH ��׼�������ݵĹ�ϣֵ */
    unsigned char bHashStdResult[32] = {0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
                                        0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32};

    HANDLE DeviceHandle,pSessionHandle; 
    int ret;

    printf("\n=====SM3 Hash test start!\n");

    ret=SDF_OpenDevice(&DeviceHandle);  //���豸
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_OpenDevice error!return 0x%08x\n",ret);
        return ret;
    }
    
    ret=SDF_OpenSession(DeviceHandle, &pSessionHandle); //�򿪻Ự���
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_OpenSession error!return 0x%08x\n",ret);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }
    
    unsigned char hashResult[32]; 
    unsigned int hashResultLen;
    
    ret=SDF_HashInit(pSessionHandle,SGD_SM3,NULL,NULL,0);
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_HashInit Function failure! %08x %08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }
    
    ret=SDF_HashUpdate(pSessionHandle,bHashData,64);
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_HashUpdate Function failure! %08x %08x\n",ret,SPII_GetErrorInfo(pSessionHandle));   
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }
    
    ret=SDF_HashFinal(pSessionHandle,hashResult,&hashResultLen);
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_HashFinish Function failure! %08x %08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }
    printbuff("bHashData", bHashData, 64);
    printbuff("hashResult", hashResult, hashResultLen);

    if(memcmp(hashResult,bHashStdResult,hashResultLen)!=0){ /* ���׼�������ݽ��жԱ� */
        printbuff("Compare error:\nSM3 Hash std Result:",bHashStdResult,64);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return -1;
    }
        
    printf("=====SM3 HASH test succeed!\n");

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return 0;    
}


int main(){
    
    int ret;
    
    ret = sm3_hash();
    if(ret!=0) return -1;

    printf("\n=====All test succeed!\n");
    return 0;
}

