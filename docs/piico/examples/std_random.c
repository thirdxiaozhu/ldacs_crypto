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
* Function name:    getRandom
* Description:      ��ȡӲ�������
* Return:           0 success  ,  other fail
**********************************************************/
int getRandom(){
    HANDLE DeviceHandle,pSessionHandle; 
    int ret;

    printf("\n=====Random SDF_GenerateRandom test start!\n");

    ret=SDF_OpenDevice(&DeviceHandle);  //���豸
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_OpenDevice error!return is %08x\n",ret);
        return ret;
    }
    
    ret=SDF_OpenSession(DeviceHandle, &pSessionHandle); //�򿪻Ự���
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_OpenSession error!return is %08x\n",ret);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }

    unsigned char randomData[64];
    ret=SDF_GenerateRandom(pSessionHandle,64,randomData);
	if(ret!=0){
        printf("SDF_GenerateRandom Function failure! %08x %08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return ret;
	}
    printbuff("randomData", randomData, 64);
        
    printf("=====Random SDF_GenerateRandom test succeed!\n");

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return 0;    
}

int main(void)
{
    int ret;

    ret = getRandom();
    if(ret!=0) return -1;
    
    printf("\n=====All test succeed!\n");
    return 0;
}

