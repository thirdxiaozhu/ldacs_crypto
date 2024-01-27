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
* Function name:    sm2_encrypt_decrypt
* Description:      SM2加解密运算
* Return:           0 success  ,  other fail
**********************************************************/
int sm2_encrypt_decrypt(){
    HANDLE DeviceHandle,pSessionHandle; 
    int ret;

    printf("\n=====SM2 Encryption & Decryption test start!\n");

    ret=SDF_OpenDevice(&DeviceHandle);  //打开设备
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_OpenDevice error!return 0x%08x\n",ret);
        return ret;
    }
    
    ret=SDF_OpenSession(DeviceHandle, &pSessionHandle); //打开会话句柄
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_OpenSession error!return 0x%08x\n",ret);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }

    ECCrefPrivateKey vk; //private key
    ECCrefPublicKey pk;  //public key
    ret=SDF_GenerateKeyPair_ECC(pSessionHandle,SGD_SM2_1,256,&pk,&vk); //? 为什么是SGD_SM2_1
    if(ret!=0){
        printf("SDF_GenerateKeyPair_ECC Function failure! %08x\n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }

    unsigned char pbPlainText[32];  //加密用的明文数据
    ret=SDF_GenerateRandom(pSessionHandle,32,pbPlainText);
	if(ret!=0){
        printf("SDF_GenerateRandom Function failure! %08x\n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return ret;
	}
    printbuff("PlainText", pbPlainText, 32);

    ECCCipher *eccEnData;
    eccEnData=malloc(sizeof(ECCCipher)+32); /* 需要申请额外的空间，来存放加密后的密文. 额外长度应与明文长度相同 */
	if(eccEnData==NULL){
        printf("malloc failure!\n");
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return -1;
    }

    ret=SDF_ExternalEncrypt_ECC(pSessionHandle,SGD_SM2_3,&pk,pbPlainText,32,eccEnData);
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_ExternalEncrypt_ECC Function failure! %08x %08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
		return ret;				
	}
    printbuff("eccEnData:",eccEnData->C,eccEnData->L);
    

    unsigned char tempData[32];
    unsigned int tempDataLen;
    ret=SDF_ExternalDecrypt_ECC(pSessionHandle,SGD_SM2_3,&vk,eccEnData,tempData,&tempDataLen);
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_ExternalDecrypt_ECC Function failure! %08x %08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }
    if(memcmp(pbPlainText,tempData,tempDataLen)!=0){ /* 将解密结果与明文数据进行对比 */
        printbuff("Compare error:\nSM2 Encryption PlainText:",pbPlainText,tempDataLen);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return -1;
    }
    printbuff("Decrypted", tempData, tempDataLen);
        
    printf("=====SM2 Encryption & Decryption test succeed!\n");

    free(eccEnData);
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return 0;    
}

/*******************************************************
*
* Function name:    sm2_encrypt_decrypt
* Description:      SM2加解密运算
* Return:           0 success  ,  other fail
**********************************************************/
int sm2_sign_verify(){
    HANDLE DeviceHandle,pSessionHandle; 
    int ret;

    printf("\n=====SM2 Sign & Verify test start!\n");

    ret=SDF_OpenDevice(&DeviceHandle);  //打开设备
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_OpenDevice error!return 0x%08x\n",ret);
        return ret;
    }
    
    ret=SDF_OpenSession(DeviceHandle, &pSessionHandle); //打开会话句柄
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_OpenSession error!return 0x%08x\n",ret);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }

    ECCrefPrivateKey vk; //private key
    ECCrefPublicKey pk;  //public key
    ret=SDF_GenerateKeyPair_ECC(pSessionHandle,SGD_SM2_1,256,&pk,&vk); //? 为什么是SGD_SM2_1
    if(ret!=0){
        printf("SDF_GenerateKeyPair_ECC Function failure! %08x\n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }

    unsigned char pbPlainText[32];  //加密用的明文数据
    ret=SDF_GenerateRandom(pSessionHandle,32,pbPlainText);
	if(ret!=0){
        printf("SDF_GenerateRandom Function failure! %08x\n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return ret;
	}
    printbuff("PlainText", pbPlainText, 32);

    ECCSignature eccSignData;
    ret=SDF_ExternalSign_ECC(pSessionHandle,SGD_SM2_1,&vk,pbPlainText,32,&eccSignData);
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_ExternalSign_ECC Function failure! %08x\n",ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }
    printf("SM2 Sign finished! Sign data:\n");
    printbuff("eccSignData.r:",eccSignData.r,ECCref_MAX_LEN);
    printbuff("eccSignData.s:",eccSignData.s,ECCref_MAX_LEN);

    ret=SDF_ExternalVerify_ECC(pSessionHandle,SGD_SM2_1,&pk,pbPlainText,32,&eccSignData);
    if(ret!=SR_SUCCESSFULLY){
        printf("SDF_ExternalVerify_ECC Function failure! %08x\n", ret);
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return ret;
    }
    printf("SM2 Verify finished!\n");

    //Vrify fail test start
    printf("SM2 Verify pbPlainText2 start!\n");
    unsigned char pbPlainText2[32];
    memcpy(pbPlainText2, pbPlainText, 32);
    pbPlainText2[0] = 0x01;
    printbuff("PlainText2", pbPlainText2, 32);
    ret=SDF_ExternalVerify_ECC(pSessionHandle,SGD_SM2_1,&pk,pbPlainText2,32,&eccSignData);
    if(ret!=SR_SUCCESSFULLY){
        if(ret == CCR_ECC_VERIFY_FAIL){
            printf("SDF_ExternalVerify_ECC Vrify fail! %08X\n", ret);
        } else {
            printf("SDF_ExternalVerify_ECC Function failure! %08x\n", ret);
            SDF_CloseSession(pSessionHandle);
            SDF_CloseDevice(DeviceHandle);
            return ret;
        }
    }
    printf("SM2 Verify pbPlainText2 finished!\n");
    //Vrify fail test end
    
    printf("=====SM2 Sign & Verify test succeed!\n");

    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return 0;    
}


int main(void)
{
    int ret;

    ret = sm2_encrypt_decrypt();
    if(ret!=0) return -1;

    ret = sm2_sign_verify();
    if(ret!=0) return -1;

    printf("\n=====All test succeed!\n");
    return 0;
}

