#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include "piico_define.h"
#include "piico_error.h"
#include "api.h"

#define THREADNUM   20
#define COMFLAG     1

unsigned int threadnum=THREADNUM;

int errornum1=0,errornum2=0,errornum3=0;

typedef struct threadarg_st{
    int     testlength;
    int    threadid;
    int    testtimes;
    int    Alog;
    int     errorflag;
}ThreadArg;
            
void SetData(unsigned char *buf,int len,int offset)
{
    int i;
    for(i=0;i<len;i++)
        buf[i]=offset&0xff;
}


void TestEn(ThreadArg *Test_ulHandle)
{
    
    unsigned char iv[16],key[16];
    unsigned char *data,*endata,*data2;
    ECCCipher *cd;
    ECCSignature sd;
    ECCrefPrivateKey vk;
    ECCrefPublicKey pk;
    int testtime,num,ret,flag=0;
    unsigned int lenm;
    
    unsigned int testlen,relen;
    testlen=Test_ulHandle->testlength;
    testtime=Test_ulHandle->testtimes;
    data=(unsigned char *)malloc(testlen);
    endata=(unsigned char *)malloc(testlen);
    data2=(unsigned char *)malloc(testlen);
    SetData(data,testlen,Test_ulHandle->threadid);

    HANDLE DeviceHandle,SessionHandle;
    
    ret=SDF_OpenDevice(&DeviceHandle);
    if(ret!=0) {
        printf("Open device error!return is %08x\n",ret);
        return ;
    }
    ret=SDF_OpenSession(DeviceHandle,&SessionHandle);   
    if(ret!=0){
        printf("Open Session error!return is %08x,%08x\n",ret,SPII_GetErrorInfo(SessionHandle));
        SDF_CloseDevice(DeviceHandle);
        return ;
    }
    
    ret=SDF_GenerateRandom(SessionHandle, testlen, data);
    if(ret){
        printf("Thread %d SDF_GenerateRandom Function failure! %08x\n",Test_ulHandle->threadid,ret);
        goto ErrorEnd;
    }
    
    ret=SDF_GenerateKeyPair_ECC(SessionHandle,SGD_SM2_1,256,&pk,&vk);
    if(ret){
        printf("Thread %d SDF_GenerateKeyPair_ECC Function failure! %08x\n",Test_ulHandle->threadid,ret);
        goto ErrorEnd;
    }
    cd=malloc(sizeof(ECCCipher)+testlen);
    if(cd==NULL){
        goto ErrorEnd;
    }
    for(num=0;num<testtime;num++)
    {
        ret=SDF_ExternalEncrypt_ECC(SessionHandle,SGD_SM2_3,&pk,data,testlen,cd);
        if(ret){
            printf("Thread %d times %d SDF_ExternalEncrypt_ECC Function failure! %08x\n",Test_ulHandle->threadid,num,ret);
            flag=1;
            Test_ulHandle->errorflag=(Test_ulHandle->errorflag)|0x01;
            break;                        
        }
        
        if(num%1000==0){
            printf("Thread %d times %d ECC pk Encrypt test!\n",Test_ulHandle->threadid,num);
        }
    }
    
    if(!flag)
    {
        ret=SDF_ExternalDecrypt_ECC(SessionHandle,SGD_SM2_3,&vk,cd,endata,&lenm);
        if(ret){
            printf("Thread %d  SDF_ExternalDecrypt_ECC Function failure! %08x %08x\n",Test_ulHandle->threadid,ret,SPII_GetErrorInfo(SessionHandle));
            flag=1;
            Test_ulHandle->errorflag=(Test_ulHandle->errorflag)|0x01;
        }
        
        if(memcmp(data,endata,lenm)!=0){
            printf("Thread %d Compare failure! \n",Test_ulHandle->threadid);
            flag=1;
            Test_ulHandle->errorflag=(Test_ulHandle->errorflag)|0x01;
        } else {
            printf("Thread %d Compare Succeed! \n",Test_ulHandle->threadid);
        }
    }
    free(cd);

ErrorEnd:
    SDF_CloseSession(SessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return;
}
void TestDe(ThreadArg *Test_ulHandle)
{
    
    unsigned char iv[16],key[16];
    unsigned char *data,*endata,*data2;
    ECCCipher *cd;
    ECCSignature sd;
    ECCrefPrivateKey vk;
    ECCrefPublicKey pk;
    int testtime,num,ret,flag=0;
    unsigned int lenm;

    unsigned int testlen,relen;
    testlen=Test_ulHandle->testlength;
    testtime=Test_ulHandle->testtimes;
    data=(unsigned char *)malloc(testlen);
    endata=(unsigned char *)malloc(testlen);
    data2=(unsigned char *)malloc(testlen);
    SetData(data,testlen,Test_ulHandle->threadid);

    HANDLE DeviceHandle,SessionHandle;
    
    ret=SDF_OpenDevice(&DeviceHandle);
    if(ret!=0) {
        printf("Open device error!return is %08x\n",ret);
        return ;
    }
    ret=SDF_OpenSession(DeviceHandle,&SessionHandle);   
    if(ret!=0){
        printf("Open Session error!return is %08x,%08x\n",ret,SPII_GetErrorInfo(SessionHandle));
        SDF_CloseDevice(DeviceHandle);
        return ;
    }

    
    ret=SDF_GenerateRandom(SessionHandle, testlen, data);
    if(ret){
        printf("Thread %d SDF_GenerateRandom Function failure! %08x\n",Test_ulHandle->threadid,ret);
        goto ErrorEnd;
    }
    
    ret=SDF_GenerateKeyPair_ECC(SessionHandle,SGD_SM2_1,256,&pk,&vk);
    if(ret){
        printf("Thread %d SDF_GenerateKeyPair_ECC Function failure! %08x\n",Test_ulHandle->threadid,ret);
        goto ErrorEnd;
    }
    
    cd=malloc(sizeof(ECCCipher)+testlen);
    if(cd==NULL){
        goto ErrorEnd;
    }
    
    ret=SDF_ExternalEncrypt_ECC(SessionHandle,SGD_SM2_3,&pk,data,testlen,cd);
    if(ret){
        printf("Thread %d SDF_ExternalEncrypt_ECC Function failure! %08x\n",Test_ulHandle->threadid,ret);
        flag=1;
        Test_ulHandle->errorflag=(Test_ulHandle->errorflag)|0x01;
        goto ErrorEnd;
    }
    for(num=0;num<testtime;num++)
    {
        ret=SDF_ExternalDecrypt_ECC(SessionHandle,SGD_SM2_3,&vk,cd,endata,&lenm);
        if(ret){
            printf("Thread %d times %d SDF_ExternalDecrypt_ECC Function failure! %08x\n",Test_ulHandle->threadid,num,ret);
            flag=1;
            Test_ulHandle->errorflag=(Test_ulHandle->errorflag)|0x01;
            break;                        
        }
        
        if(memcmp(data,endata,lenm)!=0){
            printf("Thread %d %d times Compare failure! \n",Test_ulHandle->threadid,num);
            flag=1;
            Test_ulHandle->errorflag=(Test_ulHandle->errorflag)|0x01;
            break;
        }
        
        if(num%1000==0){
            printf("Thread %d times %d ECC vk Decrypt test!\n",Test_ulHandle->threadid,num);
        }
                

    }
    
    free(cd);
    
ErrorEnd:
    SDF_CloseSession(SessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return;

}
void TestSign(ThreadArg *Test_ulHandle)
{
    
    unsigned char iv[16],key[16];
    unsigned char data[32],endata[32],data2[32];
    ECCCipher *cd;
    ECCSignature sd;
    ECCrefPrivateKey vk;
    ECCrefPublicKey pk;
    int testtime,num,ret,flag=0;
    unsigned int lenm;
    
    testtime=Test_ulHandle->testtimes;
    SetData(data,32,Test_ulHandle->threadid);

    HANDLE DeviceHandle,SessionHandle;
    
    ret=SDF_OpenDevice(&DeviceHandle);
    if(ret!=0) {
        printf("Open device error!return is %08x\n",ret);
        return ;
    }
    ret=SDF_OpenSession(DeviceHandle,&SessionHandle);   
    if(ret!=0){
        printf("Open Session error!return is %08x,%08x\n",ret,SPII_GetErrorInfo(SessionHandle));
        SDF_CloseDevice(DeviceHandle);
        return ;
    }
    
    ret=SDF_GenerateRandom(SessionHandle, 32,data);
    if(ret){
        printf("Thread %d SDF_GenerateRandom Function failure! %08x\n",Test_ulHandle->threadid,ret);
        goto ErrorEnd;
    }
    ret=SDF_GenerateKeyPair_ECC(SessionHandle,SGD_SM2_1,256,&pk,&vk);
    if(ret){
        printf("Thread %d SDF_GenerateKeyPair_ECC Function failure! %08x\n",Test_ulHandle->threadid,ret);
        goto ErrorEnd;
    }
    
    for(num=0;num<testtime;num++){
        ret=SDF_ExternalSign_ECC(SessionHandle,SGD_SM2_1,&vk,data,32,&sd);
        if(ret){
            printf("Thread %d times %d SDF_ExternalSign_ECC Function failure! %08x\n",Test_ulHandle->threadid,num,ret);
            flag=1;
            Test_ulHandle->errorflag=(Test_ulHandle->errorflag)|0x01;
            break;                        
        }
        
        if(num%1000==0){
            printf("Thread %d times %d ECC vk sign test!\n",Test_ulHandle->threadid,num);
        }
    }
    
    if(!flag){
        ret=SDF_ExternalVerify_ECC(SessionHandle,SGD_SM2_1,&pk,data,32,&sd);
        if(ret)
        {
            printf("Thread %d  SDF_ExternalVerify_ECC Function failure! %08x\n",Test_ulHandle->threadid,ret);
            flag=1;
            Test_ulHandle->errorflag=(Test_ulHandle->errorflag)|0x01;
        } else {
            printf("Thread %d  SDF_ExternalVerify_ECC Function Succeed! \n",Test_ulHandle->threadid);
        }     
    }
    
ErrorEnd:
    SDF_CloseSession(SessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return;

}
void TestVer(ThreadArg *Test_ulHandle)
{
    
    unsigned char iv[16],key[16];
    unsigned char data[32],endata[32],data2[32];
    ECCCipher *cd;
    ECCSignature sd;
    ECCrefPrivateKey vk;
    ECCrefPublicKey pk;
    int testtime,num,ret,flag=0;
    unsigned int lenm;
    
    testtime=Test_ulHandle->testtimes;
    SetData(data,32,Test_ulHandle->threadid);

    HANDLE DeviceHandle,SessionHandle;
    
    ret=SDF_OpenDevice(&DeviceHandle);
    if(ret!=0) {
        printf("Open device error!return is %08x\n",ret);
        return ;
    }
    ret=SDF_OpenSession(DeviceHandle,&SessionHandle);   
    if(ret!=0){
        printf("Open Session error!return is %08x,%08x\n",ret,SPII_GetErrorInfo(SessionHandle));
        SDF_CloseDevice(DeviceHandle);
        return ;
    }
    
    ret=SDF_GenerateRandom(SessionHandle, 32,data);
    if(ret){
        printf("Thread %d SDF_GenerateRandom Function failure! %08x\n",Test_ulHandle->threadid,ret);
        goto ErrorEnd;
    }
    ret=SDF_GenerateKeyPair_ECC(SessionHandle,SGD_SM2_1,256,&pk,&vk);
    if(ret){
        printf("Thread %d SDF_GenerateKeyPair_ECC Function failure! %08x\n",Test_ulHandle->threadid,ret);
        goto ErrorEnd;
    }
    ret=SDF_ExternalSign_ECC(SessionHandle,SGD_SM2_1,&vk,data,32,&sd);
    if(ret){
        printf("Thread %d SDF_ExternalSign_ECC Function failure! %08x\n",Test_ulHandle->threadid,ret);
        flag=1;
        Test_ulHandle->errorflag=(Test_ulHandle->errorflag)|0x01;
        goto ErrorEnd;
    }
    
    for(num=0;num<testtime;num++){
        ret=SDF_ExternalVerify_ECC(SessionHandle,SGD_SM2_1,&pk,data,32,&sd);
        if(ret){
            printf("Thread %d  times %d SDF_ExternalVerify_ECC Function failure! %08x\n",Test_ulHandle->threadid,num,ret);
            flag=1;
            Test_ulHandle->errorflag=(Test_ulHandle->errorflag)|0x01;
            break;
        }
        
        if(num%1000==0){
            printf("Thread %d times %d ECC pk unsign test!\n",Test_ulHandle->threadid,num);
        }
    }
    
ErrorEnd:
    SDF_CloseSession(SessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return;

}
void TestGen(ThreadArg *Test_ulHandle)
{
    unsigned char iv[16],key[16];
    unsigned char data[32],endata[32],data2[32];
    ECCCipher *cd;
    ECCSignature sd;
    ECCrefPrivateKey vk;
    ECCrefPublicKey pk;
    int testtime,num,ret,flag=0;
    unsigned int lenm;
    
    testtime=Test_ulHandle->testtimes;

    HANDLE DeviceHandle,SessionHandle;
    
    ret=SDF_OpenDevice(&DeviceHandle);
    if(ret!=0) {
        printf("Open device error!return is %08x\n",ret);
        return ;
    }
    ret=SDF_OpenSession(DeviceHandle,&SessionHandle);   
    if(ret!=0){
        printf("Open Session error!return is %08x,%08x\n",ret,SPII_GetErrorInfo(SessionHandle));
        SDF_CloseDevice(DeviceHandle);
        return ;
    }

    
    for(num=0;num<testtime;num++){
        ret=SDF_GenerateKeyPair_ECC(SessionHandle,SGD_SM2_1,256,&pk,&vk);
        if(ret)
        {
            printf("Thread %d SDF_GenerateKeyPair_ECC Function failure! %08x\n",Test_ulHandle->threadid,ret);
            flag=1;
            Test_ulHandle->errorflag=(Test_ulHandle->errorflag)|0x01;
            break;
        }
        if(num%1000==0){
            printf("Thread %d times %d ECC KeyPair Generate test!\n",Test_ulHandle->threadid,num);
        }
    }
    
    ret=SDF_ExternalSign_ECC(SessionHandle,SGD_SM2_1,&vk,data,32,&sd);
    if(ret){
        printf("Thread %d SDF_ExternalSign_ECC Function failure! %08x\n",Test_ulHandle->threadid,ret);
        flag=1;
        Test_ulHandle->errorflag=(Test_ulHandle->errorflag)|0x01;
        goto ErrorEnd;                       
    }
    
    ret=SDF_ExternalVerify_ECC(SessionHandle,SGD_SM2_1,&pk,data,32,&sd);
    if(ret){
        printf("Thread %d  SDF_ExternalVerify_ECC Function failure! %08x\n",Test_ulHandle->threadid,ret);
        flag=1;
        Test_ulHandle->errorflag=(Test_ulHandle->errorflag)|0x01;
        goto ErrorEnd;
    }
    
    printf("Thread %d last KeyPair Check succeed!\n",Test_ulHandle->threadid);

    
ErrorEnd:
    SDF_CloseSession(SessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return;

}
int main()
{
    struct timeval end,begin;
    unsigned long sec,msec;
    int num=0,count,i=0,j=0,ret=0;
    unsigned int testtime=0,testlength=0,testthreadnum=0,testalog;
    float sptime,rate,alog;
    pthread_t idth[THREADNUM];
    ThreadArg threadarg[THREADNUM];
    
    printf("PIICO EncryrptCard SM2 test .....\n");
    printf("Please input test times:");
    scanf("%d",&testtime);
    printf("Please input test threadnum (1~10):");
    scanf("%d",&testthreadnum);
    printf("Please input test Alog:1:ECC_Enc 2:ECC_Dec: 3:ECC_Sign 4:ECC_Ver 5:ECC_Gen\n");
    printf("Please Select:");
    scanf("%d",&testalog);

    if(testalog == 1 || testalog == 2 ){
        printf("Please input test length:");
        scanf("%d",&testlength);
    }
    
    for(i=0;i<testthreadnum;i++){
        threadarg[i].testlength=testlength;
        threadarg[i].threadid=i;
        threadarg[i].testtimes=testtime;
        threadarg[i].Alog=alog;
        threadarg[i].errorflag=0;
    }
    
    gettimeofday(&begin,0);
    for(j=0;j<testthreadnum;j++)
    {
        switch(testalog)
        {
            case 1:
                ret=pthread_create(&idth[j],NULL,(void *)TestEn,&threadarg[j]);
                break;
            case 2:
                ret=pthread_create(&idth[j],NULL,(void *)TestDe,&threadarg[j]);
                break;
            case 3:
                ret=pthread_create(&idth[j],NULL,(void *)TestSign,&threadarg[j]);
                break;
            case 4:
                ret=pthread_create(&idth[j],NULL,(void *)TestVer,&threadarg[j]);
                break;
            case 5:
                ret=pthread_create(&idth[j],NULL,(void *)TestGen,&threadarg[j]);
                break;
            default:
                return 0;
        }
        if(ret){
            printf ("Create pthread error! %d\n",ret);
        } else {
            printf("thread %d succeed!\n",j);
        }
    }
    
    for(j=0;j<testthreadnum;j++){
        pthread_join(idth[j],NULL);
    }
        
    for(j=0;j<testthreadnum;j++){
        printf("threadarg[%d].errorflag=0x%08x\n",j,threadarg[j].errorflag);
    }

    gettimeofday(&end,0);
    
    if((end.tv_usec - begin.tv_usec)<0){
        msec=end.tv_usec/1000.0+1000 - begin.tv_usec/1000.0;
        sec =end.tv_sec - begin.tv_sec - 1;
    } else {
        msec=end.tv_usec/1000.0 - begin.tv_usec/1000.0;
        sec =end.tv_sec - begin.tv_sec;
    } 
    sptime=((float)msec/1000+sec);

    rate=testtime*testthreadnum/sptime;
    printf("Time: %2.2f sec\n",sptime);
    printf("rate: %f times/Second\n",rate);

    if(testalog == 1 || testalog == 2 ){ //for enc and dec
        rate = rate*testlength/1024/1024*8;
        printf("rate: %f Mbps\n",rate);
    }
    
    return 0;
}
