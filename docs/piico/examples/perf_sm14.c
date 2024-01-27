#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "api.h"
#include "piico_define.h"
#include "piico_error.h"

#define THREADNUM 640
#define COMFLAG 1

unsigned int threadnum = THREADNUM;

int errornum1 = 0, errornum2 = 0, errornum3 = 0;

typedef struct threadarg_st {
  int testlength;
  int threadid;
  int testtimes;
  int Alog;
  int encryptflag;
  int errorflag;
} ThreadArg;

void SetData(unsigned char *buf, int len, int offset) {
  int i;
  for (i = 0; i < len; i++) buf[i] = offset & 0xff;
}

void TestEnDe(ThreadArg *Test_ulHandle) {
  unsigned char iv[16], key[16], ivt[16], pucData[400];
  unsigned char *data, *endata, *data2;
  HANDLE DeviceHandle, SessionHandle;
  unsigned int testlen, relen, num, testtime, i;
  unsigned char pin[100] = {"wuxipiico"};
  int flag = 0, ret, testbyteslong;
  HANDLE keyHandle, keyHandle1;

  testlen = Test_ulHandle->testlength;
  testtime = Test_ulHandle->testtimes;
  data = (unsigned char *)malloc(testlen);
  endata = (unsigned char *)malloc(testlen);
  data2 = (unsigned char *)malloc(testlen);

  ret = SDF_OpenDevice(&DeviceHandle);
  if (ret) {
    // printf("Open device error!return 0x%08x(%s)\n",ret, pii_strerror(ret));
    printf("Open device error!return 0x%08x\n", ret);
    return;
  }

  ret = SDF_OpenSession(DeviceHandle, &SessionHandle);
  if (ret) {
    printf("Open Session error!return is %08x,%08x\n", ret,
           SPII_GetErrorInfo(SessionHandle));
    SDF_CloseDevice(DeviceHandle);
    return;
  }

  ret = SDF_GenerateRandom(SessionHandle, 16, key);
  if (ret) {
    printf("Thread %d SDF_GenerateRandom Function failure! %08x\n",
           Test_ulHandle->threadid, ret);
    Test_ulHandle->errorflag = (Test_ulHandle->errorflag) | 0x01;
    goto ErrorEnd;
  }

  ret = SDF_GenerateRandom(SessionHandle, 16, iv);
  if (ret) {
    printf("Thread %d SDF_GenerateRandom Function failure! %08x\n",
           Test_ulHandle->threadid, ret);
    Test_ulHandle->errorflag = (Test_ulHandle->errorflag) | 0x01;
    goto ErrorEnd;
  }

  ret = SDF_GenerateRandom(SessionHandle, testlen, data);
  if (ret) {
    printf("Thread %d SDF_GenerateRandom Function failure! %08x\n",
           Test_ulHandle->threadid, ret);
    Test_ulHandle->errorflag = (Test_ulHandle->errorflag) | 0x01;
    goto ErrorEnd;
  }

  for (num = 0; num < testtime; num++) {
    if ((2 * num) % 5000 == 0) {
      printf("Thread %d num:%d\n", Test_ulHandle->threadid, num);
    }

    memcpy(ivt, iv, 16);
    ret = SPII_EncryptEx(SessionHandle, data, testlen, key, 16, ivt, 16,
                         Test_ulHandle->Alog, endata, &relen);
    if (ret) {
      printf("Thread %d times %d SPII_EncryptEx Function failure! %08x\n",
             Test_ulHandle->threadid, num, ret);
      Test_ulHandle->errorflag = (Test_ulHandle->errorflag) | 0x01;
      goto ErrorEndDK;
    }

    if (testlen != relen) {
      printf(
          "Thread %d times %d Encrypt return length error!testlen is %d,return "
          "length is %d\n",
          Test_ulHandle->threadid, num, testlen, relen);
      Test_ulHandle->errorflag = (Test_ulHandle->errorflag) | 0x02;
      goto ErrorEndDK;
    }

    memcpy(ivt, iv, 16);
    ret = SPII_DecryptEx(SessionHandle, endata, relen, key, 16, ivt, 16,
                         Test_ulHandle->Alog, data2, &relen);
    if (ret) {
      printf("Thread %d times %d SPII_DecryptEx Function failure! %08x\n",
             Test_ulHandle->threadid, num, ret);
      errornum3++;
      Test_ulHandle->errorflag = (Test_ulHandle->errorflag) | 0x04;
      goto ErrorEndDK;
    }
    if (testlen != relen) {
      printf(
          "Thread %d times %d Decrypt return length error!testlen is %d,return "
          "length is %d\n",
          Test_ulHandle->threadid, num, testlen, relen);
      Test_ulHandle->errorflag = (Test_ulHandle->errorflag) | 0x08;
      goto ErrorEndDK;
    }
    if (COMFLAG) {
      if (relen != testlen || memcmp(data, data2, testlen) != 0) {
        printf(
            "Thread %d times %d Compare failure!Test length is %d ,but return "
            "length is %d\n",
            Test_ulHandle->threadid, num, testlen, relen);
        Test_ulHandle->errorflag = (Test_ulHandle->errorflag) | 0x10;
        errornum3++;
        if (relen == testlen) {
          for (i = 0; i < testlen; i++) {
            printf("%02x ", data[i]);
          }
          printf("\n");

          for (i = 0; i < testlen; i++) {
            printf("%02x ", data2[i]);
          }
          printf("\n");

          for (i = 0; i < 16; i++) {
            printf("%02x ", iv[i]);
          }
          printf("\n");
        }
        goto ErrorEndDK;
      }
    }
  }
ErrorEndDK:
ErrorEnd:
  SDF_CloseSession(SessionHandle);
  SDF_CloseDevice(DeviceHandle);
  free(data);
  free(endata);
  free(data2);
  return;
}

int main() {
  struct timeval end, begin;
  unsigned long sec, msec;
  int num = 0, count, i = 0, j = 0, ret = 0;
  unsigned int testtime = 0, testlength = 0, testthreadnum = 0, testalog;
  float sptime, rate, alog;
  int encryptflag;
  pthread_t idth[THREADNUM];
  ThreadArg threadarg[THREADNUM];
  DEVICEINFO DeInfo;
  HANDLE DeviceHandle, pSessionHandle;

  ret = SDF_OpenDevice(&DeviceHandle);
  if (ret != SR_SUCCESSFULLY) {
    printf("SDF_OpenDevice error!return is %08x\n", ret);
    return;
  }

  ret = SDF_OpenSession(DeviceHandle, &pSessionHandle);
  if (ret != SR_SUCCESSFULLY) {
    printf("SDF_OpenSession error!return is %08x,%08x \n", ret,
           SPII_GetErrorInfo(pSessionHandle));
    ret = SDF_CloseDevice(DeviceHandle);
    return;
  }

  ret = SDF_GetDeviceInfo(pSessionHandle, &DeInfo);

  if (ret != SR_SUCCESSFULLY) {
    printf("SDF_GetDeviceInfo error!return is %08x %08x\n", ret,
           SPII_GetErrorInfo(pSessionHandle));
    ret = SDF_CloseSession(pSessionHandle);
    ret = SDF_CloseDevice(DeviceHandle);
    return;
  }
  ret = SDF_CloseSession(pSessionHandle);
  ret = SDF_CloseDevice(DeviceHandle);

  printf("PIICO EncryptCard SM1&SM4 test ....\n");
  printf("Please input test times:");
  scanf("%d", &testtime);
  printf("Please input test length:");
  scanf("%d", &testlength);
  printf("Please input test threadnum (<640):");
  scanf("%d", &testthreadnum);
  printf("Please input test Alog:\n");
  printf("SM1_ECB_Encrypt--------------1\n");
  printf("SM1_ECB_Decrypt--------------2\n");
  printf("SM1_CBC_Encrypt--------------3\n");
  printf("SM1_CBC_Decrypt--------------4\n");
  printf("SM4_ECB_Encrypt--------------5\n");
  printf("SM4_ECB_Decrypt--------------6\n");
  printf("SM4_CBC_Encrypt--------------7\n");
  printf("SM4_CBC_Decrypt--------------8\n");
  if ((DeInfo.SymAlgAbility & SGD_SSF33_CBC) == SGD_SSF33_CBC) {
    printf("SSF33_ECB_Encrypt-------------9\n");
    printf("SSF33_ECB_Decrypt------------10\n");
    printf("SSF33_CBC_Encrypt------------11\n");
    printf("SSF33_CBC_Decrypt------------12\n");
  }
  if ((DeInfo.SymAlgAbility & SGD_SM7_CBC) == SGD_SM7_CBC) {
    printf("SM7_ECB_Encrypt--------------13\n");
    printf("SM7_ECB_Decrypt--------------14\n");
    printf("SM7_CBC_Encrypt--------------15\n");
    printf("SM7_CBC_Decrypt--------------16\n");
  }
  scanf("%d", &testalog);

  switch (testalog) {
    case 1:
    default:
      alog = SGD_SM1_ECB;
      encryptflag = 1;
      break;
    case 2:
      alog = SGD_SM1_ECB;
      encryptflag = 0;
      break;
    case 3:
      alog = SGD_SM1_CBC;
      encryptflag = 1;
      break;
    case 4:
      alog = SGD_SM1_CBC;
      encryptflag = 0;
      break;
    case 5:
      alog = SGD_SM4_ECB;
      encryptflag = 1;
      break;
    case 6:
      alog = SGD_SM4_ECB;
      encryptflag = 0;
      break;
    case 7:
      alog = SGD_SM4_CBC;
      encryptflag = 1;
      break;
    case 8:
      alog = SGD_SM4_CBC;
      encryptflag = 0;
      break;
    case 9:
      alog = SGD_SSF33_ECB;
      encryptflag = 1;
      break;
    case 10:
      alog = SGD_SSF33_ECB;
      encryptflag = 0;
      break;
    case 11:
      alog = SGD_SSF33_CBC;
      encryptflag = 1;
      break;
    case 12:
      alog = SGD_SSF33_CBC;
      encryptflag = 0;
      break;
    case 13:
      alog = SGD_SM7_ECB;
      encryptflag = 1;
      break;
    case 14:
      alog = SGD_SM7_ECB;
      encryptflag = 0;
      break;
    case 15:
      alog = SGD_SM7_CBC;
      encryptflag = 1;
      break;
    case 16:
      alog = SGD_SM7_CBC;
      encryptflag = 0;
      break;
  }

  for (i = 0; i < testthreadnum; i++) {
    threadarg[i].testlength = testlength;
    threadarg[i].threadid = i;
    threadarg[i].testtimes = testtime;
    threadarg[i].Alog = alog;
    threadarg[i].encryptflag = encryptflag;
    threadarg[i].errorflag = 0;
  }

  gettimeofday(&begin, 0);
  for (j = 0; j < testthreadnum; j++) {
    ret = pthread_create(&idth[j], NULL, (void *)TestEnDe, &threadarg[j]);
    if (ret) {
      printf("Create pthread error! %d\n", ret);
    } else {
      printf("thread %d succeed!\n", j);
    }
  }

  for (j = 0; j < testthreadnum; j++) {
    pthread_join(idth[j], NULL);
  }

  for (j = 0; j < testthreadnum; j++) {
    printf("threadarg[%d].errorflag=0x%08x\n", j, threadarg[j].errorflag);
  }

  gettimeofday(&end, 0);

  if ((end.tv_usec - begin.tv_usec) < 0) {
    msec = end.tv_usec / 1000.0 + 1000 - begin.tv_usec / 1000.0;
    sec = end.tv_sec - begin.tv_sec - 1;
  } else {
    msec = end.tv_usec / 1000.0 - begin.tv_usec / 1000.0;
    sec = end.tv_sec - begin.tv_sec;
  }
  sptime = ((float)msec / 1000 + sec);
  testlength = testlength * testthreadnum;

  rate = testtime / 1024 * testlength / 1024 * 16 / sptime;
  printf("Time: %2.2f sec\n", sptime);
  printf("rate: %f Mbps\n", rate);

  return 0;
}
