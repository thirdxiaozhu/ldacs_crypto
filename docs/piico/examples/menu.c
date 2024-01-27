
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#include "api.h"
#include "piico_define.h"
#include "piico_error.h"
#define DATALEN MAX_DATALEN
void StatusChange();
int Gflag = 0;

int readfile(char *file, unsigned char *buf, int *len)
{
  int i;
  int filelen;
  FILE *fp = fopen(file, "rb");
  if (fp == NULL)
  {
    printf("fopen error!\n");
    return -1;
  }
  // printf("fp:%x\n",fp);
  fseek(fp, 0, SEEK_END);
  filelen = ftell(fp);
  *len = filelen;
  fseek(fp, 0, SEEK_SET);
  fread(buf, filelen, 1, fp);
  fclose(fp);
  return 0;
}

int wrtiefile(char *file, unsigned char *buf, int len)
{
  FILE *fp = fopen(file, "wb");
  if (!fp)
    return -1;
  fwrite(buf, len, 1, fp);
  fclose(fp);
  return 0;
}
void PrintPer(char *info, int totl, int step)
{
  float p;
  int tmp, hz;
  hz = 500;
  if (step % hz != 0)
  {
    p = (float)step / totl * 100;
    if (step == 0)
      printf("%s %.2f %%....--\n", info, p);
    else
    {
      printf("\033[1A");
      printf("\033[K");
      tmp = (step / hz) % 4;
      switch (tmp)
      {
      case 0:
        printf("%s %.2f %%....|\n", info, p);
        break;
      case 1:
        printf("%s %.2f %%..../\n", info, p);
        break;
      case 2:
        printf("%s %.2f %%....--\n", info, p);
        break;
      case 3:
        printf("%s %.2f %%....\\ \n", info, p);
        break;
      }
    }
  }
}
void printeccchiper(const char *printtitle, ECCCipher *endata)
{
  int i;
  printf("%s:\n", printtitle);
  for (i = 0; i < 32; i++)
  {
    printf("%02x ", endata->x[i + 32]);
    if (((i + 1) % 16) == 0)
      printf("\n");
  }
  for (i = 0; i < 32; i++)
  {
    printf("%02x ", endata->y[i + 32]);
    if (((i + 1) % 16) == 0)
      printf("\n");
  }
  for (i = 0; i < 32; i++)
  {
    printf("%02x ", endata->M[i]);
    if (((i + 1) % 16) == 0)
      printf("\n");
  }
  printf("L is %d\n", endata->L);
  for (i = 0; i < endata->L; i++)
  {
    printf("%02x ", endata->C[i]);
    if (((i + 1) % 16) == 0)
      printf("\n");
  }
}
void printeccpk(const char *printtitle, ECCrefPublicKey *pk)
{
  int i;
  printf("%s:\n", printtitle);
  for (i = 0; i < 32; i++)
  {
    printf("%02x ", pk->x[i + 32]);
    if (((i + 1) % 16) == 0)
      printf("\n");
  }
  for (i = 0; i < 32; i++)
  {
    printf("%02x ", pk->y[i + 32]);
    if (((i + 1) % 16) == 0)
      printf("\n");
  }
}
void printeccvk(const char *printtitle, ECCrefPrivateKey *vk)
{
  int i;
  printf("%s:\n", printtitle);
  for (i = 0; i < 32; i++)
  {
    printf("%02x ", vk->K[i + 32]);
    if (((i + 1) % 16) == 0)
      printf("\n");
  }
}
void printbuff1(const char *printtitle, unsigned char *buff, int len)
{
  int i;
  printf("%s:\n", printtitle);
  for (i = 0; i < len; i++)
  {
    printf("%02x ", buff[i]);
    if (((i + 1) % 16) == 0)
      printf("\n");
  }
  if ((i % 16) == 0)
    printf("=============================\n");
  else
    printf("\n=============================\n");
}

void printbuff(unsigned char *buff, int len)
{
  int i;
  for (i = 0; i < len; i++)
  {
    printf("%02x ", buff[i]);
    if (((i + 1) % 32) == 0)
      printf("\n");
  }
  if ((i % 32) == 0)
    printf("=============================\n");
  else
    printf("\n=============================\n");
}

void EncryptTest2()
{
  HANDLE keyHandle2;
  HANDLE keyHandle1, DeviceHandle, pSessionHandle = NULL;
  int indexNum, len, ret, select, alog, i, testlen;
  unsigned char ivdata[16], ivdata2[16];
  unsigned char key[16] = {0x40, 0xbb, 0x12, 0xdd, 0x6a, 0x82, 0x73, 0x86,
                           0x7f, 0x35, 0x29, 0xd3, 0x54, 0xb4, 0xa0, 0x26};
  unsigned char data1[16384], endata[16384], data2[16384];
  unsigned char pincode[16] = {"wuxipiico"};
  ECCCipher *endata2;
  ret = SDF_OpenDevice(&DeviceHandle);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenDevice error!return is %08x\n", ret);
    return;
  }
  else
    printf("OpenDevice succeed!the DeviceHandle is %x\n", DeviceHandle);
  ret = SDF_OpenSession(DeviceHandle, &pSessionHandle); 
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenSession error!return is %08x\n", ret);
    ret = SDF_CloseSession(pSessionHandle);
    return;
  }
  else
    printf("OpenSession succeed!the SessionHandle is %x\n", pSessionHandle);
  printf("Please input the test length(0<length<16384):");
  scanf("%d", &testlen);
  printf("Please input the key Index (0<=Index<10000)");
  scanf("%d", &indexNum);
  ret = SDF_ImportKey(pSessionHandle, key, 16, &keyHandle1);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_ImportKey error!return is %08x\n", ret);
    goto Error2return;
  }
  else
    printf("ImportKey succeed!the Handle is %08x\n", keyHandle1);
  ret = SDF_GenerateRandom(pSessionHandle, 16, ivdata);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("Get Random error! and the return is %08x\n ,%08x\n", ret,
           SPII_GetErrorInfo(pSessionHandle));
    goto Error2return;
  }
  memcpy(ivdata2, ivdata, 16);
  len = testlen;
  ret = SDF_GenerateRandom(pSessionHandle, len, data1);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("Get Random error! and the return is %08x\n ,%08x\n", ret,
           SPII_GetErrorInfo(pSessionHandle));
    goto Error2return;
  }
  //	printf("data1 is :\n");
  //	printbuff(data1,len);
  printf("SM1_ECB:----- 1\n");
  printf("SM1_CBC:----- 2\n");
  printf("SM4_ECB: ---- 3\n");
  printf("SM4_CBC: ---- 4\n");
  printf("Please select the Alog:");
  scanf("%d", &select);
  switch (select)
  {
  case 1:
    alog = SGD_SM1_ECB;
    break;
  case 2:
    alog = SGD_SM1_CBC;
    break;
  case 3:
    alog = SGD_SM4_ECB;
    break;
  case 4:
    alog = SGD_SM4_CBC;
    break;
  default:
    alog = SGD_SM1_ECB;
    break;
  }
  ret = SDF_Encrypt(pSessionHandle, keyHandle1, alog, ivdata, data1, testlen,
                    endata, &len);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("Encrypt error! return is %08x ,%08x\n", ret,
           SPII_GetErrorInfo(pSessionHandle));
    goto Error2return;
  }
  else
    printf("Encrypt succeed!\n");
  ret = SDF_Decrypt(pSessionHandle, keyHandle1, alog, ivdata2, endata, len,
                    endata, &len);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("Decrypt error! return is %08x ,%08x\n", ret,
           SPII_GetErrorInfo(pSessionHandle));
    goto Error2return;
  }
  else
    printf("Decrypt succeed!\n");
  if ((memcmp(endata, data1, len) == 0) && (len == testlen))
  {
    printf("compare succeed!\n");
    /*		printf("data1 is :\n");
                    printbuff(data1,len);
                    printf("endata is :\n");
                    printbuff(endata,len);
                    printf("data2 is :\n");
                    printbuff(data2,len);
    */
  }
  else
  {
    printf("compare failed!\n");
    printf("data is :\n");
    printbuff(data1, len);
    printf("endata is :\n");
    printbuff(endata, len);
    //	printf("data2 is :\n");
    //	printbuff(data2,32);
  }
Error2return:
  ret = SDF_DestroyKey(pSessionHandle, keyHandle1);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_DestroyKey error!return is %08x ,%08x\n", ret,
           SPII_GetErrorInfo(pSessionHandle));
  else
    printf("Destory Key1 succeed!keyHandle1 is %08x\n", keyHandle1);
Error1return:
  ret = SDF_CloseSession(pSessionHandle);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_CloseSession error!return is %08x ,%08x\n", ret,
           SPII_GetErrorInfo(0));
  else
    printf("CloseSession succeed!\n");
  ret = SDF_CloseDevice(DeviceHandle);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_CloseDevice error! return is %08x \n", ret);
  else
    printf("CloseDevice succeed!\n");
  return;
}

void EncryptTest1()
{
  unsigned char se[2];
  int i, Alogmod, length, testtime, ret, enlen, sec, msec, ivlen;
  struct timeval now, end;
  float sptime, rate;
  unsigned char *data = NULL, *endata = NULL;
  unsigned char data1[48] = {
      0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
      0x33, 0x22, 0x11, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x86, 0x90, 0x29, 0x3b,
      0x85, 0x0c, 0xfc, 0x4b, 0xc0, 0xb6, 0x54, 0x00, 0xee, 0x92, 0xcb, 0xd3};
  unsigned char sm4d[48] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
  unsigned char endata1[48];
  unsigned char data2[48];
  unsigned char endata2[48];
  unsigned char key3[16];
  unsigned char key[16] = {0x40, 0xbb, 0x12, 0xdd, 0x6a, 0x82, 0x73, 0x86,
                           0x7f, 0x35, 0x29, 0xd3, 0x54, 0xb4, 0xa0, 0x26};
  unsigned char key2[16] = {0x06, 0xcd, 0xd0, 0x41, 0x2d, 0xe2, 0x58, 0x55,
                            0xb0, 0x3a, 0xca, 0xd2, 0x24, 0x75, 0x3d, 0xb9};
  unsigned char IV[16] = {0xe8, 0x3d, 0x17, 0x15, 0xac, 0xf3, 0x48, 0x63,
                          0xac, 0xeb, 0x93, 0xe0, 0xe5, 0xab, 0x8b, 0x90};
  unsigned char IV2[16] = {0xe8, 0x3d, 0x17, 0x15, 0xac, 0xf3, 0x48, 0x63,
                           0xac, 0xeb, 0x93, 0xe0, 0xe5, 0xab, 0x8b, 0x90};
  HANDLE keyHandle1, DeviceHandle, pSessionHandle;
  DEVICEINFO DeInfo;

  ret = SDF_OpenDevice(&DeviceHandle);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenDevice error!return is %08x\n", ret);
    return;
  }
  else
    printf("OpenDevice succeed!the DeviceHandle is %x\n", DeviceHandle);
  ret = SDF_OpenSession(DeviceHandle, &pSessionHandle);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenSession error!return is %08x,%08x \n", ret,
           SPII_GetErrorInfo(pSessionHandle));
    ret = SDF_CloseDevice(DeviceHandle);
    return;
  }
  else
  {
    printf("OpenSession succeed!the SessionHandle is %x\n", pSessionHandle);
  }

  ret = SDF_GetDeviceInfo(pSessionHandle, &DeInfo);

  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_GetDeviceInfo error!return is %08x %08x\n", ret,
           SPII_GetErrorInfo(pSessionHandle));
    goto ErrorReturn;
  }

  if ((DeInfo.SymAlgAbility & SGD_SSF33_CBC) == SGD_SSF33_CBC)
  {
    printf("                 SSF33 ECB ---------------- A\n");
    printf("                 SSF33 CBC ---------------- B\n");
  }
  printf("                 SM1 ECB ------------------ C\n");
  printf("                 SM1 CBC ------------------ D\n");
  printf("                 SM4 ECB ------------------ H\n");
  printf("                 SM4 CBC ------------------ I\n");
  if ((DeInfo.SymAlgAbility & SGD_SM7_CBC) == SGD_SM7_CBC)
  {
    printf("                 SM7 ECB ------------------ J\n");
    printf("                 SM7 CBC ------------------ K\n");
  }
  printf("                 Quit---------------------- Q\n");
  printf("Please input you select:");
  scanf("%s", se);
  if ((strcmp(se, "a") == 0) || (strcmp(se, "A") == 0))
    Alogmod = SGD_SSF33_ECB;
  if ((strcmp(se, "B") == 0) || (strcmp(se, "b") == 0))
    Alogmod = SGD_SSF33_CBC;
  if ((strcmp(se, "c") == 0) || (strcmp(se, "C") == 0))
    Alogmod = SGD_SM1_ECB;
  if ((strcmp(se, "d") == 0) || (strcmp(se, "D") == 0))
    Alogmod = SGD_SM1_CBC;
  if ((strcmp(se, "e") == 0) || (strcmp(se, "E") == 0))
    Alogmod = SGD_3DES_ECB;
  if ((strcmp(se, "f") == 0) || (strcmp(se, "F") == 0))
    Alogmod = SGD_3DES_CBC;
  if ((strcmp(se, "g") == 0) || (strcmp(se, "G") == 0))
    Alogmod = SGD_SM1_OFB;
  if ((strcmp(se, "h") == 0) || (strcmp(se, "H") == 0))
    Alogmod = SGD_SM4_ECB;
  if ((strcmp(se, "i") == 0) || (strcmp(se, "I") == 0))
    Alogmod = SGD_SM4_CBC;
  if ((strcmp(se, "j") == 0) || (strcmp(se, "J") == 0))
    Alogmod = SGD_SM7_ECB;
  if ((strcmp(se, "k") == 0) || (strcmp(se, "K") == 0))
    Alogmod = SGD_SM7_CBC;
  if ((strcmp(se, "Q") == 0) || (strcmp(se, "q") == 0))
    return;
  printf("key is :\n");
  // if(Alogmod==SGD_SSF33_ECB)
  //	printbuff(key2,16);
  // else if(Alogmod==SGD_SM4_ECB)
  if (Alogmod == SGD_SM4_ECB)
  {
    memcpy(data1, sm4d, 16);
    memcpy(key, sm4d, 16);
    printbuff(key, 16);
  }
  else
    printbuff(key, 16);
  printf("data is :\n");
  printbuff(data1, 16);
  if (Alogmod == SGD_SSF33_CBC || Alogmod == SGD_SM1_CBC ||
      Alogmod == SGD_3DES_CBC || Alogmod == SGD_SM1_OFB ||
      Alogmod == SGD_SM4_CBC)
  {
    printf("IV is:\n");
    printbuff(IV, 16);
    ivlen = 16;
  }
  if (Alogmod == SGD_SM7_CBC)
  {
    printf("IV is:\n");
    printbuff(IV, 8);
    ivlen = 8;
  }
  ret = SPII_EncryptEx(pSessionHandle, data1, 16, key, 16, IV, ivlen, Alogmod,
                       endata1, &enlen);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("Encrypt error! the return is %08x,%08x\n", ret,
           SPII_GetErrorInfo(pSessionHandle));
    goto ErrorReturn;
  }
  printf("%d endata is :\n", enlen);
  printbuff(endata1, enlen);
  if (Alogmod != SGD_SM1_OFB)
  {
    ret = SPII_DecryptEx(pSessionHandle, endata1, enlen, key, 16, IV2, ivlen,
                         Alogmod, endata1, &enlen);
    if (ret != SR_SUCCESSFULLY)
    {
      printf("Decrypt error! the return is %08x,%08x\n", ret,
             SPII_GetErrorInfo(pSessionHandle));
      goto ErrorReturn;
    }
    if (memcmp(data1, endata1, enlen) == 0)
      printf("Decrypt succeed!\n");
    else
    {
      printf("data is :\n");
      printbuff(endata1, enlen);
      goto ErrorReturn;
    }
  }
  printf("Please input you test length:");
  scanf("%d", &length);
  printf("Please input you test times:");
  scanf("%d", &testtime);
  data = (unsigned char *)malloc(length);
  if (data == NULL)
  {
    printf("malloc error!\n");
    goto ErrorReturn;
  }
  for (i = 0; i < length; i++)
    data[i] = i;
  endata = (unsigned char *)malloc(length);
  if (endata == NULL)
  {
    free(data);
    printf("malloc error!\n");
    goto ErrorReturn;
  }
  gettimeofday(&now, 0);
  for (i = 0; i < testtime; i++)
  {
    memcpy(IV2, IV, 16);
    ret = SPII_EncryptEx(pSessionHandle, data, length, key, 16, IV2, 16,
                         Alogmod, endata, &enlen);
    if (ret != SR_SUCCESSFULLY)
    {
      printf("EncyptEx error! and the return is %08x,%08x\n", ret,
             SPII_GetErrorInfo(pSessionHandle));
      free(data);
      free(endata);
      goto ErrorReturn;
    }
    if (Alogmod != SGD_SM1_OFB)
    {
      memcpy(IV2, IV, 16);
      ret = SPII_DecryptEx(pSessionHandle, endata, enlen, key, 16, IV2, 16,
                           Alogmod, endata, &enlen);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("DecyptEx error! and the return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
        free(data);
        free(endata);
        goto ErrorReturn;
      }
      if (memcmp(endata, data, enlen) != 0)
      {
        printf("Compare error! \n");
        free(data);
        free(endata);
        goto ErrorReturn;
      }
    }
    if (i % 10000 == 0)
      printf("%d Times test....\n", i);
  }
  gettimeofday(&end, 0);
  if ((end.tv_usec - now.tv_usec) < 0)
  {
    msec = end.tv_usec / 1000.0 + 1000 - now.tv_usec / 1000.0;
    sec = end.tv_sec - now.tv_sec - 1;
  }
  else
  {
    msec = end.tv_usec / 1000.0 - now.tv_usec / 1000.0;
    sec = end.tv_sec - now.tv_sec;
  }
  sptime = ((float)msec / 1000 + sec);
  printf("Spend time is %4.2f sec.\n", sptime);
  if (Alogmod != SGD_SM1_OFB)
    rate = testtime * length * 2 * 8 / 1024;
  else
    rate = testtime * length * 8 / 1024;
  rate = rate / sptime / 1024;
  printf("The rate is %4.2f Mbps!\n", rate);
  free(data);
  free(endata);
ErrorReturn:
  ret = SDF_CloseSession(pSessionHandle);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_CloseSession error!return is %08x ,%08x\n", ret,
           SPII_GetErrorInfo(0));
  else
    printf("CloseSession succeed!\n");
  ret = SDF_CloseDevice(DeviceHandle);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_CloseDevice error! return is %08x \n", ret);
  else
    printf("CloseDevice succeed!\n");
  return;
}

void MACTest()
{
  HANDLE keyHandle2;
  HANDLE keyHandle1, DeviceHandle, pSessionHandle;
  int indexNum, len, ret, select;
  unsigned char mac1[16], mac2[16];
  unsigned char key[16] = {0xCD, 0x46, 0x14, 0x55, 0x8F, 0xC0, 0xA7, 0x8E,
                           0x06, 0xF1, 0xD9, 0x6F, 0xC9, 0x12, 0xC7, 0xAA};
  unsigned char IVdata[16] = {0xE8, 0xE1, 0xA7, 0x51, 0x85, 0x85, 0x44, 0x4C,
                              0xC5, 0xD4, 0xA8, 0xD5, 0xE9, 0x94, 0x5B, 0xB0};
  unsigned char IVdata2[16] = {0xE8, 0xE1, 0xA7, 0x51, 0x85, 0x85, 0x44, 0x4C,
                               0xC5, 0xD4, 0xA8, 0xD5, 0xE9, 0x94, 0x5B, 0xB0};
  unsigned char data[32] = {0xB9, 0x7F, 0x6C, 0x7A, 0x96, 0x30, 0x92, 0xE8,
                            0x87, 0xEA, 0x3E, 0x46, 0xEE, 0x3C, 0x23, 0x5E,
                            0x47, 0xEA, 0xC7, 0x32, 0xD8, 0xF6, 0xB4, 0x24,
                            0x1A, 0xA3, 0x5E, 0xF6, 0xE5, 0xE8, 0x53, 0x18};
  unsigned char sm1mac[16] = {0xa3, 0x33, 0x44, 0xf9, 0xf9, 0x3b, 0xa6, 0xe5,
                              0x69, 0x04, 0x4a, 0x70, 0x7f, 0xb8, 0x0e, 0x44};
  unsigned char sm4mac[16] = {0xBB, 0xC0, 0xEC, 0x13, 0x1F, 0x10, 0xBE, 0xB0,
                              0x9E, 0x71, 0x25, 0x76, 0x2A, 0x1D, 0xA2, 0x68};
  unsigned char sm7mac[8] = {0xea, 0xba, 0x28, 0xa3, 0xe9, 0xe2, 0xdc, 0xba};

  ret = SDF_OpenDevice(&DeviceHandle);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenDevice error!return is %08x\n", ret);
    return;
  }
  else
    printf("OpenDevice succeed!the DeviceHandle is %x\n", DeviceHandle);
  ret = SDF_OpenSession(DeviceHandle, &pSessionHandle);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenSession error!return is %08x\n", ret);
    ret = SDF_CloseSession(pSessionHandle);
    return;
  }
  else
    printf("OpenSession succeed!the SessionHandle is %x\n", pSessionHandle);
  /*	ret=SDF_GenerateRandom(pSessionHandle,16,IVdata);
          if(ret!=SR_SUCCESSFULLY)
          {
                  printf("SDF_GenerateRandom error!return is %08x\n",ret);
                  SDF_CloseSession(pSessionHandle);
                  SDF_CloseDevice(DeviceHandle);
          }
          else
                  printf("SDF_GenerateRandom succeed!the IV is :\n");
                  printbuff(IVdata,16);
          ret=SDF_GenerateRandom(pSessionHandle,16,key);
          if(ret!=SR_SUCCESSFULLY)
          {
                  printf("SDF_GenerateRandom error!return is %08x\n",ret);
                  SDF_CloseSession(pSessionHandle);
                  SDF_CloseDevice(DeviceHandle);
          }
          else
                  printf("SDF_GenerateRandom succeed!the key is :\n");
                  printbuff(key,16);*/
  ret = SDF_ImportKey(pSessionHandle, key, 16, &keyHandle1);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_ImportKey error!return is %08x\n", ret);
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
  }
  else
    printf("ImportKey succeed!the Handle is %08x\n", keyHandle1);
  ret = SDF_ImportKey(pSessionHandle, key, 16, &keyHandle2);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_ImportKey error!return is %08x\n", ret);
    SDF_DestroyKey(pSessionHandle, keyHandle1);
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
  }
  else
    printf("ImportKey succeed!the Handle is %08x\n", keyHandle2);
  ret = SDF_CalculateMAC(pSessionHandle, keyHandle1, SGD_SM1_MAC, IVdata, data,
                         32, mac1, &len);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("MAC with key1 error! return is %08x\n", ret);
    SDF_DestroyKey(pSessionHandle, keyHandle1);
    SDF_DestroyKey(pSessionHandle, keyHandle2);
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return;
  }
  else
    printf("MAC with SM1 succeed!\n");
  if (memcmp(mac1, sm1mac, 16) != 0)
  {
    printf("sm1 std data is :");
    printbuff(sm1mac, 16);
  }
  else
    printf("SM1 Mac Compare with std data succeed!\n");
  printf("Mac1 is :\n");
  printbuff(mac1, len);
  ret = SDF_CalculateMAC(pSessionHandle, keyHandle2, SGD_SM4_MAC, IVdata2, data,
                         32, mac2, &len);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("MAC with key2 error! return is %08x\n", ret);
    SDF_DestroyKey(pSessionHandle, keyHandle1);
    SDF_DestroyKey(pSessionHandle, keyHandle2);
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return;
  }
  else
    printf("MAC with SM4 succeed!\n");
  if (memcmp(mac2, sm4mac, 16) != 0)
  {
    printf("sm4 std data is :");
    printbuff(sm4mac, 16);
  }
  else
    printf("SM4 Mac Compare with std data succeed!\n");
  printf("Mac2 is :\n");
  printbuff(mac2, 16);
  ret = SDF_CalculateMAC(pSessionHandle, keyHandle2, SGD_SM7_MAC, IVdata2, data,
                         32, mac2, &len);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("MAC with key2 error! return is %08x\n", ret);
    SDF_DestroyKey(pSessionHandle, keyHandle1);
    SDF_DestroyKey(pSessionHandle, keyHandle2);
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return;
  }
  else
    printf("MAC with SM7 succeed!\n");
  if (memcmp(mac2, sm7mac, 8) != 0)
  {
    printf("sm7 std data is :");
    printbuff(sm7mac, 8);
  }
  else
    printf("SM7 Mac Compare with std data succeed!\n");
  printf("Mac2 is :\n");
  printbuff(mac2, 8);
  ret = SDF_DestroyKey(pSessionHandle, keyHandle1);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_DestroyKey error!return is %08x\n", ret);
  else
    printf("Destory Key1 succeed!keyHandle1 is %08x\n", keyHandle1);
  ret = SDF_DestroyKey(pSessionHandle, keyHandle2);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_DestroyKey error!return is %08x\n", ret);
  else
    printf("Destory Key2 succeed!keyHandle2 is %08x\n", keyHandle2);
  ret = SDF_CloseSession(pSessionHandle);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_CloseSession error!return is %08x\n", ret);
  else
    printf("CloseSession succeed!\n");
  ret = SDF_CloseDevice(DeviceHandle);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_CloseDevice error! return is %08x \n", ret);
  else
    printf("CloseDevice succeed!\n");
}

void HASHTest()
{
  HANDLE keyHandle2;
  HANDLE keyHandle1, DeviceHandle, pSessionHandle;
  int indexNum, len, ret, select, alog, flag = 0, i, enlen, relen;
  unsigned char data[2560], data1[1024], endata[4096], data2[1024], IVdata[16],
      key[16];
  unsigned char sm3std[64] = {
      0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63,
      0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62,
      0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61,
      0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
      0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63,
      0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64};
  ECCrefPublicKey pk;
  ret = SDF_OpenDevice(&DeviceHandle);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenDevice error!return is %08x\n", ret);
    return;
  }
  else
    printf("OpenDevice succeed!the DeviceHandle is %x\n", DeviceHandle);
  ret = SDF_OpenSession(DeviceHandle, &pSessionHandle);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenSession error!return is %08x\n", ret);
    ret = SDF_CloseSession(pSessionHandle);
    return;
  }
  else
    printf("OpenSession succeed!the SessionHandle is %x\n", pSessionHandle);
  ret = SDF_GenerateRandom(pSessionHandle, 1024, data);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_GenerateRandom error!return is %08x,%08x\n", ret,
           SPII_GetErrorInfo(pSessionHandle));
    SDF_CloseSession(pSessionHandle);
    SDF_CloseDevice(DeviceHandle);
  }
  else
    printf("SDF_GenerateRandom succeed! pSessionHandle is %x \n",
           pSessionHandle);
  ret = SDF_ImportKey(pSessionHandle, data, 16, &keyHandle1);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_ImportKey error!return is %08x,%08x\n", ret,
           SPII_GetErrorInfo(pSessionHandle));
  else
    printf("ImportKey succeed!the Handle is %08x\n", keyHandle1);
  printf("Please input the Hash Data:(1:Input By Hand 2: Random )");
  scanf("%d", &select);
  if (select == 1)
  {
    printf("Please input:");
    scanf("%s", endata);
    len = strlen(endata);
    len = 64;
    memcpy(endata, sm3std, 64);
  }
  else
  {
    // len=100;
    // ret=SDF_GenerateRandom(pSessionHandle,len,endata);
    // len=4096;
    printf("Please input the test len:");
    scanf("%d", &len);
    memset(endata, 0, len);
    ret = SDF_GenerateRandom(pSessionHandle, len, endata);
  }
  printbuff(endata, len);
  while (1)
  {
    printf("          SM3 with ID --------------------- 1\n");
    printf("          SM3 without ID ------------------ 2\n");
    printf("          SHA1 ---------------------------- 3\n");
    printf("          SHA256--------------------------- 4\n");
    printf("          SHA512--------------------------- 5\n");
    printf("          Quit ---------------------------- 0\n");
    printf("    please input your select:");
    scanf("%d", &select);
    switch (select)
    {
    case 1:
      alog = SGD_SM3;
      flag = 1;
      printf("SM3 with ID hash:\n");
      break;
    case 2:
      alog = SGD_SM3;
      flag = 0;
      printf("SM3 without ID hash:\n");
      break;
    case 3:
      alog = SGD_SHA1;
      flag = 0;
      printf("SHA1:\n");
      break;
    case 4:
      alog = SGD_SHA256;
      flag = 0;
      printf("SHA256:\n");
      break;
    case 5:
      alog = SGD_SHA512;
      flag = 0;
      printf("SHA512:\n");
      break;
    case 0:
    default:
      ret = SDF_DestroyKey(pSessionHandle, keyHandle1);
      if (ret != SR_SUCCESSFULLY)
        printf("SDF_DestroyKey error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
      else
        printf("DestoryKey succeed!\n");
      ret = SDF_CloseSession(pSessionHandle);
      if (ret != SR_SUCCESSFULLY)
        printf("SDF_CloseSession error!return is %08x\n", ret);
      else
        printf("CloseSession succeed!\n");
      ret = SDF_CloseDevice(DeviceHandle);
      if (ret != SR_SUCCESSFULLY)
        printf("SDF_CloseDevice error! return is %08x \n", ret);
      else
        printf("CloseDevice succeed!\n");
      return;
    }
    if (flag)
    {
      ret = SDF_GenerateRandom(pSessionHandle, 16, data);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_GenerateRandom error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
      }
      else
        printf("SDF_GenerateRandom succeed!the ID is \n");
      printbuff(data, 16);
      ret = SDF_ExportEncPublicKey_ECC(pSessionHandle, 1, &pk);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_ExportEncPublicKey_ECC error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return;
      }
      ret = SDF_HashInit(pSessionHandle, SGD_SM3, &pk, data, 16);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_HashInit error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return;
      }
      printf("SDF_HashInit Succeed!\n");
      ret = SDF_HashUpdate(pSessionHandle, endata, len);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_HashUpdate error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return;
      }
      printf("SDF_HashUpdata 1 succeed!\n");
      ret = SDF_HashFinal(pSessionHandle, data1, &enlen);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_HashFinal error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return;
      }
      printf("Hash is :\n");
      printbuff(data1, enlen);
    }
    else
    {
      for (i = 1; i <= len; i++)
      {
        ret = SDF_HashInit(pSessionHandle, alog, NULL, NULL, 0);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SDF_HashInit error!return is %08,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          SDF_CloseSession(pSessionHandle);
          SDF_CloseDevice(DeviceHandle);
          return;
        }
        printf("SDF_HashInit Succeed!\n");
        ret = SDF_HashUpdate(pSessionHandle, endata, i);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SDF_HashUpdate error!return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          SDF_CloseSession(pSessionHandle);
          SDF_CloseDevice(DeviceHandle);
          return;
        }
        printf("SDF_HashUpdata 1 succeed!\n");
        ret = SDF_HashFinal(pSessionHandle, data1, &enlen);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SDF_HashFinal error!return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          SDF_CloseSession(pSessionHandle);
          SDF_CloseDevice(DeviceHandle);
          return;
        }
        printf("%i len Data Hash is :\n", i);
        printbuff(data1, enlen);
        pii_sm3_soft(endata, i, data2);
        if (memcmp(data1, data2, enlen) != 0)
        {
          printf("%d len data compare with soft error!the soft is :\n", i);
          printbuff(data2, enlen);
          break;
        }
      }
    }
  }
}

void SymAlgoTest()
{
  int select;
  while (1)
  {
    printf("          SM1&SM4 with key ---------------- 1\n");
    printf("          SM1&SM4 without key ------------- 2\n");
    printf("          Mac ----------------------------- 3\n");
    printf("          Hash ---------------------------- 4\n");
    printf("          Quit ---------------------------- 0\n");
    printf("    please input your select:");
    scanf("%d", &select);
    switch (select)
    {
    case 1:
      EncryptTest1();
      break;
    case 2:
      EncryptTest2();
      break;
    case 3:
      MACTest();
      break;
    case 4:
      HASHTest();
      break;
    case 0:
    default:
      return;
    }
  }
}

void Otherope()
{
  int select, ret;
  unsigned int pinlen, oldpinlen;
  HANDLE DeviceHandle;
  unsigned char Pin[256], oldPin[256];
  ret = SDF_OpenDevice(&DeviceHandle);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenDevice error!return is %08x\n", ret);
    return;
  }
  else
    printf("OpenDevice succeed!the DeviceHandle is %x\n", DeviceHandle);
  ret = SPII_ResetModule(DeviceHandle);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_ResetModule error,return is %08x!\n", ret);
  else
    printf("ResetModule succeed!\n");
  SDF_CloseDevice(DeviceHandle);
  return;
}

void GenerateKeyInCard(HANDLE pSessionHandle)
{
  int select, select2, ret, len, indexNum, keybits, relen;
  unsigned char pin[100] = {"wuxipiico"};
  unsigned char key[16] = {0x40, 0xbb, 0x12, 0xdd, 0x6a, 0x82, 0x73, 0x86,
                           0x7f, 0x35, 0x29, 0xd3, 0x54, 0xb4, 0xa0, 0x26};
  unsigned char keypairfile[1000], enkey[1000];
  unsigned char ensk[1000], padkey[256];
  ECCrefPrivateKey envk;
  ECCrefPublicKey enpk, signpk;
  ECCCipher *enR;
  //	FILE *fp;
  while (1)
  {
    select = 0;
    printf("       Generate ECC User KeyPair ------------- 1\n");
    printf("       Generate USER KEK --------------------- 2\n");
#if 0		
		printf("       Generate SM9 KeyPair ------------------ 3\n");
#endif
    printf("       Quit ---------------------------------- 0\n");
    printf("    please input your select:");
    scanf("%d", &select);
    switch (select)
    {
    case 1:

      for (indexNum = 1; indexNum < KEYPAIR_MAX_INDEX; indexNum++)
      {
        ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, indexNum, pin,
                                           strlen(pin));
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SDF_GetPrivateKeyAccessRight error! return is %08x,%08x\n",
                 ret, SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        ret = SPII_GenerateSignKeyPair_ECC(pSessionHandle, indexNum);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "Generate %d Sign ECC KeyPair failed and return is %08x,%08x\n",
              indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
          SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
          break;
        }
#if 0
							ret=SPII_GenerateEncKeyPair_ECC(pSessionHandle,indexNum);
							if(ret!=SR_SUCCESSFULLY)
							{
								printf("Generate %d enc ECC KeyPair failed and return is %08x,%08x\n",indexNum,ret,SPII_GetErrorInfo(pSessionHandle));
								SDF_ReleasePrivateKeyAccessRight(pSessionHandle,indexNum);
								break;
								}
#else
        ret = SDF_ExportSignPublicKey_ECC(pSessionHandle, indexNum, &signpk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_ExportSignPublicKey_ECC %d failed and return is "
              "%08x,%08x\n",
              indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
          SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
          break;
        }
        ret = SDF_GenerateKeyPair_ECC(pSessionHandle, SGD_SM2_3, 256, &enpk,
                                      &envk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_GenerateKeyPair_ECC %d failed and return is %08x,%08x\n",
              indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
          SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
          break;
        }
        ret = SDF_GenerateRandom(pSessionHandle, 16, keypairfile);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_GenerateKeyPair_ECC %d failed and return is %08x,%08x\n",
              indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
          SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
          break;
        }
        enR = malloc(sizeof(ECCCipher) + 16);
        ret = SDF_ExternalEncrypt_ECC(pSessionHandle, SGD_SM2_3, &signpk,
                                      keypairfile, 16, enR);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_ExternalEncrypt_ECC %d failed and return is %08x,%08x\n",
              indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
          SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
          free(enR);
          break;
        }
        ret = SPII_EncryptEx(pSessionHandle, envk.K, 64, keypairfile, 16,
                             NULL, 0, SGD_SM4_ECB, enkey, &len);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_ExternalEncrypt_ECC %d failed and return is %08x,%08x\n",
              indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
          SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
          free(enR);
          break;
        }
        ret = SPII_NVELOPEDKEY(pSessionHandle, indexNum, SGD_SM2_3,
                               SGD_SM4_ECB, enR, &enpk, enkey, len);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_NVELOPEDKEY %d failed and return is %08x,%08x\n",
                 indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
          SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
          free(enR);
          break;
        }
        free(enR);
#endif
        ret = SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_ReleasePrivateKeyAccessRight error! return is %08x "
              ",%08x\n",
              ret, SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        PrintPer("SM2 Key Pair Generate all", KEYPAIR_MAX_INDEX, indexNum);
      }
      break;

    case 2:
      for (indexNum = 0; indexNum < 1024; indexNum++)
      {
        ret = SPII_GenerateKEK(pSessionHandle, indexNum, 16);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_GenerateKEK %d error! return is %08x ,%08x\n",
                 indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        PrintPer("KEK  Generate all", 1024, indexNum);
      }
      break;
#if 0				
			case 3:
				ret=SM9KepairGenerateTest(pSessionHandle);
				if(ret!=SR_SUCCESSFULLY)
					{
						printf("SM9KepairGenerateTest error!\n");
						}
						break;
#endif
    case 0:
    default:
      return;
    }
  }
}
/*
void KeyAdmin()
{
        int len,select,alog,testtime,i,Permission,ret;
        unsigned int status,filelen,enkeylen;
        unsigned char enkey[2000],pin[100],skeyid[50];
        unsigned char yes[2];
        unsigned char keypairfile[2000];
        int rsaflag=1,kekflag=1,eccflag=1,UserID,Ukeyflag,fileoffset;
        FILE *fp;
        unsigned short CardFlag;
        ECCrefPublicKey  enpk,signpk,entpk;
        ECCrefPrivateKey	envk,signvk;
        ECCCipher *enR,*enmk;
        ECCSignature signR;
        HANDLE DeviceHandle,pSessionHandle;
        status=SDF_OpenDevice(&DeviceHandle);
        if(status!=SR_SUCCESSFULLY)
        {
                printf("SDF_OpenDevice error!return is %08x\n",status);
                return;
        }
        status=SDF_OpenSession(DeviceHandle,&pSessionHandle);
        if(status!=SR_SUCCESSFULLY)
        {
                printf("SDF_OpenSession error!return is %08x\n",status);
                SDF_CloseDevice(DeviceHandle);
                return;
        }
        printf("Please input the Ukey registing mod:0 online;1 outline:");
        scanf("%d",&Ukeyflag);
        while(1)
        {
                printf("      RegistUkey ---------------- 1\n");
                printf("      LoadinCard ---------------- 2\n");
                printf("      Key back ------------------ 3\n");
                printf("      Key store ----------------- 4\n");
                printf("      Quit ---------------------- 0\n");
                printf("Please input you select:");
                scanf("%d",&select);
                switch(select)
                {
                        case 1:
                                        printf("Please input User Type:1
Adminstrator;2 Adminstrator2;3 Operator1;4 Operator2:"); scanf("%d",&UserID);
                                        if(UserID<1||UserID>4)
                                                {
                                                        printf("User type
error!\n"); break;
                                                        }
                                        if(!Ukeyflag)
                                                        {
                                                                printf("Please
Press 'Y'or 'y' when you connet the UsbKey on EncryptCard:"); scanf("%s",yes);
                                                                if(strcmp(yes,"y")!=0&&strcmp(yes,"Y")!=0)
                                                                        break;
                                                                ret=SPII_Regsvr(pSessionHandle,Ukeyflag,NULL,0,NULL,NULL,UserID);
                                                                if(ret!=SR_SUCCESSFULLY)
                                                                        {
                                                                        printf("Regsvr
%d Usb Key failed,return is %08x
%08x",UserID,ret,SPII_GetErrorInfo(pSessionHandle)); break;
                                                                }
                                                                else
                                                                        printf("Regsvr
%d Usb Key succeed!",UserID);
                                                        }
                                        else
                                                {
                                                                memset(&envk,0,sizeof(ECCrefPrivateKey));
                                                                memset(&signvk,0,sizeof(ECCrefPrivateKey));
                                                                memset(&enpk,0,sizeof(ECCrefPublicKey));
                                                                memset(&signpk,0,sizeof(ECCrefPublicKey));
                                                                ret=SDF_GenerateKeyPair_ECC(pSessionHandle,SGD_SM2_1,256,&enpk,&envk);
                                                                if(ret!=SR_SUCCESSFULLY)
                                                                        {
                                                                        printf("Card
Generate enc Key failed and return is %08x\n",ret); break;
                                                                }
                                                                printeccpk("enc
pk",&enpk); printeccvk("enc vk",&envk);
                                                                        ret=SDF_GenerateKeyPair_ECC(pSessionHandle,SGD_SM2_1,256,&signpk,&signvk);
                                                                if(ret!=SR_SUCCESSFULLY)
                                                                        {
                                                                                printf("Card Generate sign Key failed and return is %08x\n",ret);
                                                                                break;
                                                                        }
                                                                printeccpk("sign
pk",&signpk); printeccvk("sign vk",&signvk);
                                                                ret=SPII_Regsvr(pSessionHandle,Ukeyflag,NULL,0,&enpk,&signpk,UserID);
                                                                if(ret!=SR_SUCCESSFULLY)
                                                                        {
                                                                                printf("Regsvr %d User failed,return is %08x %08x",UserID,ret,SPII_GetErrorInfo(pSessionHandle));
                                                                                break;
                                                                }
                                                                else
                                                                        {
                                                                                        printf("Regsvr %d User succeed!\n",UserID);
                                                                                        sprintf(skeyid,"TestUserKeyFile%d.bin",UserID);
                                                                                        filelen=0;
                                                                                        memcpy(keypairfile,&enpk,sizeof(ECCrefPublicKey));
                                                                                        filelen=filelen+sizeof(ECCrefPublicKey);
                                                                                        memcpy(keypairfile+filelen,&envk,sizeof(ECCrefPrivateKey));
                                                                                        filelen=filelen+sizeof(ECCrefPrivateKey);
                                                                                        memcpy(keypairfile+filelen,&signpk,sizeof(ECCrefPublicKey));
                                                                                        filelen=filelen+sizeof(ECCrefPublicKey);
                                                                                        memcpy(keypairfile+filelen,&signvk,sizeof(ECCrefPrivateKey));
                                                                                        filelen=filelen+sizeof(ECCrefPrivateKey);
                                                                                        ret=wrtiefile(skeyid,keypairfile,filelen);
                                                                                        if(ret!=0)
                                                                                                {
                                                                                                        printf("write %d TestUserKeyFile to file error!\n",UserID);
                                                                                                        }
                                                                }
                                                }
                                break;
                        case 2:
                                if(!Ukeyflag)
                                        {
                                                printf("Please Press 'Y'or 'y'
when you connet the UsbKey on EncryptCard:"); scanf("%s",yes);
                                                if(strcmp(yes,"y")!=0&&strcmp(yes,"Y")!=0)
                                                        break;
                                                ret=SPII_LoadinStepF(pSessionHandle,Ukeyflag,NULL,0,NULL,NULL,NULL,NULL);
                                                if(ret!=SR_SUCCESSFULLY)
                                                        {
                                                                printf("SPII_LoadinStepF
failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle)); break;
                                                                }
                                                ret=SPII_LoadinStepS(pSessionHandle,Ukeyflag,NULL,0,NULL,NULL);
                                                if(ret!=SR_SUCCESSFULLY)
                                                        {
                                                                printf("SPII_LoadinStepS
failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle)); break;
                                                                }
                                                else
                                                        printf("Load in Card
Succeed!\n");
                                                }
                                else
                                        {
                                                printf("Please input the test
ID(1~4):"); scanf("%d",&UserID); sprintf(skeyid,"TestUserKeyFile%d.bin",UserID);
                                                ret=readfile(skeyid,keypairfile,&filelen);
                                                if(ret!=0)
                                                        {
                                                                printf("read %d
TestUserKeyFile to file error!\n",i); break;
                                                                }
                                                memcpy(&enpk,keypairfile,sizeof(ECCrefPublicKey));
                                                memcpy(&envk,keypairfile+sizeof(ECCrefPublicKey),sizeof(ECCrefPrivateKey));
                                                memcpy(&signpk,keypairfile+sizeof(ECCrefPublicKey)+sizeof(ECCrefPrivateKey),sizeof(ECCrefPublicKey));
                                                memcpy(&signvk,keypairfile+2*sizeof(ECCrefPublicKey)+sizeof(ECCrefPrivateKey),sizeof(ECCrefPrivateKey));

                                                enR=malloc(sizeof(ECCCipher)+32);
                                                enmk=malloc(sizeof(ECCCipher)+32);
                                                printeccpk("sign pk",&signpk);
                                                printeccvk("sign vk",&signvk);
                                                ret=SPII_LoadinStepF(pSessionHandle,Ukeyflag,NULL,0,&signpk,&entpk,enR,enmk);
                                                if(ret!=SR_SUCCESSFULLY)
                                                        {
                                                                printf("SPII_LoadinStepF
failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
                                                                free(enR);
                                                                free(enmk);
                                                                break;
                                                        }
                                                        else
                                                                printf("SPII_LoadinStepF
Succeed!\n"); printeccpk("enc pk",&enpk); printeccvk("enc vk",&envk);
                                                ret=SDF_ExternalDecrypt_ECC(pSessionHandle,SGD_SM2_3,&envk,enR,pin,&len);
                                                if(ret!=SR_SUCCESSFULLY)
                                                        {
                                                                printf("SDF_ExternalDecrypt_ECC
enR failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
                                                                free(enR);
                                                                free(enmk);
                                                                break;
                                                        }
                                                if(len!=32)
                                                        {
                                                                printf("SDF_ExternalDecrypt_ECC
enR data length error,return length is \n",len); free(enR); free(enmk); break;
                                                        }
                                                else
                                                        printf("SDF_ExternalDecrypt_ECC
enR Succeed!\n");
                                                        ret=SDF_ExternalSign_ECC(pSessionHandle,SGD_SM2_1,&signvk,pin,len,&signR);
                                                        if(ret!=SR_SUCCESSFULLY)
                                                        {
                                                                printf("SDF_ExternalSign_ECC
R failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
                                                                free(enR);
                                                                free(enmk);
                                                                break;
                                                        }
                                                        else
                                                        printf("SDF_ExternalSign_ECC
Succeed!\n");
                                                        ret=SDF_ExternalDecrypt_ECC(pSessionHandle,SGD_SM2_3,&envk,enmk,pin,&len);
                                                if(ret!=SR_SUCCESSFULLY)
                                                        {
                                                                printf("SDF_ExternalDecrypt_ECC
enmk failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
                                                                free(enR);
                                                                free(enmk);
                                                                break;
                                                        }
                                                if(len!=32)
                                                        {
                                                                printf("SDF_ExternalDecrypt_ECC
enmk data length error,return length is \n",len); free(enR); free(enmk); break;
                                                        }
                                                        else
                                                                printf("SDF_ExternalDecrypt_ECC
enmk Succeed!\n"); printeccpk("temp pk",&entpk);
                                                        ret=SDF_ExternalEncrypt_ECC(pSessionHandle,SGD_SM2_3,&entpk,pin,len,enmk);
                                                        if(ret!=SR_SUCCESSFULLY)
                                                        {
                                                                printf("SDF_ExternalEncrypt_ECC
mk failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
                                                                free(enR);
                                                                free(enmk);
                                                                break;
                                                        }
                                                        else
                                                        {
                                                                printf("SDF_ExternalEncrypt_ECC
mk Succeed!\n"); printbuff(enmk->x+32,32); printbuff(enmk->y+32,32);
                                                                printbuff(enmk->M,32);
                                                                printbuff(enmk->C,enmk->L);
                                                        }
                                                        ret=SPII_LoadinStepS(pSessionHandle,Ukeyflag,NULL,0,&signR,enmk);
                                                if(ret!=SR_SUCCESSFULLY)
                                                                printf("SPII_LoadinStepS
failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle)); else
                                                                printf("Load in
Card Succeed!\n"); free(enR); free(enmk);
                                                }
                                break;
                        case 3:
                                if(!Ukeyflag)
                                        {
                                                for(UserID=1;UserID<4;UserID++)
                                                        {
                                                                printf("Please
Press 'Y'or 'y' when you connet the UsbKey on EncryptCard:"); scanf("%s",yes);
                                                                if(strcmp(yes,"y")!=0&&strcmp(yes,"Y")!=0)
                                                                        break;
                                                                ret=SPII_BackUpBK(pSessionHandle,Ukeyflag,NULL,0,UserID,NULL,NULL);
                                                                if(ret!=SR_SUCCESSFULLY)
                                                                {
                                                                        printf("SPII_BackUpBK
%d failed and return is
%08x,%08x\n",UserID,ret,SPII_GetErrorInfo(pSessionHandle)); break;
                                                                }
                                                                else
                                                                        printf("SPII_BackUpBK
%d succeed!\n",UserID);
                                                                }
                                                }
                                else
                                        {
                                                enmk=malloc(sizeof(ECCCipher)+48);
                                                for(UserID=1;UserID<4;UserID++)
                                                        {
                                                                ret=SDF_GenerateKeyPair_ECC(pSessionHandle,SGD_SM2_1,256,&enpk,&envk);
                                                                if(ret!=SR_SUCCESSFULLY)
                                                                                        printf("Card Generate enc Key failed and return is %08x\n",ret);
                                                                else
                                                                        {
                                                                                sprintf(skeyid,"SPII_BackUpBK%d.bin",UserID);
                                                                                ret=readfile(skeyid,keypairfile,&filelen);
                                                                                if(ret!=0)
                                                                                        {
                                                                                                printf("write %d Read PK VK from file error!\n",UserID);
                                                                                                free(enmk);
                                                                                                break;
                                                                                                }
                                                                                        memcpy(&enpk,keypairfile,sizeof(ECCrefPublicKey));
                                                                                        memcpy(&envk,keypairfile+sizeof(ECCrefPublicKey),sizeof(ECCrefPrivateKey));
                                                                                }
                                                                                ret=SPII_BackUpBK(pSessionHandle,Ukeyflag,NULL,0,UserID,&enpk,enmk);
                                                                                if(ret!=SR_SUCCESSFULLY)
                                                                                                        {
                                                                                                        printf("SPII_BackUpBK  %d failed and return is %08x %08x\n",UserID,ret,SPII_GetErrorInfo(pSessionHandle));
                                                                                                        free(enmk);
                                                                                                        break;
                                                                                                }
                                                                                                        sprintf(skeyid,"SPII_BackUpBK%d.bin",UserID);
                                                                                                        filelen=0;
                                                                                                        memcpy(keypairfile,&enpk,sizeof(ECCrefPublicKey));
                                                                                                        filelen=filelen+sizeof(ECCrefPublicKey);
                                                                                                        memcpy(keypairfile+filelen,&envk,sizeof(ECCrefPrivateKey));
                                                                                                        filelen=filelen+sizeof(ECCrefPrivateKey);
                                                                                                        memcpy(keypairfile+filelen,enmk,sizeof(ECCCipher)+48);
                                                                                                        filelen=filelen+sizeof(ECCCipher)+48;
                                                                                                        ret=wrtiefile(skeyid,keypairfile,filelen);
                                                                                                        if(ret!=0)
                                                                                                                {
                                                                                                                        printf("write %d SPII_BackUpBK to file error!\n",UserID);
                                                                                                                        }
                                                                                        printf("SPII_BackUpBK  %d succeed!\n",UserID);


                                                        }
                                                                free(enmk);
                                                }
                                for(i=0;i<=KEYPAIR_MAX_INDEX;i++)
                                {
                                //	PrintPer("Key Pair BackUp
all",KEYPAIR_MAX_INDEX,i);

                                        ret=SPII_BackUpECCEnc(pSessionHandle,i,keypairfile,&filelen);
                                        if(status!=0)
                                        {
                                                printf("backup %d EnEccKeyPair
error,and return is %08x\n",i,status); return;
                                        }
                                        sprintf(skeyid,"KeyBack/EEkeypair%d.bin",i);
                                        ret=wrtiefile(skeyid,keypairfile,filelen);
                                        if(ret!=0)
                                                {
                                                        printf("write %d ECC Enc
KeyPair to file error!\n",i); return;
                                                        }
                                        ret=SPII_BackUpECCSign(pSessionHandle,i,keypairfile,&filelen);
                                        if(status!=0)
                                        {
                                                printf("backup %d SignEccKeyPair
error,and return is %08x\n",i,status); return;
                                        }
                                        sprintf(skeyid,"KeyBack/ESkeypair%d.bin",i);
                                        ret=wrtiefile(skeyid,keypairfile,filelen);
                                        if(ret!=0)
                                                {
                                                        printf("write %d ECC
Sign KeyPair to file error!\n",i); return;
                                                        }
                                        ret=SPII_BackUpKEK(pSessionHandle,i,keypairfile,&filelen);
                                        if(status!=0)
                                        {
                                                printf("backup %d KEK error,and
return is %08x\n",i,status); return;
                                        }
                                        sprintf(skeyid,"KeyBack/KEK%d.bin",i);
                                        ret=wrtiefile(skeyid,keypairfile,filelen);
                                        if(ret!=0)
                                                {
                                                        printf("write %d KEK to
file error!\n",i); return;
                                                        }
                                        ret=SPII_BackUpEnMkSM9(pSessionHandle,i,keypairfile,&filelen);
                                        if(status!=0)
                                        {
                                                printf("backup %d EnMkSM9
error,and return is %08x\n",i,status); return;
                                        }
                                        sprintf(skeyid,"KeyBack/SEMkeypair%d.bin",i);
                                        ret=wrtiefile(skeyid,keypairfile,filelen);
                                        if(ret!=0)
                                                {
                                                        printf("write %d KEK to
file error!\n",i); return;
                                                        }
                                        ret=SPII_BackUpSigMkSM9(pSessionHandle,i,keypairfile,&filelen);
                                        if(status!=0)
                                        {
                                                printf("backup %d EnMkSM9
error,and return is %08x\n",i,status); return;
                                        }
                                        sprintf(skeyid,"KeyBack/SSMkeypair%d.bin",i);
                                        ret=wrtiefile(skeyid,keypairfile,filelen);
                                        if(ret!=0)
                                                {
                                                        printf("write %d KEK to
file error!\n",i); return;
                                                        }
                                        ret=SPII_BackUpEnUkSM9(pSessionHandle,i,keypairfile,&filelen);
                                        if(status!=0)
                                        {
                                                printf("backup %d EnMkSM9
error,and return is %08x\n",i,status); return;
                                        }
                                        sprintf(skeyid,"KeyBack/SEUkeypair%d.bin",i);
                                        ret=wrtiefile(skeyid,keypairfile,filelen);
                                        if(ret!=0)
                                                {
                                                        printf("write %d KEK to
file error!\n",i); return;
                                                        }
                                        ret=SPII_BackUpSigUkSM9(pSessionHandle,i,keypairfile,&filelen);
                                        if(status!=0)
                                        {
                                                printf("backup %d EnMkSM9
error,and return is %08x\n",i,status); return;
                                        }
                                        sprintf(skeyid,"KeyBack/SSUkeypair%d.bin",i);
                                        ret=wrtiefile(skeyid,keypairfile,filelen);
                                        if(ret!=0)
                                                {
                                                        printf("write %d KEK to
file error!\n",i); return;
                                                        }
                                }

                                printf("Backup Key succeed!\n");
                                break;
                        case 4:
                                        if(!Ukeyflag)
                                        {
                                                for(UserID=1;UserID<3;UserID++)
                                                        {
                                                                printf("Please
Press 'Y'or 'y' when you connet the UsbKey on EncryptCard:"); scanf("%s",yes);
                                                                if(strcmp(yes,"y")!=0&&strcmp(yes,"Y")!=0)
                                                                        break;
                                                                ret=SPII_RestoreBK(pSessionHandle,Ukeyflag,NULL,0,NULL);
                                                                if(ret!=SR_SUCCESSFULLY)
                                                                {
                                                                        printf("SPII_RestoreBK
%d failed and return is
%08x,%08x\n",UserID,ret,SPII_GetErrorInfo(pSessionHandle)); break;
                                                                }
                                                                else
                                                                        printf("SPII_RestoreBK
%d succeed!\n",UserID);
                                                                }
                                                }
                                        else
                                                {
                                                        ret=SPII_GenerateTmpPK(pSessionHandle,&entpk);
                                                        if(ret!=SR_SUCCESSFULLY)
                                                                {
                                                                        printf("SPII_GenerateTmpPK
failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle)); break;
                                                                }
                                                                else
                                                                        printf("SPII_GenerateTmpPK
succeed!\n"); enmk=malloc(sizeof(ECCCipher)+48); for(UserID=1;UserID<2;UserID++)
                                                        {

                                                                                sprintf(skeyid,"SPII_BackUpBK%d.bin",UserID);
                                                                                ret=readfile(skeyid,keypairfile,&filelen);
                                                                                if(ret!=0)
                                                                                        {
                                                                                                printf("write %d Read PK VK from file error!\n",UserID);
                                                                                                free(enmk);
                                                                                                break;
                                                                                                }
                                                                                memcpy(&enpk,keypairfile,sizeof(ECCrefPublicKey));
                                                                                        memcpy(&envk,keypairfile+sizeof(ECCrefPublicKey),sizeof(ECCrefPrivateKey));
                                                                                memcpy(enmk,keypairfile+sizeof(ECCrefPublicKey)+sizeof(ECCrefPrivateKey),sizeof(ECCCipher)+48);
                                                                                ret=SDF_ExternalDecrypt_ECC(pSessionHandle,SGD_SM2_3,&envk,enmk,pin,&len);
                                                                                if(ret!=SR_SUCCESSFULLY)
                                                                                        {
                                                                                                printf("SDF_ExternalDecrypt_ECC enmk failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
                                                                                                free(enmk);
                                                                                                break;
                                                                                        }
                                                                                if(len!=48)
                                                                                        {
                                                                                                printf("SDF_ExternalDecrypt_ECC enmk data length error,return length is \n",len);
                                                                                                free(enmk);
                                                                                                break;
                                                                                        }
                                                                                        else
                                                                                                printf("SDF_ExternalDecrypt_ECC enmk Succeed!\n");
                                                                                        ret=SDF_ExternalEncrypt_ECC(pSessionHandle,SGD_SM2_3,&entpk,pin,len,enmk);
                                                                                        if(ret!=SR_SUCCESSFULLY)
                                                                                        {
                                                                                                printf("SDF_ExternalEncrypt_ECC mk failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
                                                                                                free(enmk);
                                                                                                break;
                                                                                        }
                                                                                        else
                                                                                                printf("SDF_ExternalEncrypt_ECC mk Succeed!\n");
                                                                                        ret=SPII_RestoreBK(pSessionHandle,Ukeyflag,NULL,0,enmk);
                                                                                        if(ret!=SR_SUCCESSFULLY)
                                                                                        {
                                                                                                printf("SPII_RestoreBK mk failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
                                                                                                free(enmk);
                                                                                                break;
                                                                                        }
                                                                                        else
                                                                                                printf("SPII_RestoreBK %d succeed!\n",UserID);


                                                                }
                                                                free(enmk);
                                                        }
                                for(i=0;i<=KEYPAIR_MAX_INDEX;i++)
                                {
                                        PrintPer("Key Pair ReStore
all",KEYPAIR_MAX_INDEX,i);

                                        sprintf(skeyid,"KeyBack/EEkeypair%d.bin",i);
                                        ret=readfile(skeyid,keypairfile,&filelen);
                                        if(ret!=0)
                                                {
                                                        printf("read %d ECC Enc
KeyPair to file error!\n",i); break;
                                                        }
                                        ret=SPII_RestoreECCEnc(pSessionHandle,i,keypairfile,filelen);
                                        if(status!=0)
                                        {
                                                printf("Restore %d EnEccKeyPair
error,and return is %08x\n",i,status); break;
                                        }

                                                sprintf(skeyid,"KeyBack/ESkeypair%d.bin",i);
                                        ret=readfile(skeyid,keypairfile,&filelen);
                                        if(ret!=0)
                                                {
                                                        printf("read %d ECC Sign
KeyPair to file error!\n",i); break;
                                                        }
                                        ret=SPII_RestoreECCSign(pSessionHandle,i,keypairfile,filelen);
                                        if(status!=0)
                                        {
                                                printf("Restore %d
SignEccKeyPair error,and return is %08x\n",i,status); break;
                                        }



                                        sprintf(skeyid,"KeyBack/KEK%d.bin",i);
                                        ret=readfile(skeyid,keypairfile,&filelen);
                                        if(ret!=0)
                                                {
                                                        printf("read %d KEK to
file error!\n",i); break;
                                                        }
                                        ret=SPII_RestoreKEK(pSessionHandle,i,keypairfile,filelen);
                                        if(status!=0)
                                        {
                                                printf("Restore %d KEK error,and
return is %08x\n",i,status); break;
                                        }

                                sprintf(skeyid,"KeyBack/SEMkeypair%d.bin",i);
                                        ret=readfile(skeyid,keypairfile,&filelen);
                                        if(ret!=0)
                                                {
                                                        printf("read %d KEK to
file error!\n",i); break;
                                                        }
                                        ret=SPII_RestoreEnMkSM9(pSessionHandle,i,keypairfile,filelen);
                                        if(status!=0)
                                        {
                                                printf("Restore %d EnMkSM9
error,and return is %08x\n",i,status); break;
                                        }

                                sprintf(skeyid,"KeyBack/SSMkeypair%d.bin",i);
                                        ret=readfile(skeyid,keypairfile,&filelen);
                                        if(ret!=0)
                                                {
                                                        printf("read %d KEK to
file error!\n",i); break;
                                                        }
                                        ret=SPII_RestoreSigMkSM9(pSessionHandle,i,keypairfile,filelen);
                                        if(status!=0)
                                        {
                                                printf("Restore %d EnMkSM9
error,and return is %08x\n",i,status); break;
                                        }

                                        sprintf(skeyid,"KeyBack/SEUkeypair%d.bin",i);

                                        ret=readfile(skeyid,keypairfile,&filelen);
                                        if(ret!=0)
                                                {
                                                        printf("read %d KEK to
file error!\n",i); break;
                                                        }
                                        ret=SPII_RestoreEnUkSM9(pSessionHandle,i,keypairfile,filelen);
                                        if(status!=0)
                                        {
                                                printf("Restore %d EnMkSM9
error,and return is %08x\n",i,status); break;
                                        }

                                        sprintf(skeyid,"KeyBack/SSUkeypair%d.bin",i);
                                        ret=readfile(skeyid,keypairfile,&filelen);
                                        if(ret!=0)
                                                {
                                                        printf("write %d KEK to
file error!\n",i); break;
                                                        }
                                        ret=SPII_RestoreSigUkSM9(pSessionHandle,i,keypairfile,filelen);
                                        if(status!=0)
                                        {
                                                printf("Restore %d EnMkSM9
error,and return is %08x\n",i,status); break;
                                        }
                                }

                                printf("Restore Key succeed!\n");
                                break;


                        case 0:

                        default:

                                SDF_CloseSession(pSessionHandle);

                                SDF_CloseDevice(DeviceHandle);

                                return;

                }

        }



}
*/
void Status_Init()
{
  int len, select, alog, testtime, i, Permission, ret;
  unsigned int status, filelen, enkeylen;
  unsigned char enkey[2000], oldpin[100], skeyid[50];
  unsigned char yes[2];
  unsigned char pin[100] = {"wuxipiico"};
  unsigned char xpin[100] = {"wuxipiico"};
  unsigned char keypairfile[2000];
  int indexNum = 1, UserID, Ukeyflag, fileoffset;
  FILE *fp;
  unsigned short CardFlag;
  ECCrefPublicKey enpk, signpk, entpk;
  ECCrefPrivateKey envk, signvk;
  ECCCipher *enR, *enmk;
  ECCSignature signR;
  HANDLE DeviceHandle, pSessionHandle;
  status = SDF_OpenDevice(&DeviceHandle);
  if (status != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenDevice error!return is %08x\n", status);
    return;
  }
  status = SDF_OpenSession(DeviceHandle, &pSessionHandle);
  if (status != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenSession error!return is %08x\n", status);
    SDF_CloseDevice(DeviceHandle);
    return;
  }
  printf("Please input the Ukey registing mod:0 online;1 outline:");
  scanf("%d", &Ukeyflag);
  //	Ukeyflag=0;
  while (1)
  {
    printf("       LoadinCard ---------------------------  1\n");
    printf("       Generate Device Key Pairs ------------- 2\n");
    printf("       Restore Device Key Pairs -------------- 3\n");
    printf("       Init to Ready status ------------------ 4\n");
    printf("       Quit ---------------------------------- 0\n");
    printf("    please input your select:");
    scanf("%d", &select);
    switch (select)
    {
    case 1:
      if (!Ukeyflag)
      {
        printf(
            "Please Press 'Y'or 'y' when you connet the UsbKey on "
            "EncryptCard:");
        scanf("%s", yes);
        if (strcmp(yes, "y") != 0 && strcmp(yes, "Y") != 0)
          break;
        memset(enkey, 0, 50);
        printf("Please input the Pin of Ukey:");
        scanf("%s", enkey);
        ret = SPII_LoadinStepF(pSessionHandle, Ukeyflag, enkey, strlen(enkey),
                               NULL, NULL, NULL, NULL);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_LoadinStepF failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        ret = SPII_LoadinStepS(pSessionHandle, Ukeyflag, enkey, strlen(enkey),
                               NULL, NULL);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_LoadinStepS failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        else
          printf("Load in Card Succeed!");
      }
      else
      {
        printf("Please input the test ID(1~4):");
        scanf("%d", &UserID);
        sprintf(skeyid, "TestUserKeyFile%d.bin", UserID);
        ret = readfile(skeyid, keypairfile, &filelen);
        if (ret != 0)
        {
          printf("read %d TestUserKeyFile to file error!\n", i);
          break;
        }
        memcpy(&enpk, keypairfile, sizeof(ECCrefPublicKey));
        memcpy(&envk, keypairfile + sizeof(ECCrefPublicKey),
               sizeof(ECCrefPrivateKey));
        memcpy(
            &signpk,
            keypairfile + sizeof(ECCrefPublicKey) + sizeof(ECCrefPrivateKey),
            sizeof(ECCrefPublicKey));
        memcpy(&signvk,
               keypairfile + 2 * sizeof(ECCrefPublicKey) +
                   sizeof(ECCrefPrivateKey),
               sizeof(ECCrefPrivateKey));

        enR = malloc(sizeof(ECCCipher) + 32);
        enmk = malloc(sizeof(ECCCipher) + 32);
        printeccpk("sign pk", &signpk);
        printeccvk("sign vk", &signvk);
        ret = SPII_LoadinStepF(pSessionHandle, Ukeyflag, NULL, 0, &signpk,
                               &entpk, enR, enmk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_LoadinStepF failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        else
          printf("SPII_LoadinStepF Succeed!\n");
        printeccpk("enc pk", &enpk);
        printeccvk("enc vk", &envk);
        ret = SDF_ExternalDecrypt_ECC(pSessionHandle, SGD_SM2_3, &envk, enR,
                                      pin, &len);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_ExternalDecrypt_ECC enR failed and return is %08x,%08x\n",
              ret, SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        if (len != 32)
        {
          printf(
              "SDF_ExternalDecrypt_ECC enR data length error,return length "
              "is \n",
              len);
          free(enR);
          free(enmk);
          break;
        }
        else
          printf("SDF_ExternalDecrypt_ECC enR Succeed!\n");
        ret = SDF_ExternalSign_ECC(pSessionHandle, SGD_SM2_1, &signvk, pin,
                                   len, &signR);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SDF_ExternalSign_ECC R failed and return is %08x,%08x\n",
                 ret, SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        else
          printf("SDF_ExternalSign_ECC Succeed!\n");
        ret = SDF_ExternalDecrypt_ECC(pSessionHandle, SGD_SM2_3, &envk, enmk,
                                      pin, &len);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_ExternalDecrypt_ECC enmk failed and return is %08x,%08x\n",
              ret, SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        if (len != 32)
        {
          printf(
              "SDF_ExternalDecrypt_ECC enmk data length error,return length "
              "is \n",
              len);
          free(enR);
          free(enmk);
          break;
        }
        else
          printf("SDF_ExternalDecrypt_ECC enmk Succeed!\n");
        printeccpk("temp pk", &entpk);
        ret = SDF_ExternalEncrypt_ECC(pSessionHandle, SGD_SM2_3, &entpk, pin,
                                      len, enmk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_ExternalEncrypt_ECC mk failed and return is %08x,%08x\n",
              ret, SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        else
        {
          printf("SDF_ExternalEncrypt_ECC mk Succeed!\n");
          printbuff(enmk->x + 32, 32);
          printbuff(enmk->y + 32, 32);
          printbuff(enmk->M, 32);
          printbuff(enmk->C, enmk->L);
        }
        ret =
            SPII_LoadinStepS(pSessionHandle, Ukeyflag, NULL, 0, &signR, enmk);
        if (ret != SR_SUCCESSFULLY)
          printf("SPII_LoadinStepS failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
        else
          printf("Load in Card Succeed!\n");
        free(enR);
        free(enmk);
      }
      break;
    case 2:
      indexNum = 0;
      ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, indexNum, xpin,
                                         strlen(xpin));
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_GetPrivateKeyAccessRight error! return is %08x,%08x\n",
               ret, SPII_GetErrorInfo(pSessionHandle));
        break;
      }
      ret = SPII_GenerateSignKeyPair_ECC(pSessionHandle, indexNum);
      if (ret != SR_SUCCESSFULLY)
      {
        printf(
            "Generate %d Sign ECC KeyPair failed and return is %08x,%08x\n",
            indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
        SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
        break;
      }
#if 0
							ret=SPII_GenerateEncKeyPair_ECC(pSessionHandle,indexNum);
							if(ret!=SR_SUCCESSFULLY)
							{
								printf("Generate %d Enc ECC KeyPair failed and return is %08x,%08x\n",indexNum,ret,SPII_GetErrorInfo(pSessionHandle));
								SDF_ReleasePrivateKeyAccessRight(pSessionHandle,indexNum);
								break;
							}
#else
      ret = SDF_ExportSignPublicKey_ECC(pSessionHandle, indexNum, &signpk);
      if (ret != SR_SUCCESSFULLY)
      {
        printf(
            "SDF_ExportSignPublicKey_ECC %d failed and return is %08x,%08x\n",
            indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
        SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
        break;
      }
      ret = SDF_GenerateKeyPair_ECC(pSessionHandle, SGD_SM2_3, 256, &enpk,
                                    &envk);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_GenerateKeyPair_ECC %d failed and return is %08x,%08x\n",
               indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
        SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
        break;
      }
      ret = SDF_GenerateRandom(pSessionHandle, 16, keypairfile);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_GenerateKeyPair_ECC %d failed and return is %08x,%08x\n",
               indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
        SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
        break;
      }
      enR = malloc(sizeof(ECCCipher) + 16);
      ret = SDF_ExternalEncrypt_ECC(pSessionHandle, SGD_SM2_3, &signpk,
                                    keypairfile, 16, enR);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_ExternalEncrypt_ECC %d failed and return is %08x,%08x\n",
               indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
        SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
        free(enR);
        break;
      }
      ret = SPII_EncryptEx(pSessionHandle, envk.K, 64, keypairfile, 16, NULL,
                           0, SGD_SM4_ECB, enkey, &len);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_ExternalEncrypt_ECC %d failed and return is %08x,%08x\n",
               indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
        SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
        free(enR);
        break;
      }
      ret = SPII_NVELOPEDKEY(pSessionHandle, indexNum, SGD_SM2_3, SGD_SM4_ECB,
                             enR, &enpk, enkey, len);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SPII_NVELOPEDKEY %d failed and return is %08x,%08x\n",
               indexNum, ret, SPII_GetErrorInfo(pSessionHandle));
        SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
        free(enR);
        break;
      }
      free(enR);
#endif
      ret = SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);
      if (ret != SR_SUCCESSFULLY)
      {
        printf(
            "SDF_ReleasePrivateKeyAccessRight error! return is %08x ,%08x\n",
            ret, SPII_GetErrorInfo(pSessionHandle));
        break;
      }
      printf(
          "Generate Device Sign ECC Key Pair and Import Enc ECC Key Pair "
          "Succeed!\n");
      break;
      break;
    case 3:
      if (!Ukeyflag)
      {
        ret = SPII_GenerateTmpPK(pSessionHandle, &entpk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_GenerateTmpPK failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        else
          printf("SPII_GenerateTmpPK succeed!\n");
        /*	printf("Please Press 'Y'or 'y' when you connet the UsbKey on
           EncryptCard:"); scanf("%s",yes);
                if(strcmp(yes,"y")!=0&&strcmp(yes,"Y")!=0)
                        break;
                */
        memset(enkey, 0, 50);
        UserID = 1;
        printf("Please input the Pin of %d Ukey:", UserID);
        scanf("%s", enkey);
        ret = SPII_RestoreBK(pSessionHandle, Ukeyflag, enkey, strlen(enkey),
                             NULL);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_RestoreBK %d failed and return is %08x,%08x\n", UserID,
                 ret, SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        else
          printf("SPII_RestoreBK %d succeed!\n", UserID);
        /*	printf("Please Press 'Y'or 'y' when you connet the UsbKey on
           EncryptCard:"); scanf("%s",yes);
                if(strcmp(yes,"y")!=0&&strcmp(yes,"Y")!=0)
                        break;*/
        memset(enkey, 0, 50);
        UserID++;
        printf("Please input the Pin of %d Ukey:", UserID);
        scanf("%s", enkey);
        ret = SPII_RestoreBK(pSessionHandle, Ukeyflag, enkey, strlen(enkey),
                             NULL);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_RestoreBK %d failed and return is %08x,%08x\n", UserID,
                 ret, SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        else
          printf("SPII_RestoreBK %d succeed!\n", UserID);
      }
      else
      {
        ret = SPII_GenerateTmpPK(pSessionHandle, &entpk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_GenerateTmpPK failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          free(enmk);
          return;
        }
        else
          printf("SPII_GenerateTmpPK succeed!\n");

        for (UserID = 1; UserID < 3; UserID++)
        {
          enmk = malloc(sizeof(ECCCipher) + 48);
          sprintf(skeyid, "SPII_BackUpBK%d.bin", UserID);
          ret = readfile(skeyid, keypairfile, &filelen);
          if (ret != 0)
          {
            printf("write %d Read PK VK from file error!\n", UserID);
            free(enmk);
            return;
          }
          memcpy(&enpk, keypairfile, sizeof(ECCrefPublicKey));
          memcpy(&envk, keypairfile + sizeof(ECCrefPublicKey),
                 sizeof(ECCrefPrivateKey));
          memcpy(enmk,
                 keypairfile + sizeof(ECCrefPublicKey) +
                     sizeof(ECCrefPrivateKey),
                 sizeof(ECCCipher) + 48);
          ret = SDF_ExternalDecrypt_ECC(pSessionHandle, SGD_SM2_3, &envk,
                                        enmk, pin, &len);
          if (ret != SR_SUCCESSFULLY)
          {
            printf(
                "SDF_ExternalDecrypt_ECC enmk failed and return is "
                "%08x,%08x\n",
                ret, SPII_GetErrorInfo(pSessionHandle));
            free(enmk);
            return;
          }
          if (len != 48)
          {
            printf(
                "SDF_ExternalDecrypt_ECC enmk data length error,return "
                "length is %d\n",
                len);
            free(enmk);
            return;
          }
          else
            printf("SDF_ExternalDecrypt_ECC enmk Succeed!\n");
          ret = SDF_ExternalEncrypt_ECC(pSessionHandle, SGD_SM2_3, &entpk,
                                        pin, len, enmk);
          if (ret != SR_SUCCESSFULLY)
          {
            printf(
                "SDF_ExternalEncrypt_ECC mk failed and return is %08x,%08x\n",
                ret, SPII_GetErrorInfo(pSessionHandle));
            free(enmk);
            return;
          }
          else
            printf("SDF_ExternalEncrypt_ECC mk Succeed!\n");
          ret = SPII_RestoreBK(pSessionHandle, Ukeyflag, NULL, 0, enmk);
          if (ret != SR_SUCCESSFULLY)
          {
            printf("SPII_RestoreBK mk failed and return is %08x,%08x\n", ret,
                   SPII_GetErrorInfo(pSessionHandle));
            free(enmk);
            return;
          }
          else
            printf("SPII_RestoreBK %d succeed!\n", UserID);
          free(enmk);
        }
      }
      printf("the Restore starting.....\n");
      i = 0;
      sprintf(skeyid, "KeyBack/EEkeypair%d.bin", i);
      ret = readfile(skeyid, keypairfile, &filelen);
      if (ret != 0)
      {
        printf("read %d ECC Enc KeyPair to file error!\n", i);
        return;
      }
      ret = SPII_RestoreECCEnc(pSessionHandle, i, keypairfile, filelen);
      if (status != 0)
      {
        printf("Restore %d EnEccKeyPair error,and return is %08x\n", i,
               status);
        return;
      }

      sprintf(skeyid, "KeyBack/ESkeypair%d.bin", i);
      ret = readfile(skeyid, keypairfile, &filelen);
      if (ret != 0)
      {
        printf("read %d ECC Sign KeyPair to file error!\n", i);
        return;
      }
      ret = SPII_RestoreECCSign(pSessionHandle, i, keypairfile, filelen);
      if (status != 0)
      {
        printf("Restore %d SignEccKeyPair error,and return is %08x\n", i,
               status);
        return;
      }
      printf("Restore Device Key succeed!\n");
      break;

      break;
    case 4:

      ret = SPII_ISTORS(DeviceHandle);
      if (ret != 0)
        printf("SPII_ISTORS failed,and return is %08x \n", ret);
      else
        printf("SPII_ISTORS succeed\n");
      break;
    case 0:
    default:
      SDF_CloseSession(pSessionHandle);
      SDF_CloseDevice(DeviceHandle);
      return;
    }
  }
}

void Status_Factor()
{
  int len, select, alog, testtime, i, ret, indexNum;
  unsigned int status, filelen, enkeylen;
  unsigned char enkey[2000], skeyid[50];
  unsigned char pin[100] = {"wuxipiico"};
  unsigned char yes[2];
  unsigned char keypairfile[2000];
  int rsaflag = 1, kekflag = 1, eccflag = 1, UserID, Ukeyflag, fileoffset;
  FILE *fp;
  unsigned short CardFlag;
  ECCrefPublicKey enpk, signpk, entpk;
  ECCrefPrivateKey envk, signvk;
  ECCCipher *enR, *enmk;
  ECCSignature signR;
  HANDLE DeviceHandle, pSessionHandle;
  status = SDF_OpenDevice(&DeviceHandle);
  if (status != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenDevice error!return is %08x\n", status);
    return;
  }
  status = SDF_OpenSession(DeviceHandle, &pSessionHandle);
  if (status != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenSession error!return is %08x\n", status);
    SDF_CloseDevice(DeviceHandle);
    return;
  }
  printf("Please input the Ukey registing mod:0 online;1 outline:");
  scanf("%d", &Ukeyflag);
  //	Ukeyflag=0;
  while (1)
  {
    printf("====You can Do these Opension in Factory Status====\n");
    printf("      RegistUkey ---------------------------- 1\n");
    printf("      LoadinCard ---------------------------- 2\n");
    printf("      Init_File_System ---------------------- 3\n");
    printf("      INIT_KeyContain ----------------------- 4\n");
    printf("      Encrypt Card Set Zero ----------------- 5\n");
    printf("      Factory to Init status ---------------- 6\n");
    printf("     Quit ----------------------------------- 0 0\n");
    printf("Please input you select:");
    scanf("%d", &select);
    switch (select)
    {
    case 1:
      printf(
          "Please input User Type:1 Adminstrator;2 Adminstrator2;3 "
          "Operator1;4 Operator2:");
      scanf("%d", &UserID);
      if (UserID < 1 || UserID > 4)
      {
        printf("User type error!\n");
        break;
      }
      if (!Ukeyflag)
      {
        /*	printf("Please Press 'Y'or 'y' when you connet the UsbKey on
           EncryptCard:"); scanf("%s",yes);
                if(strcmp(yes,"y")!=0&&strcmp(yes,"Y")!=0)
                        break;*/
        memset(enkey, 0, 50);
        printf("Please input the Pin of Ukey:");
        scanf("%s", enkey);
        len = strlen(enkey);
        ret = SPII_Regsvr(pSessionHandle, Ukeyflag, enkey, len, NULL, NULL,
                          UserID);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("Regsvr %d Usb Key failed,return is %08x %08x", UserID, ret,
                 SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        else
          printf("Regsvr %d Usb Key succeed!", UserID);
      }
      else
      {
        memset(&envk, 0, sizeof(ECCrefPrivateKey));
        memset(&signvk, 0, sizeof(ECCrefPrivateKey));
        memset(&enpk, 0, sizeof(ECCrefPublicKey));
        memset(&signpk, 0, sizeof(ECCrefPublicKey));
        ret = SDF_GenerateKeyPair_ECC(pSessionHandle, SGD_SM2_1, 256, &enpk,
                                      &envk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("Card Generate enc Key failed and return is %08x\n", ret);
          break;
        }
        printeccpk("enc pk", &enpk);
        printeccvk("enc vk", &envk);
        ret = SDF_GenerateKeyPair_ECC(pSessionHandle, SGD_SM2_1, 256, &signpk,
                                      &signvk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("Card Generate sign Key failed and return is %08x\n", ret);
          break;
        }
        printeccpk("sign pk", &signpk);
        printeccvk("sign vk", &signvk);
        ret = SPII_Regsvr(pSessionHandle, Ukeyflag, NULL, 0, &enpk, &signpk,
                          UserID);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("Regsvr %d User failed,return is %08x %08x", UserID, ret,
                 SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        else
        {
          printf("Regsvr %d User succeed!\n", UserID);
          sprintf(skeyid, "TestUserKeyFile%d.bin", UserID);
          filelen = 0;
          memcpy(keypairfile, &enpk, sizeof(ECCrefPublicKey));
          filelen = filelen + sizeof(ECCrefPublicKey);
          memcpy(keypairfile + filelen, &envk, sizeof(ECCrefPrivateKey));
          filelen = filelen + sizeof(ECCrefPrivateKey);
          memcpy(keypairfile + filelen, &signpk, sizeof(ECCrefPublicKey));
          filelen = filelen + sizeof(ECCrefPublicKey);
          memcpy(keypairfile + filelen, &signvk, sizeof(ECCrefPrivateKey));
          filelen = filelen + sizeof(ECCrefPrivateKey);
          ret = wrtiefile(skeyid, keypairfile, filelen);
          if (ret != 0)
          {
            printf("write %d TestUserKeyFile to file error!\n", UserID);
          }
        }
      }
      break;
    case 2:
      if (!Ukeyflag)
      {
        printf(
            "Please Press 'Y'or 'y' when you connet the UsbKey on "
            "EncryptCard:");
        scanf("%s", yes);
        if (strcmp(yes, "y") != 0 && strcmp(yes, "Y") != 0)
          break;
        memset(enkey, 0, 50);
        printf("Please input the Pin of Ukey:");
        scanf("%s", enkey);
        ret = SPII_LoadinStepF(pSessionHandle, Ukeyflag, enkey, strlen(enkey),
                               NULL, NULL, NULL, NULL);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_LoadinStepF failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        ret = SPII_LoadinStepS(pSessionHandle, Ukeyflag, enkey, strlen(enkey),
                               NULL, NULL);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_LoadinStepS failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        else
          printf("Load in Card Succeed!");
      }
      else
      {
        printf("Please input the test ID(1~4):");
        scanf("%d", &UserID);
        sprintf(skeyid, "TestUserKeyFile%d.bin", UserID);
        ret = readfile(skeyid, keypairfile, &filelen);
        if (ret != 0)
        {
          printf("read %d TestUserKeyFile to file error!\n", i);
          break;
        }
        memcpy(&enpk, keypairfile, sizeof(ECCrefPublicKey));
        memcpy(&envk, keypairfile + sizeof(ECCrefPublicKey),
               sizeof(ECCrefPrivateKey));
        memcpy(
            &signpk,
            keypairfile + sizeof(ECCrefPublicKey) + sizeof(ECCrefPrivateKey),
            sizeof(ECCrefPublicKey));
        memcpy(&signvk,
               keypairfile + 2 * sizeof(ECCrefPublicKey) +
                   sizeof(ECCrefPrivateKey),
               sizeof(ECCrefPrivateKey));

        enR = malloc(sizeof(ECCCipher) + 32);
        enmk = malloc(sizeof(ECCCipher) + 32);
        printeccpk("sign pk", &signpk);
        printeccvk("sign vk", &signvk);
        ret = SPII_LoadinStepF(pSessionHandle, Ukeyflag, NULL, 0, &signpk,
                               &entpk, enR, enmk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_LoadinStepF failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        else
          printf("SPII_LoadinStepF Succeed!\n");
        printeccpk("enc pk", &enpk);
        printeccvk("enc vk", &envk);
        ret = SDF_ExternalDecrypt_ECC(pSessionHandle, SGD_SM2_3, &envk, enR,
                                      pin, &len);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_ExternalDecrypt_ECC enR failed and return is %08x,%08x\n",
              ret, SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        if (len != 32)
        {
          printf(
              "SDF_ExternalDecrypt_ECC enR data length error,return length "
              "is \n",
              len);
          free(enR);
          free(enmk);
          break;
        }
        else
          printf("SDF_ExternalDecrypt_ECC enR Succeed!\n");
        ret = SDF_ExternalSign_ECC(pSessionHandle, SGD_SM2_1, &signvk, pin,
                                   len, &signR);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SDF_ExternalSign_ECC R failed and return is %08x,%08x\n",
                 ret, SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        else
          printf("SDF_ExternalSign_ECC Succeed!\n");
        ret = SDF_ExternalDecrypt_ECC(pSessionHandle, SGD_SM2_3, &envk, enmk,
                                      pin, &len);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_ExternalDecrypt_ECC enmk failed and return is %08x,%08x\n",
              ret, SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        if (len != 32)
        {
          printf(
              "SDF_ExternalDecrypt_ECC enmk data length error,return length "
              "is \n",
              len);
          free(enR);
          free(enmk);
          break;
        }
        else
          printf("SDF_ExternalDecrypt_ECC enmk Succeed!\n");
        printeccpk("temp pk", &entpk);
        ret = SDF_ExternalEncrypt_ECC(pSessionHandle, SGD_SM2_3, &entpk, pin,
                                      len, enmk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_ExternalEncrypt_ECC mk failed and return is %08x,%08x\n",
              ret, SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        else
        {
          printf("SDF_ExternalEncrypt_ECC mk Succeed!\n");
          printbuff(enmk->x + 32, 32);
          printbuff(enmk->y + 32, 32);
          printbuff(enmk->M, 32);
          printbuff(enmk->C, enmk->L);
        }
        ret =
            SPII_LoadinStepS(pSessionHandle, Ukeyflag, NULL, 0, &signR, enmk);
        if (ret != SR_SUCCESSFULLY)
          printf("SPII_LoadinStepS failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
        else
          printf("Load in Card Succeed!\n");
        free(enR);
        free(enmk);
      }
      break;
    case 3:
      ret = SPII_Init_FileSystem(pSessionHandle);
      if (ret != SR_SUCCESSFULLY)
        printf("SPII_Init_FileSystem error! return is %08x ,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
      else
        printf("SPII_Init_FileSystem succeed!\n");
      break;
    case 4:
      printf(
          "Please Press '1' to Init All KeyContains ,Press '0' to Init One "
          "KeyContains:");
      scanf("%d", &ret);
      if (!ret)
      {
        printf("Please input the keyID(0<=KeyID<1024):");
        scanf("%d", &indexNum);
        ret = SPII_Init_KeyContainer(DeviceHandle, indexNum);
        if (ret != SR_SUCCESSFULLY)
          printf("SPII_Init_KeyContainer error! return is %08x \n", ret);
        else
          printf("SPII_Init_KeyContainer succeed!\n");
      }
      else
      {
        for (i = 0; i < KEYPAIR_MAX_INDEX; i++)
        {
          ret = SPII_Init_KeyContainer(DeviceHandle, i);
          if (ret != SR_SUCCESSFULLY)
          {
            printf("SPII_Init_KeyContainer %d error! return is %08x \n", i,
                   ret);
            break;
          }
          PrintPer("Init KeyContainer", KEYPAIR_MAX_INDEX, i);
        }
      }
      break;

    case 5:
      printf(
          "This Operation will set EncryptCard to Zero,and Should Regist "
          "Operator in Factory Status!\nAre you sure?Y/N:");
      scanf("%s", yes);
      if (strcmp(yes, "y") != 0 && strcmp(yes, "Y") != 0)
        break;
      else
      {
        ret = SPII_Init_Device(DeviceHandle);
        if (ret != SR_SUCCESSFULLY)
          printf("Init Card failed and return is %08x\n", ret);
        else
          printf("Init Succeed!\n");
      }
      break;
    case 6:

      ret = SPII_FSTOIS(DeviceHandle);
      if (ret != 0)
        printf("SPII_FSTOIS failed,and return is %08x \n", ret);
      else
        printf("SPII_FSTOIS succeed\n");
      break;
    case 0:
    default:
      SDF_CloseSession(pSessionHandle);
      SDF_CloseDevice(DeviceHandle);
      return;
    }
  }
}

void Status_Ready()
{
  int len, select, alog, testtime, i, Permission, ret;
  unsigned int status, filelen, enkeylen;
  unsigned char enkey[2000], pin[100], oldpin[100], skeyid[50];
  unsigned char yes[2];
  unsigned char keypairfile[2000];
  int indexNum = 1, UserID, Ukeyflag, fileoffset;
  FILE *fp;
  unsigned short CardFlag;
  ECCrefPublicKey enpk, signpk, entpk;
  ECCrefPrivateKey envk, signvk;
  ECCCipher *enR, *enmk;
  ECCSignature signR;
  HANDLE DeviceHandle, pSessionHandle;
  status = SDF_OpenDevice(&DeviceHandle);
  if (status != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenDevice error!return is %08x\n", status);
    return;
  }
  status = SDF_OpenSession(DeviceHandle, &pSessionHandle);
  if (status != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenSession error!return is %08x\n", status);
    SDF_CloseDevice(DeviceHandle);
    return;
  }
  printf("Please input the Ukey registing mod:0 online;1 outline:");
  scanf("%d", &Ukeyflag);
  //	Ukeyflag=0;
  while (1)
  {
    printf("       LoadinCard ---------------------------  1\n");
    printf("       GenerateKey in Card ------------------- 2\n");
    printf("       BackUpKeyPair ------------------------- 3\n");
    printf("       RestorKeyPair ------------------------- 4\n");
    printf("       ChangePrivateKeyAccessRight ----------- 5\n");
    printf("       InitCard(Set Zero)--- ----------------- 6\n");
    // printf("       Change Ukey Pin ----------------------- 7\n");
    printf("       Ready to Init status ------------------ 8\n");
    printf("     quit ------------------------------------ 0\n");
    printf("    please input your select:");
    scanf("%d", &select);
    switch (select)
    {
    case 1:
      if (!Ukeyflag)
      {
        printf(
            "Please Press 'Y'or 'y' when you connet the UsbKey on "
            "EncryptCard:");
        scanf("%s", yes);
        if (strcmp(yes, "y") != 0 && strcmp(yes, "Y") != 0)
          break;
        memset(enkey, 0, 50);
        printf("Please input the Pin of Ukey:");
        scanf("%s", enkey);
        ret = SPII_LoadinStepF(pSessionHandle, Ukeyflag, enkey, strlen(enkey),
                               NULL, NULL, NULL, NULL);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_LoadinStepF failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        ret = SPII_LoadinStepS(pSessionHandle, Ukeyflag, enkey, strlen(enkey),
                               NULL, NULL);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_LoadinStepS failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        else
          printf("Load in Card Succeed!");
      }
      else
      {
        printf("Please input the test ID(1~4):");
        scanf("%d", &UserID);
        sprintf(skeyid, "TestUserKeyFile%d.bin", UserID);
        ret = readfile(skeyid, keypairfile, &filelen);
        if (ret != 0)
        {
          printf("read %d TestUserKeyFile to file error!\n", i);
          break;
        }
        memcpy(&enpk, keypairfile, sizeof(ECCrefPublicKey));
        memcpy(&envk, keypairfile + sizeof(ECCrefPublicKey),
               sizeof(ECCrefPrivateKey));
        memcpy(
            &signpk,
            keypairfile + sizeof(ECCrefPublicKey) + sizeof(ECCrefPrivateKey),
            sizeof(ECCrefPublicKey));
        memcpy(&signvk,
               keypairfile + 2 * sizeof(ECCrefPublicKey) +
                   sizeof(ECCrefPrivateKey),
               sizeof(ECCrefPrivateKey));

        enR = malloc(sizeof(ECCCipher) + 32);
        enmk = malloc(sizeof(ECCCipher) + 32);
        printeccpk("sign pk", &signpk);
        printeccvk("sign vk", &signvk);
        ret = SPII_LoadinStepF(pSessionHandle, Ukeyflag, NULL, 0, &signpk,
                               &entpk, enR, enmk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_LoadinStepF failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        else
          printf("SPII_LoadinStepF Succeed!\n");
        printeccpk("enc pk", &enpk);
        printeccvk("enc vk", &envk);
        ret = SDF_ExternalDecrypt_ECC(pSessionHandle, SGD_SM2_3, &envk, enR,
                                      pin, &len);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_ExternalDecrypt_ECC enR failed and return is %08x,%08x\n",
              ret, SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        if (len != 32)
        {
          printf(
              "SDF_ExternalDecrypt_ECC enR data length error,return length "
              "is \n",
              len);
          free(enR);
          free(enmk);
          break;
        }
        else
          printf("SDF_ExternalDecrypt_ECC enR Succeed!\n");
        ret = SDF_ExternalSign_ECC(pSessionHandle, SGD_SM2_1, &signvk, pin,
                                   len, &signR);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SDF_ExternalSign_ECC R failed and return is %08x,%08x\n",
                 ret, SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        else
          printf("SDF_ExternalSign_ECC Succeed!\n");
        ret = SDF_ExternalDecrypt_ECC(pSessionHandle, SGD_SM2_3, &envk, enmk,
                                      pin, &len);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_ExternalDecrypt_ECC enmk failed and return is %08x,%08x\n",
              ret, SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        if (len != 32)
        {
          printf(
              "SDF_ExternalDecrypt_ECC enmk data length error,return length "
              "is \n",
              len);
          free(enR);
          free(enmk);
          break;
        }
        else
          printf("SDF_ExternalDecrypt_ECC enmk Succeed!\n");
        printeccpk("temp pk", &entpk);
        ret = SDF_ExternalEncrypt_ECC(pSessionHandle, SGD_SM2_3, &entpk, pin,
                                      len, enmk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "SDF_ExternalEncrypt_ECC mk failed and return is %08x,%08x\n",
              ret, SPII_GetErrorInfo(pSessionHandle));
          free(enR);
          free(enmk);
          break;
        }
        else
        {
          printf("SDF_ExternalEncrypt_ECC mk Succeed!\n");
          printbuff(enmk->x + 32, 32);
          printbuff(enmk->y + 32, 32);
          printbuff(enmk->M, 32);
          printbuff(enmk->C, enmk->L);
        }
        ret =
            SPII_LoadinStepS(pSessionHandle, Ukeyflag, NULL, 0, &signR, enmk);
        if (ret != SR_SUCCESSFULLY)
          printf("SPII_LoadinStepS failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
        else
          printf("Load in Card Succeed!\n");
        free(enR);
        free(enmk);
      }
      break;
    case 2:
      GenerateKeyInCard(pSessionHandle);
      break;

    case 3:
      if (!Ukeyflag)
      {
        for (UserID = 1; UserID < 4; UserID++)
        {
          printf(
              "Please Press 'Y'or 'y' when you connet the UsbKey on "
              "EncryptCard:");
          scanf("%s", yes);
          if (strcmp(yes, "y") != 0 && strcmp(yes, "Y") != 0)
            break;
          memset(enkey, 0, 50);
          printf("Please input the Pin of %d Ukey:", UserID);
          scanf("%s", enkey);
          ret = SPII_BackUpBK(pSessionHandle, Ukeyflag, enkey, strlen(enkey),
                              UserID, NULL, NULL);
          if (ret != SR_SUCCESSFULLY)
          {
            printf("SPII_BackUpBK %d failed and return is %08x,%08x\n",
                   UserID, ret, SPII_GetErrorInfo(pSessionHandle));
            break;
          }
          else
            printf("SPII_BackUpBK %d succeed!\n", UserID);
        }
      }
      else
      {
        enmk = malloc(sizeof(ECCCipher) + 48);
        for (UserID = 1; UserID < 4; UserID++)
        {
          ret = SDF_GenerateKeyPair_ECC(pSessionHandle, SGD_SM2_1, 256, &enpk,
                                        &envk);
          if (ret != SR_SUCCESSFULLY)
          {
            printf("Card Generate enc Key failed and return is %08x\n", ret);
            sprintf(skeyid, "SPII_BackUpBK%d.bin", UserID);
            ret = readfile(skeyid, keypairfile, &filelen);
            if (ret != 0)
            {
              printf("write %d Read PK VK from file error!\n", UserID);
              break;
            }
            memcpy(&enpk, keypairfile, sizeof(ECCrefPublicKey));
            memcpy(&envk, keypairfile + sizeof(ECCrefPublicKey),
                   sizeof(ECCrefPrivateKey));
          }
          ret = SPII_BackUpBK(pSessionHandle, Ukeyflag, NULL, 0, UserID,
                              &enpk, enmk);
          if (ret != SR_SUCCESSFULLY)
          {
            printf("SPII_BackUpBK  %d failed and return is %08x %08x\n",
                   UserID, ret, SPII_GetErrorInfo(pSessionHandle));
            break;
          }
          printf("UserID is %d\n", UserID);
          printeccchiper("BackUpBK", enmk);
          sprintf(skeyid, "SPII_BackUpBK%d.bin", UserID);
          filelen = 0;
          memcpy(keypairfile, &enpk, sizeof(ECCrefPublicKey));
          filelen = filelen + sizeof(ECCrefPublicKey);
          memcpy(keypairfile + filelen, &envk, sizeof(ECCrefPrivateKey));
          filelen = filelen + sizeof(ECCrefPrivateKey);
          memcpy(keypairfile + filelen, enmk, sizeof(ECCCipher) + 48);
          filelen = filelen + sizeof(ECCCipher) + 48;
          ret = wrtiefile(skeyid, keypairfile, filelen);
          if (ret != 0)
          {
            printf("write %d SPII_BackUpBK to file error!\n", UserID);
          }
          printf("SPII_BackUpBK  %d succeed!\n", UserID);
        }
        free(enmk);
      }
      for (i = 0; i < KEYPAIR_MAX_INDEX; i++)
      {
        //			PrintPer("Key Pair BackUp
        // all",KEYPAIR_MAX_INDEX,i);
        if (i % 100 == 0)
          printf("%d keyPair BackUp\n", i);

        ret = SPII_BackUpECCEnc(pSessionHandle, i, keypairfile, &filelen);
        if (status != 0)
        {
          printf("backup %d EnEccKeyPair error,and return is %08x\n\n\n", i,
                 status);
          return;
        }
        sprintf(skeyid, "KeyBack/EEkeypair%d.bin", i);
        ret = wrtiefile(skeyid, keypairfile, filelen);
        if (ret != 0)
        {
          printf("write %d ECC Enc KeyPair to file error!\n", i);
          return;
        }
        ret = SPII_BackUpECCSign(pSessionHandle, i, keypairfile, &filelen);
        if (status != 0)
        {
          printf("backup %d SignEccKeyPair error,and return is %08x\n\n\n", i,
                 status);
          return;
        }
        sprintf(skeyid, "KeyBack/ESkeypair%d.bin", i);
        ret = wrtiefile(skeyid, keypairfile, filelen);
        if (ret != 0)
        {
          printf("write %d ECC Sign KeyPair to file error!\n", i);
          return;
        }
        if (i < 1024)
        {
          ret = SPII_BackUpKEK(pSessionHandle, i, keypairfile, &filelen);
          if (status != 0)
          {
            printf("backup %d KEK error,and return is %08x\n\n\n", i, status);
            return;
          }
          sprintf(skeyid, "KeyBack/KEK%d.bin", i);
          ret = wrtiefile(skeyid, keypairfile, filelen);
          if (ret != 0)
          {
            printf("write %d KEK to file error!\n", i);
            return;
          }
        }
        /*				ret=SPII_BackUpEnMkSM9(pSessionHandle,i,keypairfile,&filelen);
                                        if(status!=0)
                                        {
                                                printf("backup %d EnMkSM9
           error,and return is %08x\n",i,status); return;
                                        }
                                        sprintf(skeyid,"KeyBack/SEMkeypair%d.bin",i);
                                        ret=wrtiefile(skeyid,keypairfile,filelen);
                                        if(ret!=0)
                                                {
                                                        printf("write %d KEK
           to file error!\n",i); return;
                                                        }
                                        ret=SPII_BackUpSigMkSM9(pSessionHandle,i,keypairfile,&filelen);
                                        if(status!=0)
                                        {
                                                printf("backup %d EnMkSM9
           error,and return is %08x\n",i,status); return;
                                        }
                                        sprintf(skeyid,"KeyBack/SSMkeypair%d.bin",i);
                                        ret=wrtiefile(skeyid,keypairfile,filelen);
                                        if(ret!=0)
                                                {
                                                        printf("write %d KEK
           to file error!\n",i); return;
                                                        }
                                        ret=SPII_BackUpEnUkSM9(pSessionHandle,i,keypairfile,&filelen);
                                        if(status!=0)
                                        {
                                                printf("backup %d EnMkSM9
           error,and return is %08x\n",i,status); return;
                                        }
                                        sprintf(skeyid,"KeyBack/SEUkeypair%d.bin",i);
                                        ret=wrtiefile(skeyid,keypairfile,filelen);
                                        if(ret!=0)
                                                {
                                                        printf("write %d KEK
           to file error!\n",i); return;
                                                        }
                                        ret=SPII_BackUpSigUkSM9(pSessionHandle,i,keypairfile,&filelen);
                                        if(status!=0)
                                        {
                                                printf("backup %d EnMkSM9
           error,and return is %08x\n",i,status); return;
                                        }
                                        sprintf(skeyid,"KeyBack/SSUkeypair%d.bin",i);
                                        ret=wrtiefile(skeyid,keypairfile,filelen);
                                        if(ret!=0)
                                                {
                                                        printf("write %d KEK
           to file error!\n",i); return;
                                                        }*/
      }

      printf("Backup Key succeed!\n");
      break;
    case 4:
      if (!Ukeyflag)
      {
        ret = SPII_GenerateTmpPK(pSessionHandle, &entpk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_GenerateTmpPK failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          return;
        }
        else
          printf("SPII_GenerateTmpPK succeed!\n");

        memset(enkey, 0, 50);
        UserID = 1;
        printf("Please input the Pin of Ukey:");
        scanf("%s", enkey);
        ret = SPII_RestoreBK(pSessionHandle, Ukeyflag, enkey, strlen(enkey),
                             NULL);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_RestoreBK %d failed and return is %08x,%08x\n", UserID,
                 ret, SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        else
          printf("SPII_RestoreBK %d succeed!\n", UserID);
        memset(enkey, 0, 50);
        UserID = 2;
        printf("Please input the Pin of Ukey:");
        scanf("%s", enkey);
        ret = SPII_RestoreBK(pSessionHandle, Ukeyflag, enkey, strlen(enkey),
                             NULL);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_RestoreBK %d failed and return is %08x,%08x\n", UserID,
                 ret, SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        else
          printf("SPII_RestoreBK %d succeed!\n", UserID);
      }
      else
      {
        ret = SPII_GenerateTmpPK(pSessionHandle, &entpk);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SPII_GenerateTmpPK failed and return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          free(enmk);
          return;
        }
        else
          printf("SPII_GenerateTmpPK succeed!\n");

        for (UserID = 1; UserID < 3; UserID++)
        {
          enmk = malloc(sizeof(ECCCipher) + 48);
          sprintf(skeyid, "SPII_BackUpBK%d.bin", UserID);
          ret = readfile(skeyid, keypairfile, &filelen);
          if (ret != 0)
          {
            printf("write %d Read PK VK from file error!\n", UserID);
            free(enmk);
            return;
          }
          memcpy(&enpk, keypairfile, sizeof(ECCrefPublicKey));
          memcpy(&envk, keypairfile + sizeof(ECCrefPublicKey),
                 sizeof(ECCrefPrivateKey));
          memcpy(enmk,
                 keypairfile + sizeof(ECCrefPublicKey) +
                     sizeof(ECCrefPrivateKey),
                 sizeof(ECCCipher) + 48);
          ret = SDF_ExternalDecrypt_ECC(pSessionHandle, SGD_SM2_3, &envk,
                                        enmk, pin, &len);
          if (ret != SR_SUCCESSFULLY)
          {
            printf(
                "SDF_ExternalDecrypt_ECC enmk failed and return is "
                "%08x,%08x\n",
                ret, SPII_GetErrorInfo(pSessionHandle));
            free(enmk);
            return;
          }
          if (len != 48)
          {
            printf(
                "SDF_ExternalDecrypt_ECC enmk data length error,return "
                "length is %d\n",
                len);
            free(enmk);
            return;
          }
          else
            printf("SDF_ExternalDecrypt_ECC enmk Succeed!\n");
          ret = SDF_ExternalEncrypt_ECC(pSessionHandle, SGD_SM2_3, &entpk,
                                        pin, len, enmk);
          if (ret != SR_SUCCESSFULLY)
          {
            printf(
                "SDF_ExternalEncrypt_ECC mk failed and return is %08x,%08x\n",
                ret, SPII_GetErrorInfo(pSessionHandle));
            free(enmk);
            return;
          }
          else
            printf("SDF_ExternalEncrypt_ECC mk Succeed!\n");
          ret = SPII_RestoreBK(pSessionHandle, Ukeyflag, NULL, 0, enmk);
          if (ret != SR_SUCCESSFULLY)
          {
            printf("SPII_RestoreBK mk failed and return is %08x,%08x\n", ret,
                   SPII_GetErrorInfo(pSessionHandle));
            free(enmk);
            return;
          }
          else
            printf("SPII_RestoreBK %d succeed!\n", UserID);
          free(enmk);
        }
      }
      printf("the Restore starting.....\n");
      for (i = 1; i < KEYPAIR_MAX_INDEX; i++)
      {
        //	PrintPer("Key Pair ReStore all",KEYPAIR_MAX_INDEX,i);

        if (i % 100 == 0)
          printf("%d keyPair Restore\n", i);
        sprintf(skeyid, "KeyBack/EEkeypair%d.bin", i);
        ret = readfile(skeyid, keypairfile, &filelen);
        if (ret != 0)
        {
          printf("read %d ECC Enc KeyPair to file error!\n", i);
          return;
        }
        ret = SPII_RestoreECCEnc(pSessionHandle, i, keypairfile, filelen);
        if (ret != 0)
        {
          printf("Restore %d EnEccKeyPair error,and return is %08x\n", i,
                 status);
          return;
        }
        sprintf(skeyid, "KeyBack/ESkeypair%d.bin", i);
        ret = readfile(skeyid, keypairfile, &filelen);
        if (ret != 0)
        {
          printf("read %d ECC Sign KeyPair to file error!\n", i);
          return;
        }
        ret = SPII_RestoreECCSign(pSessionHandle, i, keypairfile, filelen);
        if (ret != 0)
        {
          printf("Restore %d SignEccKeyPair error,and return is %08x\n", i,
                 status);
          return;
        }

        if (i <= 1024)
        {
          sprintf(skeyid, "KeyBack/KEK%d.bin", i - 1);
          printf("%s\n", skeyid);
          ret = readfile(skeyid, keypairfile, &filelen);
          if (ret != 0)
          {
            printf("read %d KEK to file error!\n", i - 1);
            return;
          }
          ret = SPII_RestoreKEK(pSessionHandle, i - 1, keypairfile, filelen);
          if (ret != 0)
          {
            printf("Restore %d KEK error,and return is %08x\n", i - 1,
                   status);
            return;
          }
        }
        /*	sprintf(skeyid,"KeyBack/SEMkeypair%d.bin",i);
                ret=readfile(skeyid,keypairfile,&filelen);
                if(ret!=0)
                        {
                                printf("read %d KEK to file error!\n",i);
                                return;
                                }
                ret=SPII_RestoreEnMkSM9(pSessionHandle,i,keypairfile,filelen);
                if(ret!=0)
                {
                        printf("Restore %d EnMkSM9 error,and return is
           %08x\n",i,status); return;
                }

                sprintf(skeyid,"KeyBack/SSMkeypair%d.bin",i);
                ret=readfile(skeyid,keypairfile,&filelen);
                if(ret!=0)
                        {
                                printf("read %d KEK to file error!\n",i);
                                return;
                                }
                ret=SPII_RestoreSigMkSM9(pSessionHandle,i,keypairfile,filelen);
                if(ret!=0)
                {
                        printf("Restore %d EnMkSM9 error,and return is
           %08x\n",i,status); return;
                }

                sprintf(skeyid,"KeyBack/SEUkeypair%d.bin",i);

                ret=readfile(skeyid,keypairfile,&filelen);
                if(ret!=0)
                        {
                                printf("read %d KEK to file error!\n",i);
                                return;
                                }
                ret=SPII_RestoreEnUkSM9(pSessionHandle,i,keypairfile,filelen);
                if(ret!=0)
                {
                        printf("Restore %d EnMkSM9 error,and return is
           %08x\n",i,status); return;
                }

                sprintf(skeyid,"KeyBack/SSUkeypair%d.bin",i);
                ret=readfile(skeyid,keypairfile,&filelen);
                if(ret!=0)
                        {
                                printf("write %d KEK to file error!\n",i);
                                return;
                                }
                ret=SPII_RestoreSigUkSM9(pSessionHandle,i,keypairfile,filelen);
                if(ret!=0)
                {
                        printf("Restore %d EnMkSM9 error,and return is
           %08x\n",i,status); return;
                }*/
      }

      printf("Restore Key succeed!\n");
      break;
    case 5:
      printf("Please input the keyID(0<=KeyID<1024):");
      scanf("%d", &indexNum);
      printf("Please input the old PrivateKeyAccessRight PassWord:");
      scanf("%s", oldpin);
      printf("Please input the new PrivateKeyAccessRight PassWord:");
      scanf("%s", pin);
      ret = SPII_ChangePrivateKeyAccessRight(
          pSessionHandle, indexNum, oldpin, strlen(oldpin), pin, strlen(pin));
      if (ret != SR_SUCCESSFULLY)
        printf(
            "SPII_ChangePrivateKeyAccessRight error! return is %08x ,%08x\n",
            ret, SPII_GetErrorInfo(pSessionHandle));
      else
        printf("Release Right succeed!\n");
      break;
    case 6:
      printf(
          "This Operation will set EncryptCard to Zero,and Should Regist "
          "Operator in Factory Status!\nAre you sure?Y/N:");
      scanf("%s", yes);
      if (strcmp(yes, "y") != 0 && strcmp(yes, "Y") != 0)
        break;
      else
      {
        ret = SPII_Init_Device(DeviceHandle);
        if (ret != SR_SUCCESSFULLY)
          printf("Init Card failed and return is %08x\n", ret);
        else
          printf("Init Succeed!\n");
      }
      break;
#if 0				
			case 7:
				memset(pin,0,50);
				memset(oldpin,0,50);
				printf("Please input the Old Pin:");
				scanf("%s",oldpin);
				printf("Please input the new Pin:");
				scanf("%s",pin);
				ret=SPII_ChangeUkeyPin(pSessionHandle,oldpin,strlen(oldpin),pin,strlen(pin));
				if(ret!=SR_SUCCESSFULLY)
					printf("SPII_ChangeUkeyPin error! return is %08x ,%08x\n",ret, SPII_GetErrorInfo(pSessionHandle));
				else
					printf("SPII_ChangeUkeyPin succeed!\n");
					break;
#endif
    case 8:

      ret = SPII_RSTOIS(DeviceHandle);
      if (ret != 0)
        printf("SPII_RSTOIS failed,and return is %08x \n", ret);
      else
        printf("SPII_RSTOIS succeed\n");
      break;
    case 0:
    default:
      SDF_CloseSession(pSessionHandle);
      SDF_CloseDevice(DeviceHandle);
      return;
    }
  }
}
void INITCARD()
{
  int select, ret, len, indexNum, keybits, i;
  unsigned int status;
  unsigned char pin[100], oldpin[100];
  HANDLE DeviceHandle, pSessionHandle;
  ret = SDF_OpenDevice(&DeviceHandle);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_OpenDevice error!return is %08x\n", ret);
  else
    printf("OpenDevice succeed!the DeviceHandle is %x\n", DeviceHandle);
  ret = SDF_OpenSession(DeviceHandle, &pSessionHandle);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_OpenSession error!return is %08x,%08x\n", ret,
           SPII_GetErrorInfo(NULL));
  else
    printf("OpenSession succeed!the SessionHandle is %x\n", pSessionHandle);
  while (1)
  {
    select = 0;
    printf("       Factor Status ------------------------- 1\n");
    printf("       Init Status --------------------------- 2\n");
    printf("       Ready Status -------------------------- 3\n");
    printf("       EncryptCard status -------------------- 4\n");
    printf("       Quit ---------------------------------- 0\n");
    printf("    please input your select:");
    scanf("%d", &select);
    switch (select)
    {
    case 1:
      Status_Factor();
      break;
    case 2:
      Status_Init();
      break;
    case 3:
      Status_Ready();
      break;
    case 4:
      StatusChange();
      break;
    case 0:
    default:
      ret = SDF_CloseSession(pSessionHandle);
      if (ret != SR_SUCCESSFULLY)
        printf("SDF_CloseSession error!return is %08x\n", ret);
      else
        printf("CloseSession succeed!\n");
      ret = SDF_CloseDevice(DeviceHandle);
      if (ret != SR_SUCCESSFULLY)
        printf("SDF_CloseDevice error! return is %08x \n", ret);
      else
        printf("CloseDevice succeed!\n");
      return;
    }
  }
}

void ECCTest()
{
  int select, ret, len, indexNum, length, i, filelen;
  ECCrefPublicKey pk, epk;
  ECCrefPrivateKey vk;
  ECCCipher *endata, *endata2, *endata3;
  ECCSignature sigdata;
  unsigned char data[3584], pin[256], edata[256], mdata[256];
  unsigned char skeyid[50];
  unsigned char keypairfile[2000];
  unsigned char *c;
  unsigned char pincode[] = {"wuxipiico"};
  HANDLE DeviceHandle, pSessionHandle, KeyHandle1;
  FILE *fp;
  ret = SDF_OpenDevice(&DeviceHandle);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_OpenDevice error!return is %08x\n", ret);
  else
    printf("OpenDevice succeed!the DeviceHandle is %x\n", DeviceHandle);
  ret = SDF_OpenSession(DeviceHandle, &pSessionHandle);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_OpenSession error!return is %08x\n", ret);
  else
    printf("OpenSession succeed!the SessionHandle is %x\n", pSessionHandle);
  len = 256;
  ret = SDF_GenerateKeyPair_ECC(pSessionHandle, SGD_SM2_1, len, &pk, &vk);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_GenerateKey_ECC error!return is %08x,%08x\n", ret,
           SPII_GetErrorInfo(pSessionHandle));
  else
  {
    printf("GenECCKeyPair  succeed!\n");
    printf("pk.bits:%d\n", pk.bits);
    printf("pk.x:\n");
    printbuff(pk.x, ECCref_MAX_LEN);
    printf("pk.y:\n");
    printbuff(pk.y, ECCref_MAX_LEN);
    printf("====================\n");
    printf("vk.bits:%d\n", vk.bits);
    printf("vk.K:\n");
    printbuff(vk.K, ECCref_MAX_LEN);
    fp = fopen("ECCfile", "wt");
    if (fp == NULL)
    {
      printf("Open File error!");
      return;
    }
    fwrite(&pk, 1, sizeof(ECCrefPublicKey), fp);
    fwrite(&vk, 1, sizeof(ECCrefPrivateKey), fp);
    fclose(fp);
  }

  printf("Please input the test length:(1~3584)");

  scanf("%d", &length);

  if (length > MAX_DATALEN)

  {
    printf("Test length error!");

    return;
  }

  ret = SDF_GenerateRandom(pSessionHandle, length, data);

  if (ret != SR_SUCCESSFULLY)

    printf("SDF_GenerateRandom error!return is %08x,%08x\n", ret,
           SPII_GetErrorInfo(pSessionHandle));

  else

  {
    printf("The data is :\n");

    printbuff(data, length);
  }

  while (1)

  {
    printf("          SDF_ExternalSign_ECC -------------- 1\n");
    printf("          SDF_ExternalVerify_ECC ------------- 2\n");
    printf("          SDF_InternalSign_ECC --------------- 3\n");
    printf("          SDF_InternalVerify_ECC ------------- 4\n");
    printf("          SDF_InternalEncrypt_ECC ------------10\n");
    printf("          SDF_InternalDecrypt_ECC ------------11\n");
    printf("          SDF_ExternalEncrypt_ECC ------------ 5\n");
    printf("          SDF_ExternalDecrypt_ECC ------------ 6\n");
    printf("          SDF_ExchangeDigitEnvelopeBaseOnECC - 7\n");
    printf("          Test all Store KeyPair ------------- 8\n");
    printf("          Check all BackUp KeyPair ----------- 9\n");
    printf("          Quit ------------------------------- 0\n");

    printf("    please input your select:");

    scanf("%d", &select);

    switch (select)

    {
    case 1:

      ret = SDF_ExternalSign_ECC(pSessionHandle, SGD_SM2_1, &vk, data, 32,
                                 &sigdata);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_ExternalSign_ECC error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

      else
      {
        printf("SPII_ExternalSign succeed!\n");

        printf("sigdata.r :\n");

        printbuff(sigdata.r, ECCref_MAX_LEN);

        printf("sigdata.s :\n");

        printbuff(sigdata.s, ECCref_MAX_LEN);
      }

      break;

    case 2:

      ret = SDF_ExternalVerify_ECC(pSessionHandle, SGD_SM2_1, &pk, data, 32,
                                   &sigdata);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_ExternalVerify_ECC error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

      else

        printf("Verify Succeed!\n");

      break;

    case 3:

      printf("Please input the Key Index (Index<=18):");

      scanf("%d", &indexNum);

      printf("To get Privatekey access right,please input the password :");

      scanf("%s", pin);

      ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, indexNum, pin,
                                         strlen(pin));

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_GetPrivateKeyAccessRight error! return is %08x ,%08x\n",
               ret, SPII_GetErrorInfo(pSessionHandle));

      else

      {
        ret = SDF_InternalSign_ECC(pSessionHandle, indexNum, data, 32,
                                   &sigdata);

        if (ret != SR_SUCCESSFULLY)

          printf("SDF_InternalSign_ECC error!return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));

        else
        {
          printf("SDF_InternalSign succeed!\n");

          printf("sigdata.r :\n");

          printbuff(sigdata.r, ECCref_MAX_LEN);

          printf("sigdata.s :\n");

          printbuff(sigdata.s, ECCref_MAX_LEN);
        }
      }

      break;

    case 4:

      printf("Please input the Key Index (Index<=18):");

      scanf("%d", &indexNum);

      ret = SDF_InternalVerify_ECC(pSessionHandle, indexNum, data, 32,
                                   &sigdata);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_InternalVerify_ECC error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

      else

        printf("Verify Succeed!\n");

      break;

    case 5:

      endata = malloc(sizeof(ECCCipher) + length);

      ret = SDF_ExternalEncrypt_ECC(pSessionHandle, SGD_SM2_3, &pk, data,
                                    length, endata);

      //(eccd.C)=unsigned char[length];

      // realloc(eccd.C,length);

      //	eccd.C=c;

      // ret=SDF_ExternalEncrypt_ECC(pSessionHandle,SGD_SM2_3,&pk,data,length,&eccd);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_ExternalEncrypt_ECC error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

      else
      {
        printf("Encrypt Succeed!\n");

        printf("endata.x\n");

        printbuff(endata->x, ECCref_MAX_LEN);

        printf("endata.y\n");

        printbuff(endata->y, ECCref_MAX_LEN);

        printf("endata.M\n");

        printbuff(endata->M, 32);

#ifdef STD20100816

        printf("endata.C\n");

        printbuff(endata->C, ECCref_MAX_LEN);

#else

        printf("endata.L is %08x\n", endata->L);

        printf("endata.C\n");

        printbuff(endata->C, endata->L);

#endif
      }

      break;

    case 6:

      ret = SDF_ExternalDecrypt_ECC(pSessionHandle, SGD_SM2_3, &vk, endata,
                                    data, &len);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_ExternalDecrypt_ECC error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

      else
      {
        printf("Decrypt Succeed!\n");

        printf("The data is :\n");

        printbuff(data, len);
      }

      free(endata);

      break;

    case 7:

      printf("Please input the Key Index (Index<=18):");

      scanf("%d", &indexNum);

      printf("To get Privatekey access right,please input the password :");

      scanf("%s", pin);

      ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, indexNum, pin,
                                         strlen(pin));

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_GetPrivateKeyAccessRight error! return is %08x ,%08x\n",
               ret, SPII_GetErrorInfo(pSessionHandle));

      else

      {
        ret = SDF_ExportEncPublicKey_ECC(pSessionHandle, indexNum, &epk);

        if (ret != SR_SUCCESSFULLY)

        {
          printf("SDF_ExportEncPublicKey_ECC error!return is %08x,%08x\n",
                 ret, SPII_GetErrorInfo(pSessionHandle));

          break;
        }

        else

          printf("SDF_ExportEncPublicKey_ECC succeed!\n");

        endata2 = malloc(sizeof(ECCCipher) + length);

        endata = malloc(sizeof(ECCCipher) + length);

        ret = SDF_ExternalEncrypt_ECC(pSessionHandle, SGD_SM2_3, &epk, data,
                                      length, endata);

        if (ret != SR_SUCCESSFULLY)

        {
          printf("SDF_ExternalEncrypt_ECC error!return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));

          goto breaktest;
        }

        else
        {
          printf("Encrypt Succeed!\n");

          printf("endata.x\n");

          printbuff(endata->x, ECCref_MAX_LEN);

          printf("endata.y\n");

          printbuff(endata->y, ECCref_MAX_LEN);

          printf("endata.M\n");

          printbuff(endata->M, 32);

#ifdef STD20100816

          printf("endata.C\n");

          printbuff(endata->C, ECCref_MAX_LEN);

#else

          printf("endata.L is %08x\n", endata->L);

          printf("endata.C\n");

          printbuff(endata->C, endata->L);

#endif
        }

        ret = SDF_ExchangeDigitEnvelopeBaseOnECC(
            pSessionHandle, indexNum, SGD_SM2_3, &pk, endata, endata2);

        if (ret != SR_SUCCESSFULLY)

        {
          printf(
              "SDF_ExchangeDigitEnvelopeBaseOnECC error!return is "
              "%08x,%08x\n",
              ret, SPII_GetErrorInfo(pSessionHandle));

          goto breaktest;
        }

        else
        {
          printf("Encrypt Succeed!\n");

          printf("endata2.x\n");

          printbuff(endata2->x, ECCref_MAX_LEN);

          printf("endata.y\n");

          printbuff(endata2->y, ECCref_MAX_LEN);

          printf("endata.M\n");

          printbuff(endata2->M, 32);

#ifdef STD20100816

          printf("endata.C\n");

          printbuff(endata2->C, ECCref_MAX_LEN);

#else

          printf("endata.L is %08x\n", endata2->L);

          printf("endata.C\n");

          printbuff(endata2->C, endata2->L);

#endif
        }

        ret = SDF_ExternalDecrypt_ECC(pSessionHandle, SGD_SM2_3, &vk, endata2,
                                      data, &len);

        if (ret != SR_SUCCESSFULLY)

          printf("SDF_ExternalDecrypt_ECC error!return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));

        else
        {
          printf("Decrypt Succeed!\n");

          printf("The data is :\n");

          printbuff(data, len);
        }

      breaktest:

        free(endata);

        free(endata2);
      }

      break;

    case 8:
      for (i = 0; i <= KEYPAIR_MAX_INDEX; i++)
      {
        ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, i, pincode,
                                           strlen(pincode));
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "NO %d KeyPair SDF_GetPrivateKeyAccessRight error!return is "
              "%08x,%08x\n",
              i, ret, SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        ret = SDF_GenerateRandom(pSessionHandle, 16, data);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("SDF_GenerateRandom error!return is %08x,%08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        ret = SDF_InternalSign_ECC(pSessionHandle, i, data, 32, &sigdata);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "NO %d KeyPair SDF_InternalSign_ECC error!return is "
              "%08x,%08x\n",
              i, ret, SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        ret = SDF_InternalVerify_ECC(pSessionHandle, i, data, 32, &sigdata);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "NO %d KeyPair SDF_InternalSign_ECC error!return is "
              "%08x,%08x\n",
              i, ret, SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        filelen = 0;
        memcpy(keypairfile, data, 32);
        filelen = 32;
        memcpy(keypairfile + filelen, &sigdata, sizeof(ECCSignature));
        filelen = filelen + sizeof(ECCSignature);
        sprintf(skeyid, "KeyTest/SignKeypair%d.bin", i);
        ret = wrtiefile(skeyid, keypairfile, filelen);
        endata3 = malloc(sizeof(ECCCipher) + 16);
        ret = SDF_GenerateKeyWithIPK_ECC(pSessionHandle, i, 128, endata3,
                                         &KeyHandle1);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "NO %d KeyPair SDF_GenerateKeyWithIPK_ECC error!return is "
              "%08x,%08x\n",
              i, ret, SPII_GetErrorInfo(pSessionHandle));
          free(endata3);
          break;
        }
        ret = SDF_Encrypt(pSessionHandle, KeyHandle1, SGD_SM4_ECB, NULL, data,
                          32, edata, &len);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "NO %d KeyPair SDF_GenerateKeyWithIPK_ECC error!return is "
              "%08x,%08x\n",
              i, ret, SPII_GetErrorInfo(pSessionHandle));
          SDF_DestroyKey(pSessionHandle, KeyHandle1);
          free(endata3);
          break;
        }
        SDF_DestroyKey(pSessionHandle, KeyHandle1);

        filelen = 0;
        memcpy(keypairfile, data, 32);
        filelen = 32;
        memcpy(keypairfile + filelen, edata, 32);
        filelen = filelen + 32;
        memcpy(keypairfile + filelen, endata3, sizeof(ECCCipher) + 16);
        filelen = filelen + sizeof(ECCCipher) + 16;
        sprintf(skeyid, "KeyTest/EnKeypair%d.bin", i);
        ret = wrtiefile(skeyid, keypairfile, filelen);

        ret =
            SDF_ImportKeyWithISK_ECC(pSessionHandle, i, endata3, &KeyHandle1);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "NO %d KeyPair SDF_ImportKeyWithISK_ECC error!return is "
              "%08x,%08x\n",
              i, ret, SPII_GetErrorInfo(pSessionHandle));
          free(endata3);
          break;
        }
        free(endata3);
        ret = SDF_Decrypt(pSessionHandle, KeyHandle1, SGD_SM4_ECB, NULL,
                          edata, len, mdata, &length);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("NO %d KeyPair SDF_Decrypt error!return is %08x,%08x\n", i,
                 ret, SPII_GetErrorInfo(pSessionHandle));
          SDF_DestroyKey(pSessionHandle, KeyHandle1);
          break;
        }
        SDF_DestroyKey(pSessionHandle, KeyHandle1);
        if (length != 32)
        {
          printf("NO %d KeyPair SDF_Decrypt return length error!\n", i);
          break;
        }
        else if (memcmp(data, mdata, 32) != 0)
        {
          printf("NO %d KeyPair SDF_Decrypt return data error!\n", i);
          break;
        }
        PrintPer("All ECC User KeyPair Test it", KEYPAIR_MAX_INDEX, i);
      }

      break;
    case 9:
      for (i = 0; i <= KEYPAIR_MAX_INDEX; i++)
      {
        ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, i, pincode,
                                           strlen(pincode));
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "NO %d KeyPair SDF_GetPrivateKeyAccessRight error!return is "
              "%08x,%08x\n",
              i, ret, SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        sprintf(skeyid, "KeyTest/SignKeypair%d.bin", i);
        ret = readfile(skeyid, keypairfile, &filelen);
        memcpy(data, keypairfile, 32);
        filelen = 32;
        memcpy(&sigdata, keypairfile + filelen, sizeof(ECCSignature));
        filelen = filelen + sizeof(ECCSignature);
        /*	ret=SDF_GenerateRandom(pSessionHandle,16,data);
                if(ret!=SR_SUCCESSFULLY)
                {
                                printf("SDF_GenerateRandom error!return is
           %08x,%08x\n",ret, SPII_GetErrorInfo(pSessionHandle)); break;
                }
                ret=SDF_InternalSign_ECC(pSessionHandle,i,data,32,&sigdata);
                if(ret!=SR_SUCCESSFULLY)
                {
                        printf("NO %d KeyPair SDF_InternalSign_ECC
           error!return is %08x,%08x\n",i,ret,
           SPII_GetErrorInfo(pSessionHandle)); break;
                        }*/
        ret = SDF_InternalVerify_ECC(pSessionHandle, i, data, 32, &sigdata);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "NO %d KeyPair SDF_InternalSign_ECC error!return is "
              "%08x,%08x\n",
              i, ret, SPII_GetErrorInfo(pSessionHandle));
          break;
        }
        endata3 = malloc(sizeof(ECCCipher) + 16);
        sprintf(skeyid, "KeyTest/EnKeypair%d.bin", i);
        ret = readfile(skeyid, keypairfile, &filelen);
        memcpy(data, keypairfile, 32);
        filelen = 32;
        memcpy(edata, keypairfile + filelen, 32);
        filelen = filelen + 32;
        memcpy(endata3, keypairfile + filelen, sizeof(ECCCipher) + 16);
        /*	ret=SDF_GenerateKeyWithIPK_ECC
           (pSessionHandle,i,128,endata3,&KeyHandle1);
                if(ret!=SR_SUCCESSFULLY)
                {
                        printf("NO %d KeyPair SDF_GenerateKeyWithIPK_ECC
           error!return is %08x,%08x\n",i,ret,
           SPII_GetErrorInfo(pSessionHandle)); free(endata3); break;
                        }

                ret=SDF_Encrypt(pSessionHandle,KeyHandle1,SGD_SM4_ECB,NULL,data,32,edata,&len);
                if(ret!=SR_SUCCESSFULLY)
                {
                        printf("NO %d KeyPair SDF_GenerateKeyWithIPK_ECC
           error!return is %08x,%08x\n",i,ret,
           SPII_GetErrorInfo(pSessionHandle));
                        SDF_DestroyKey(pSessionHandle,KeyHandle1);
                        free(endata3);
                        break;
                        }
                SDF_DestroyKey(pSessionHandle,KeyHandle1);
                */

        ret =
            SDF_ImportKeyWithISK_ECC(pSessionHandle, i, endata3, &KeyHandle1);
        if (ret != SR_SUCCESSFULLY)
        {
          printf(
              "NO %d KeyPair SDF_ImportKeyWithISK_ECC error!return is "
              "%08x,%08x\n",
              i, ret, SPII_GetErrorInfo(pSessionHandle));
          free(endata3);
          break;
        }
        free(endata3);
        len = 32;
        ret = SDF_Decrypt(pSessionHandle, KeyHandle1, SGD_SM4_ECB, NULL,
                          edata, len, mdata, &length);
        if (ret != SR_SUCCESSFULLY)
        {
          printf("NO %d KeyPair SDF_Decrypt error!return is %08x,%08x\n", i,
                 ret, SPII_GetErrorInfo(pSessionHandle));
          SDF_DestroyKey(pSessionHandle, KeyHandle1);
          break;
        }
        SDF_DestroyKey(pSessionHandle, KeyHandle1);
        if (length != 32)
        {
          printf("NO %d KeyPair SDF_Decrypt return length error!\n", i);
          break;
        }
        else if (memcmp(data, mdata, 32) != 0)
        {
          printf("NO %d KeyPair SDF_Decrypt return data error!\n", i);
          break;
        }
        PrintPer("All ECC User KeyPair Test it", KEYPAIR_MAX_INDEX, i);
      }
      break;

    case 10:

      printf("Please input the Key Index (Index<=9999):");

      scanf("%d", &indexNum);

      endata = malloc(sizeof(ECCCipher) + length);

      ret = SDF_InternalEncrypt_ECC(pSessionHandle, indexNum, SGD_SM2_3, data,
                                    length, endata);

      //(eccd.C)=unsigned char[length];

      // realloc(eccd.C,length);

      //    eccd.C=c;

      // ret=SDF_ExternalEncrypt_ECC(pSessionHandle,SGD_SM2_3,&pk,data,length,&eccd);

      if (ret)

        printf("SDF_InternalEncrypt_ECC failed! return: 0x%08x, 0x%08x\n",
               ret, SPII_GetErrorInfo(pSessionHandle));

      else
      {
        printf("Encrypt Succeed!\n");

        printf("endata.x\n");

        printbuff(endata->x, ECCref_MAX_LEN);

        printf("endata.y\n");

        printbuff(endata->y, ECCref_MAX_LEN);

        printf("endata.M\n");

        printbuff(endata->M, 32);

#ifdef STD20100816

        printf("endata.C\n");

        printbuff(endata->C, ECCref_MAX_LEN);

#else

        printf("endata.L is 0x%08x\n", endata->L);

        printf("endata.C\n");

        printbuff(endata->C, endata->L);

#endif
      }

      break;

    case 11:

      printf("Please input the Key Index (Index<=9999):");

      scanf("%d", &indexNum);

      printf("To get Privatekey access right,please input the password :");

      scanf("%s", pin);

      ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, indexNum, pin,
                                         strlen(pin));

      if (ret)

        printf(
            "SDF_GetPrivateKeyAccessRight failed! return: 0x%08x , 0x%08x\n",
            ret, SPII_GetErrorInfo(pSessionHandle));

      else

      {
        ret = SDF_InternalDecrypt_ECC(pSessionHandle, indexNum, SGD_SM2_3,
                                      endata, data, &len);

        if (ret)

          printf("SDF_InternalDecrypt_ECC failed! return: 0x%08x, 0x%08x\n",
                 ret, SPII_GetErrorInfo(pSessionHandle));

        else
        {
          printf("Decrypt Succeed!\n");

          printf("The data is :\n");

          printbuff(data, len);
        }

        free(endata);
      }

      break;

    case 0:

      ret = SDF_CloseSession(pSessionHandle);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_CloseSession error! return is %08x \n", ret);

      else

        printf("Close Session succeed!\n");

      ret = SDF_CloseDevice(DeviceHandle);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_CloseDevice error! return is %08x \n", ret);

      else

        printf("CloseDevice succeed!\n");

      return;

    default:

      return;
    }
  }
}

void KEKManage()

{
  int select, ret;
  unsigned int len = 16, indexNum;

  unsigned char data[32];

  HANDLE DeviceHandle, pSessionHandle, phKeyHandle1, phKeyHandle2, phKeyHandle3;

  ret = SDF_OpenDevice(&DeviceHandle);

  if (ret != SR_SUCCESSFULLY)

    printf("SDF_OpenDevice error!return is %08x\n", ret);

  else

    printf("OpenDevice succeed!the DeviceHandle is %x\n", DeviceHandle);

  ret = SDF_OpenSession(DeviceHandle, &pSessionHandle);

  if (ret != SR_SUCCESSFULLY)

    printf("SDF_OpenSession error!return is %08x\n", ret);

  else

    printf("OpenSession succeed!the SessionHandle is %x\n", pSessionHandle);

  while (1)

  {
    printf("          SDF_GenerateKeyWithKEK ------------- 1\n");

    printf("          SDF_ImportKeyWithKEK --------------- 2\n");

    printf("          SDF_ImportKey ---------------------- 3\n");

    printf("          SDF_DestroyKey --------------------- 4\n");

    printf("          Quit ------------------------------- 0\n");

    printf("    please input your select:");

    scanf("%d", &select);

    switch (select)

    {
    case 1:

      printf("Please input the Key Index (1<=Index<=128):");

      scanf("%d", &indexNum);

      ret = SDF_GenerateKeyWithKEK(pSessionHandle, 128, SGD_SM4_ECB, indexNum,
                                   data, &len, &phKeyHandle1);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_GenerateKeyKEK error!return is %08x\n", ret);

      else
      {
        printf("GenerateKey succeed!the Handle is %08x\n", phKeyHandle1);

        printf("The encrypt key is :\n");

        printbuff(data, len);
      }

      break;

    case 2:

      printf("Please input the Key Index (1<=Index<=128):");

      scanf("%d", &indexNum);

      ret = SDF_ImportKeyWithKEK(pSessionHandle, SGD_SM4_ECB, indexNum, data,
                                 len, &phKeyHandle2);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_ImportKeyKEK error!return is %08x\n", ret);

      else

        printf("ImportKey succeed!the Handle is %08x\n", phKeyHandle2);

      break;

    case 3:

      ret = SDF_ImportKey(pSessionHandle, data, len, &phKeyHandle3);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_ImportKey error!return is %08x\n", ret);

      else

        printf("ImportKey succeed!the Handle is %08x\n", phKeyHandle3);

      break;

    case 4:

      ret = SDF_DestroyKey(pSessionHandle, phKeyHandle1);
      if (ret != SR_SUCCESSFULLY)
        printf("SDF_DestroyKey keyHandle 1 error!return is %08x\n", ret);
      else
        printf("KeyHandle 1 DestoryKey succeed!\n");
      ret = SDF_DestroyKey(pSessionHandle, phKeyHandle2);
      if (ret != SR_SUCCESSFULLY)
        printf("SDF_DestroyKey keyHandle 2 error!return is %08x\n", ret);
      else
        printf("KeyHandle 2 DestoryKey succeed!\n");
      ret = SDF_DestroyKey(pSessionHandle, phKeyHandle3);
      if (ret != SR_SUCCESSFULLY)
        printf("SDF_DestroyKey keyHandle 3 error!return is %08x\n", ret);
      else
        printf("DestoryKey keyHandle 3 succeed!\n");

      break;

    case 0:

      ret = SDF_CloseSession(pSessionHandle);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_CloseSession error! return is %08x \n", ret);

      else

        printf("Close Session succeed!\n");

      ret = SDF_CloseDevice(DeviceHandle);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_CloseDevice error! return is %08x \n", ret);

      else

        printf("CloseDevice succeed!\n");

      return;

    default:

      return;
    }
  }
}

void ECCKeyManage()

{
  int select, ret, len, enlen, dnlen, indexNum, indexNum2;

  ECCrefPublicKey pk, spks, spkt, rpks, rpkt;

  ECCrefPrivateKey vk;

  ECCCipher *data;

  unsigned char data1[350], endata[350], data2[350];

  unsigned char pin[256];

  HANDLE DeviceHandle, pSessionHandle, phKeyHandle, phKeyHandle1, phKeyHandle2,
      AgreementHandle;

  ret = SDF_OpenDevice(&DeviceHandle);

  if (ret != SR_SUCCESSFULLY)

    printf("SDF_OpenDevice error!return is %08x\n", ret);

  else

    printf("OpenDevice succeed!the DeviceHandle is 0x%08x\n", DeviceHandle);

  ret = SDF_OpenSession(DeviceHandle, &pSessionHandle);

  if (ret != SR_SUCCESSFULLY)

    printf("SDF_OpenSession error!return is %08x\n", ret);

  else

    printf("OpenSession succeed!the SessionHandle is 0x%08x\n", pSessionHandle);

  data = malloc(sizeof(ECCCipher) + 16);

  while (1)

  {
    printf("          SDF_ExportSignPublicKey_ECC -------- 1\n");

    printf("          SDF_ExportEncPublicKey_ECC --------- 2\n");

    printf("          SDF_GenerateKeyPair_ECC ------------ 3\n");

    printf("          SDF_GenerateKeyWithIPK_ECC --------- 4\n");

    printf("          SDF_GenerateKeyWithEPK_ECC --------- 5\n");

    printf("          SDF_ImportKeyWithISK_ECC ----------- 6\n");

    printf("          SDF_ExchangeDigitEnvelopeBaseOnECC - 7\n");

    printf("          ECC Agreement ---------------------- 8\n");

    printf("          Quit ------------------------------- 0\n");

    printf("    please input your select:");

    scanf("%d", &select);

    switch (select)

    {
    case 1:

      printf("Please input the Key Index (Index<=18):");

      scanf("%d", &indexNum);

      ret = SDF_ExportSignPublicKey_ECC(pSessionHandle, indexNum, &pk);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_ExportSignPublicKey_ECC error!return is %08x %08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

      else
      {
        printf("GetECCSignPK  succeed!\n");

        printf("bits:%d\n", pk.bits);

        printf("x:\n");

        printbuff(pk.x, ECCref_MAX_LEN);

        printf("y:\n");

        printbuff(pk.y, ECCref_MAX_LEN);
      }

      break;

    case 2:

      printf("Please input the Key Index (Index<=18):");

      scanf("%d", &indexNum);

      ret = SDF_ExportEncPublicKey_ECC(pSessionHandle, indexNum, &pk);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_ExportEncPublicKey_ECC error!return is %08x %08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

      else
      {
        printf("GetECCEncPK  succeed!\n");

        printf("bits:%d\n", pk.bits);

        printf("x:\n");

        printbuff(pk.x, ECCref_MAX_LEN);

        printf("y:\n");

        printbuff(pk.y, ECCref_MAX_LEN);
      }

      break;

    case 3:

      len = 256;

      ret = SDF_GenerateKeyPair_ECC(pSessionHandle, SGD_SM2_1, len, &pk, &vk);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_GenerateKey_ECC error!return is %08x %08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

      else
      {
        printf("GenECCKeyPair  succeed!\n");

        printf("pk.bits:%d\n", pk.bits);

        printf("pk.x:\n");

        printbuff(pk.x, ECCref_MAX_LEN);

        printf("pk.y:\n");

        printbuff(pk.y, ECCref_MAX_LEN);

        printf("====================\n");

        printf("vk.bits:%d\n", vk.bits);

        printf("vk.K:\n");

        printbuff(vk.K, ECCref_MAX_LEN);
      }

      break;

    case 4:

      printf("Please input the Key Index (Index<=18):");

      scanf("%d", &indexNum);

      ret = SDF_GenerateKeyWithIPK_ECC(pSessionHandle, indexNum, 128, data,
                                       &phKeyHandle);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_GenerateKeyWithIPK_ECC error!return is %08x %08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

      else
      {
        printf("GenerateKey succeed!the Handle is %08x\n", phKeyHandle);

        printf("The encrypt key is :\n");

        printf("data.x\n");

        printbuff(data->x, ECCref_MAX_LEN);

        printf("data.y\n");

        printbuff(data->y, ECCref_MAX_LEN);

        printf("data.C\n");

#ifdef STD20100816

        printbuff(data->C, ECCref_MAX_LEN);

#else

        printbuff(data->C, data->L);

#endif

        printf("data.M\n");

        printbuff(data->M, 32);
      }

      break;

    case 5:

      ret = SDF_GenerateKeyWithEPK_ECC(pSessionHandle, 128, SGD_SM2_3, &pk,
                                       data, &phKeyHandle);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_GenerateKeyWithEPK_ECC error!return is %08x %08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

      else
      {
        printf("GenerateKey succeed!the Handle is %08x\n", phKeyHandle);

        printf("The encrypt key is :\n");

        printf("data.x\n");

        printbuff(data->x, ECCref_MAX_LEN);

        printf("data.y\n");

        printbuff(data->y, ECCref_MAX_LEN);

        printf("data.C\n");

#ifdef STD20100816

        printbuff(data->C, ECCref_MAX_LEN);

#else

        printbuff(data->C, data->L);

#endif

        printf("data.M\n");

        printbuff(data->M, 32);
      }

      break;

    case 6:

      printf("Please input the Key Index (Index<=18):");

      scanf("%d", &indexNum);

      printf("To get Privatekey access right,please input the password :");

      scanf("%s", pin);

      ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, indexNum, pin,
                                         strlen(pin));

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_GetPrivateKeyAccessRight error! return is %08x  %08x\n",
               ret, SPII_GetErrorInfo(pSessionHandle));

      else

      {
        ret = SDF_ImportKeyWithISK_ECC(pSessionHandle, indexNum, data,
                                       &phKeyHandle);

        if (ret != SR_SUCCESSFULLY)

          printf("SDF_ImportKeyWithISK_ECC error!return is %08x %08x\n", ret,
                 SPII_GetErrorInfo(pSessionHandle));

        else

          printf("ImportKey succeed!the Handle is %08x\n", phKeyHandle);
      }

      break;

    case 7:

      printf("Please input the key Index (Index<=18)");

      scanf("%d", &indexNum);

      printf("To get Privatekey access right,please input the password :");

      scanf("%s", pin);

      ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, indexNum, pin,
                                         strlen(pin));

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_GetPrivateKeyAccessRight error! return is %08x  %08x\n",
               ret, SPII_GetErrorInfo(pSessionHandle));

      else
      {
        ret = SDF_ExchangeDigitEnvelopeBaseOnECC(pSessionHandle, indexNum,
                                                 SGD_SM2_3, &pk, data,
                                                 (ECCCipher *)data2);

        if (ret != SR_SUCCESSFULLY)

          printf("SDF_ExchangeDigitEnvelope_ECC error!return is %08x %08x\n",
                 ret, SPII_GetErrorInfo(pSessionHandle));

        else
        {
          printf(" succeed!");

          printf("The encrypt key is :\n");

          printf("data.x\n");

          printbuff(((ECCCipher *)data2)->x, ECCref_MAX_LEN);

          printf("data.y\n");

          printbuff(((ECCCipher *)data2)->y, ECCref_MAX_LEN);

          printf("data.C\n");

#ifdef STD20100816

          printbuff(((ECCCipher *)data2)->C, ECCref_MAX_LEN);

#else

          printbuff(((ECCCipher *)data2)->C, data->L);

#endif

          printf("data.M\n");

          printbuff(((ECCCipher *)data2)->M, 32);
        }
      }

      break;

    case 8:

      printf("Please input the Sponsor key Index (Index<=18)");

      scanf("%d", &indexNum);

      printf("To get Privatekey access right,please input the password :");

      scanf("%s", pin);

      ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, indexNum, pin,
                                         strlen(pin));

      if (ret != SR_SUCCESSFULLY)

      {
        printf("SDF_GetPrivateKeyAccessRight error! return is %08x  %08x\n",
               ret, SPII_GetErrorInfo(pSessionHandle));

        break;
      }

      printf("Please input the ReSponsor key Index (1<=Index<=18)");

      scanf("%d", &indexNum2);

      printf("To get Privatekey access right,please input the password :");

      scanf("%s", pin);

      ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, indexNum2, pin,
                                         strlen(pin));

      if (ret != SR_SUCCESSFULLY)

      {
        printf("SDF_GetPrivateKeyAccessRight error! return is %08x  %08x\n",
               ret, SPII_GetErrorInfo(pSessionHandle));

        break;
      }

      ret = SDF_GenerateAgreementDataWithECC(pSessionHandle, indexNum, 128,
                                             NULL, 0, &spks, &spkt,
                                             &AgreementHandle);

      if (ret != SR_SUCCESSFULLY)

      {
        printf(
            "SDF_GenerateAgreementDataWithECC error! return is %08x  %08x\n",
            ret, SPII_GetErrorInfo(pSessionHandle));

        break;
      }

      else

        printf("SDF_GenerateAgreementDataWithECC succeed!\n");

      printf("spks.bits:%d\n", spks.bits);

      printf("spks.x:\n");

      printbuff(spks.x, ECCref_MAX_LEN);

      printf("spks.y:\n");

      printbuff(spks.y, ECCref_MAX_LEN);

      printf("========================\n");

      printf("spkt.bits:%d\n", spkt.bits);

      printf("spkt.x:\n");

      printbuff(spkt.x, ECCref_MAX_LEN);

      printf("spkt.y:\n");

      printbuff(spkt.y, ECCref_MAX_LEN);

      ret = SDF_GenerateAgreementDataAndKeyWithECC(
          pSessionHandle, indexNum2, 128, NULL, 0, NULL, 0, &spks, &spkt,
          &rpks, &rpkt, &phKeyHandle1);

      if (ret != SR_SUCCESSFULLY)

      {
        printf(
            "SDF_GenerateAgreementDataAndKeyWithECC error! return is %08x  "
            "%08x\n",
            ret, SPII_GetErrorInfo(pSessionHandle));

        ret = SPII_DestroyAgreementHandle(pSessionHandle, AgreementHandle);

        if (ret != SR_SUCCESSFULLY)

          printf("SPII_DestroyAgreementHandle error! return is %08x  %08x\n",
                 ret, SPII_GetErrorInfo(pSessionHandle));

        break;
      }

      else

        printf(
            "SDF_GenerateAgreementDataAndKeyWithECC succeed!the KeyHandle1 "
            "is %08x\n",
            phKeyHandle1);

      ret = SDF_GenerateKeyWithECC(pSessionHandle, NULL, 0, &rpks, &rpkt,
                                   AgreementHandle, &phKeyHandle2);

      if (ret != SR_SUCCESSFULLY)

      {
        printf("SDF_GenerateKeyWithECC error! return is %08x  %08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

        SPII_DestroyAgreementHandle(pSessionHandle, AgreementHandle);

        SDF_DestroyKey(pSessionHandle, phKeyHandle1);

        break;
      }

      else

        printf("SDF_GenerateKeyWithECC succeed!the KeyHandle2 is %08x\n",
               phKeyHandle2);

      //	SPII_DestroyAgreementHandle(pSessionHandle,AgreementHandle);

      len = 32;

      for (ret = 0; ret < len; ret++)
        data1[ret] = ret;

      ret = SDF_Encrypt(pSessionHandle, phKeyHandle1, SGD_SM1_ECB, NULL,
                        data1, len, endata, &enlen);

      if (ret != SR_SUCCESSFULLY)

      {
        printf("SDF_Encrypt with Handle1 error!ret is %08x  %08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

        SDF_DestroyKey(pSessionHandle, phKeyHandle1);

        SDF_DestroyKey(pSessionHandle, phKeyHandle2);

        break;
      }

      else

        printf("SDF_Encrypt with Handle1 succeed!\n");

      ret = SDF_Decrypt(pSessionHandle, phKeyHandle2, SGD_SM1_ECB, NULL,
                        endata, enlen, data2, &dnlen);

      if (ret != SR_SUCCESSFULLY)

      {
        printf("SDF_Decrypt with Handle2 error!ret is %08x  %08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

        SDF_DestroyKey(pSessionHandle, phKeyHandle1);

        SDF_DestroyKey(pSessionHandle, phKeyHandle2);

        break;
      }

      else

        printf("SDF_Decrypt with Handle2 succeed!\n");

      if (memcmp(data1, data2, dnlen) == 0)

        printf("The Agreement Key succeed!\n");

      else

        printf("The Agreement Key failed!\n");

      SDF_DestroyKey(pSessionHandle, phKeyHandle1);

      SDF_DestroyKey(pSessionHandle, phKeyHandle2);

      break;

    case 0:

      free(data);

      ret = SDF_CloseSession(pSessionHandle);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_CloseSession error! return is %08x  %08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

      else

        printf("Close Session succeed!\n");

      ret = SDF_CloseDevice(DeviceHandle);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_CloseDevice error! return is %08x  %08x\n", ret,
               SPII_GetErrorInfo(0));

      else

        printf("CloseDevice succeed!\n");

      return;

    default:

      return;
    }
  }

} /**/

void KeyManage()

{
  int select;

  while (1)

  {
    printf("          ECC KEY Manage --------------------- 2\n");

    printf("          KEK KEY Manage --------------------- 3\n");

    printf("          Quit ------------------------------- 0\n");

    printf("    please input your select:");

    scanf("%d", &select);

    switch (select)

    {
      /*			case 1:

                                      RSAKeyManage();

                                      break;

      */
    case 2:

      ECCKeyManage();

      break;

    case 3:

      KEKManage();

      break;

    case 0:

      return;

    default:

      break;
    }
  }

  /**/
}

void DeviceManage()

{
  HANDLE DeviceHandle = NULL, pSessionHandle = NULL;

  int select, ret, len, indexNum;

  DEVICEINFO DeInfo;

  unsigned char pin[256];
  unsigned char *data = NULL;
  unsigned char DeviceSerial[17] = {0};

  ret = SDF_OpenDevice(&DeviceHandle);

  if (ret != SR_SUCCESSFULLY)

    printf("SDF_OpenDevice error!return is %08x\n", ret);

  else

    printf("OpenDevice succeed!the DeviceHandle is %x\n", DeviceHandle);

  while (1)

  {
    printf("          SDF_OpenSession -------------------- 3\n");

    printf("          SDF_CloseSession ------------------- 4\n");

    printf("          SDF_GetDeviceInfo ------------------ 5\n");

    printf("          SDF_GenerateRandom ----------------- 6\n");

    printf("          SDF_GetPrivateKeyAccessRight ------- 7\n");

    printf("          SDF_ReleasePrivateKeyAccessRight --- 8\n");

    printf("          Quit ------------------------------- 0\n");

    printf("    please input your select:");

    scanf("%d", &select);

    switch (select)

    {
    case 3:

      ret = SDF_OpenSession(DeviceHandle, &pSessionHandle);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_OpenSession error!return is %08x\n", ret);

      else

        printf("OpenSession succeed!the SessionHandle is %x\n",
               pSessionHandle);

      break;

    case 4:

      ret = SDF_CloseSession(pSessionHandle);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_CloseSession error!return is %08x\n", ret);

      else

        printf("CloseSession succeed!\n");

      break;

    case 5:

      ret = SDF_GetDeviceInfo(pSessionHandle, &DeInfo);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_GetDeviceInfo error!return is %08x %08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

      else
      {
        printf("GetDeviceInfo succeed!\n");

        printf("DeInfo.IssuerName:\n");

        //		printbuff(DeInfo.IssuerName,40);

        printf("%s\n", DeInfo.IssuerName);

        printf("DeInfo.DeviceName:\n");

        //		printbuff(DeInfo.DeviceName,16);

        printf("%s\n", DeInfo.DeviceName);

        printf("DeInfo.DeviceSerial:\n");

        //		printbuff(DeInfo.DeviceSerial,16);
        memcpy(DeviceSerial, DeInfo.DeviceSerial, 16);
        printf("%s\n", DeviceSerial);

        printf("DeInfo.DeviceVersion:%08x\n", DeInfo.DeviceVersion);

        printf("DeInfo.StandardVersion:%08x\n", DeInfo.StandardVersion);

        printf("DeInfo.AsymAlgAbility:%08x %08x\n", DeInfo.AsymAlgAbility[0],
               DeInfo.AsymAlgAbility[1]);

        printf("DeInfo.SymAlgAbility:%08x\n", DeInfo.SymAlgAbility);

        printf("DeInfo.HashAlgAbility:%08x\n", DeInfo.HashAlgAbility);

        printf("DeInfo.BufferSize:%08x\n", DeInfo.BufferSize);
      }

      break;

    case 6:

      printf("please input the Random length(0<length):");

      scanf("%d", &len);
      data = malloc(len);

      ret = SDF_GenerateRandom(pSessionHandle, len, data);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_GenerateRandom error!return is %08x\n", ret);

      else
      {
        printf("Get Random succeed!\n");
        /*	if(len>16)
                {
                        printbuff(data,16);
                        printf(". . . . . . .\n");
                        printbuff(data+len-len%16,len%16);
                }
                else*/
        printbuff(data, len);
      }
      free(data);

      break;

    case 7:

      printf("please input the index (0<=index<=18):");

      scanf("%d", &indexNum);

      printf("please input the password:");

      scanf("%s", pin);

      ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, indexNum, pin,
                                         strlen(pin));

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_GetPrivateKeyAccessRight error! return is %08x %08x\n",
               ret, SPII_GetErrorInfo(pSessionHandle));

      else

        printf("Get Right succeed!\n");

      break;

    case 8:

      printf("please input the index (0<=index<=18):");

      scanf("%d", &indexNum);

      ret = SDF_ReleasePrivateKeyAccessRight(pSessionHandle, indexNum);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_ReleasePrivateKeyAccessRight error! return is %08x \n",
               ret);

      else

        printf("Release Right succeed!\n");

      break;

    case 0:

      ret = SDF_CloseDevice(DeviceHandle);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_CloseDevice error! return is %08x \n", ret);

      else

        printf("CloseDevice succeed!\n");

      return;

    default:

      break;
    }
  }
}

void FileTest()

{
  HANDLE DeviceHandle, pSessionHandle;

  int select, ret, filelen, offset, i;

  unsigned int writelen, readlen;

  unsigned char pin[256];

  unsigned char *data, *outdata;

  memset(pin, 0, 246);

  ret = SDF_OpenDevice(&DeviceHandle);

  if (ret != SR_SUCCESSFULLY)

    printf("SDF_OpenDevice error!return is %08x\n", ret);

  else

    printf("OpenDevice succeed!the DeviceHandle is %x\n", DeviceHandle);

  ret = SDF_OpenSession(DeviceHandle, &pSessionHandle);

  if (ret != SR_SUCCESSFULLY)

    printf("SDF_OpenSession error!return is %08x\n", ret);

  else

    printf("OpenSession succeed!the SessionHandle is 0x%08x\n", pSessionHandle);

  while (1)

  {
    printf("          SDF_CreateFile ---------------------- 1\n");

    printf("          SDF_WriteFile ---------------------- 2\n");

    printf("          SDF_ReadFile ----------------------- 3\n");

    printf("          SDF_DeleteFile --------------------- 4\n");

    printf("          Quit ------------------------------- 0\n");

    printf("    please input your select:");

    scanf("%d", &select);

    switch (select)

    {
    case 1:

      printf("Please input the File name:");

      scanf("%s", pin);

      printf("Please input the File length:");

      scanf("%d", &filelen);

      ret = SDF_CreateFile(pSessionHandle, pin, strlen(pin), filelen);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_CreatFile error!return is %08x\n", ret);

      else

        printf("SDF_CreatFile succeed!\n");

      break;

    case 2:

      printf("Please input the File name:");

      scanf("%s", pin);

      printf("Please input the write offset:");

      scanf("%d", &offset);

      printf("Please input the write length:");

      scanf("%d", &writelen);

      data = malloc(writelen);

      for (i = 0; i < writelen; i++)
        data[i] = i;

      ret = SDF_WriteFile(pSessionHandle, pin, strlen(pin), offset, writelen,
                          data);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_WriteFile error!return is %08x\n", ret);

      else

        printf("SDF_WriteFile succeed!the writelength is %08x\n", writelen);

      free(data);

      break;

    case 3:

      printf("Please input the File name:");

      scanf("%s", pin);

      printf("Please input the read offset:");

      scanf("%d", &offset);

      printf("Please input the read length:");

      scanf("%d", &readlen);

      outdata = malloc(readlen);

      ret = SDF_ReadFile(pSessionHandle, pin, strlen(pin), offset, &readlen,
                         outdata);

      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_ReadFile error!return is %08x\n", ret);
      }
      else

      {
        printbuff(outdata, readlen);

        printf("SDF_ReadFile succeed!the readlen is %08x\n", readlen);
      }

      free(outdata);

      break;

    case 4:

      printf("Please input the File name:");

      scanf("%s", pin);

      ret = SDF_DeleteFile(pSessionHandle, pin, strlen(pin));

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_DeleteFile error!return is %08x\n", ret);

      else

        printf("SDF_DeleteFile succeed!\n");

      break;

    case 0:

    default:

      ret = SDF_CloseSession(pSessionHandle);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_CloseSession error! return is %08x \n", ret);

      else

        printf("Close Session succeed!\n");

      ret = SDF_CloseDevice(DeviceHandle);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_CloseDevice error! return is %08x \n", ret);

      else

        printf("CloseDevice succeed!\n");

      return;
    }
  }
}

void EnCapTest(unsigned int Alog, struct timeval *starttime,
               struct timeval *endtime, unsigned int *testlen,
               unsigned int *testtimes)

{
  HANDLE KeyHandlen1, DeviceHandle, pSessionHandle;

  unsigned char key[16], ivdata[16], ivdata2[16];

  unsigned char data[DATALEN], endata[DATALEN], data2[DATALEN];

  int len, ret, select, i, relen, testtime;

  ret = SDF_OpenDevice(&DeviceHandle);

  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenDevice error!return is %08x\n", ret);
    return;
  }
  else
    printf("OpenDevice succeed!the DeviceHandle is %x\n", DeviceHandle);
  ret = SDF_OpenSession(DeviceHandle, &pSessionHandle);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenSession error!return is %08x\n", ret);
    ret = SDF_CloseSession(pSessionHandle);
    return;
  }
  else
    printf("OpenSession succeed!the SessionHandle is %x\n", pSessionHandle);
  ret = SDF_ImportKey(pSessionHandle, key, 16, &KeyHandlen1);
  if (ret != SDR_OK)
  {
    printf("SDF_ImportKey error! and return is %08x \n", ret);
    return;
  }
  printf("Please input test length:");
  scanf("%d", &len);
  *testlen = len;
  printf("Please input test times:");
  scanf("%d", &testtime);
  *testtimes = testtime;
  gettimeofday(starttime, 0);
  for (i = 0; i < testtime; i++)
  {
    if (Alog != SGD_SM3)
    {
      ret = SDF_Encrypt(pSessionHandle, KeyHandlen1, Alog, NULL, data, len,
                        endata, &relen);
      if (ret != SDR_OK)
      {
        printf("SDF_Encrypt error! and return is %08x %08x", ret,
               SPII_GetErrorInfo(pSessionHandle));
        break;
      }
      ret = SDF_Decrypt(pSessionHandle, KeyHandlen1, Alog, NULL, endata, relen,
                        data2, &relen);
      if (ret != SDR_OK)
      {
        printf("SDF_Decrypt error! and return is %08x %08x ", ret,
               SPII_GetErrorInfo(pSessionHandle));
        break;
      }
      if (memcmp(data, data2, relen) != 0)
        printf("%d times Compare error!\n", i);
      if (i % 1000 == 0)
        printf("%d times test....\n", i);
    }
    else
    {
      ret = SDF_HashInit(pSessionHandle, Alog, NULL, NULL, 0);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_HashInit error!return is %08,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        break;
      }
      ret = SDF_HashUpdate(pSessionHandle, data, len);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_HashUpdate error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        break;
      }
      ret = SDF_HashFinal(pSessionHandle, endata, &relen);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_HashFinal error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        break;
      }
      ret = SDF_HashInit(pSessionHandle, Alog, NULL, NULL, 0);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_HashInit error!return is %08,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        break;
      }
      ret = SDF_HashUpdate(pSessionHandle, data, len);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_HashUpdate error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        break;
      }
      ret = SDF_HashFinal(pSessionHandle, endata, &relen);
      if (ret != SR_SUCCESSFULLY)
      {
        printf("SDF_HashFinal error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));
        SDF_CloseSession(pSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        break;
      }
    }
    if (i % 1000 == 0)
      printf("%d SM3 times test....\n", i);
  }
  gettimeofday(endtime, 0);
  ret = SDF_DestroyKey(pSessionHandle, KeyHandlen1);
  ret = SDF_CloseSession(pSessionHandle);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_CloseSession error! return is %08x \n", ret);
  else
    printf("Close Session succeed!\n");
  ret = SDF_CloseDevice(DeviceHandle);
  if (ret != SR_SUCCESSFULLY)
    printf("SDF_CloseDevice error! return is %08x \n", ret);
  else
    printf("CloseDevice succeed!\n");
  return;
}

void CapabilityStat(struct timeval *starttime, struct timeval *endtime,
                    unsigned int testlen, unsigned int testtimes)

{
  float rate, spendtimes;

  int sec, msec;

  if ((endtime->tv_usec - starttime->tv_usec) < 0)

  {
    msec = endtime->tv_usec / 1000.0 + 1000 - starttime->tv_usec / 1000.0;

    sec = endtime->tv_sec - starttime->tv_sec - 1;
  }

  else

  {
    msec = endtime->tv_usec / 1000.0 - starttime->tv_usec / 1000.0;

    sec = endtime->tv_sec - starttime->tv_sec;
  }

  spendtimes = ((float)msec / 1000 + sec);

  //	printf("spend times is %f seconds\n",spendtimes);

  if (testlen != 0)

  {
    printf("================================\n");

    printf("Test length is: %d Bytes\n", testlen);

    printf("Test times is: %d\n", testtimes);

    rate = testtimes * testlen * 2 * 8 / 1024;

    rate = rate / spendtimes / 1024;

    printf("time consuming:%f seconds\nrate:%fMbps\n", spendtimes, rate);

    printf("================================\n");
  }

  else

  {
    printf("================================\n");

    rate = testtimes / spendtimes;

    printf("Test times is: %d\n", testtimes);

    printf("spend second:%f seconds \nrate:%ftimes/sec\n", spendtimes, rate);

    printf("================================\n");
  }
}

void SignTest(unsigned int alog, struct timeval *starttime,
              struct timeval *endtime, unsigned int *testtimes)

{
  unsigned char pincode[16] = {"wuxipiico"};

  int indexNum = 1;

  HANDLE KeyHandlen1, DeviceHandle, pSessionHandle;

  unsigned char key[16], ivdata[16], ivdata2[16];

  unsigned char data[256], pachdata[256], endata[256], sigdata[256];

  int len, ret, select, i, relen, testtime;

  RSArefPublicKey rsapk;

  RSArefPrivateKey rsavk;

  ECCrefPublicKey eccpk;

  ECCrefPrivateKey eccvk;

  ECCCipher *eccendata;

  ECCSignature signdata;

  ret = SDF_OpenDevice(&DeviceHandle);

  if (ret != SR_SUCCESSFULLY)

  {
    printf("SDF_OpenDevice error!return is %08x\n", ret);

    return;
  }

  else

    printf("OpenDevice succeed!the DeviceHandle is %x\n", DeviceHandle);

  ret = SDF_OpenSession(DeviceHandle, &pSessionHandle);

  if (ret != SR_SUCCESSFULLY)

  {
    printf("SDF_OpenSession error!return is %08x\n", ret);

    ret = SDF_CloseSession(pSessionHandle);

    return;
  }

  else

    printf("OpenSession succeed!the SessionHandle is %x\n", pSessionHandle);

  ret = SDF_GetPrivateKeyAccessRight(pSessionHandle, indexNum, pincode, 9);

  if (ret != SR_SUCCESSFULLY)

  {
    printf("SDF_GetPrivateKeyAccessRight error! return is %08x \n", ret);

    SDF_CloseSession(pSessionHandle);

    SDF_CloseDevice(DeviceHandle);

    return;
  }

  else

    printf("Get Right succeed!\n");

  memset(data, 0x7e, 16);

  printf("please input the test times:");

  scanf("%d", &testtime);

  *testtimes = testtime;

  switch (alog)

  {
  case 13:
    ret = SDF_GenerateKeyPair_ECC(pSessionHandle, SGD_SM2_1, 256, &eccpk,
                                  &eccvk);

    if (ret != SR_SUCCESSFULLY)

    {
      printf("SDF_GenerateKeyPair_ECC error!return is %08x\n", ret);

      break;
    }
    gettimeofday(starttime, 0);

    for (i = 0; i < testtime; i++)

    {
      ret = SDF_ExternalSign_ECC(pSessionHandle, SGD_SM2_1, &eccvk, data, 32,
                                 &signdata);

      if (ret != SR_SUCCESSFULLY)

      {
        printf("SDF_ExternalSign_ECC error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

        break;
      }

      if (i % 1000 == 0)
        printf("%d times test.....\n", i);
    }

    gettimeofday(endtime, 0);
    ret = SDF_ExternalVerify_ECC(pSessionHandle, SGD_SM2_1, &eccpk, data, 32,
                                 &signdata);

    if (ret != SR_SUCCESSFULLY)

      printf("SDF_ExternalVerify_ECC error!return is %08x  %08x\n", ret,
             SPII_GetErrorInfo(pSessionHandle));

    break;

  case 5:

    gettimeofday(starttime, 0);

    for (i = 0; i < testtime; i++)

    {
      ret =
          SDF_InternalSign_ECC(pSessionHandle, indexNum, data, 32, &signdata);

      if (ret != SR_SUCCESSFULLY)

      {
        printf("SDF_InternalSign_ECC error!return is %08x %08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

        break;
      }

      if (i % 1000 == 0)
        printf("%d times test.....\n", i);
    }

    gettimeofday(endtime, 0);

    ret = SDF_ExportSignPublicKey_ECC(pSessionHandle, indexNum, &eccpk);

    if (ret != SR_SUCCESSFULLY)

    {
      printf("SDF_ExportSignPublicKey_ECC error!return is %08x %08x\n", ret,
             SPII_GetErrorInfo(pSessionHandle));

      SDF_CloseSession(pSessionHandle);

      SDF_CloseDevice(DeviceHandle);

      return;
    }

    ret = SDF_ExternalVerify_ECC(pSessionHandle, SGD_SM2_1, &eccpk, data, 32,
                                 &signdata);

    if (ret != SR_SUCCESSFULLY)

      printf("SDF_ExternalVerify_ECC error!return is %08x %08x\n", ret,
             SPII_GetErrorInfo(pSessionHandle));

    break;

  case 6:

    ret = SDF_InternalSign_ECC(pSessionHandle, indexNum, data, 32, &signdata);

    if (ret != SR_SUCCESSFULLY)

    {
      printf("SDF_InternalSign_ECC error!return is %08x %08x\n", ret,
             SPII_GetErrorInfo(pSessionHandle));

      break;
    }
    gettimeofday(starttime, 0);

    for (i = 0; i < testtime; i++)

    {
      ret = SDF_ExportSignPublicKey_ECC(pSessionHandle, indexNum, &eccpk);

      if (ret != SR_SUCCESSFULLY)

      {
        printf("SDF_ExportSignPublicKey_ECC error!return is %08x %08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

        SDF_CloseSession(pSessionHandle);

        SDF_CloseDevice(DeviceHandle);

        return;
      }

      ret = SDF_ExternalVerify_ECC(pSessionHandle, SGD_SM2_1, &eccpk, data,
                                   32, &signdata);

      if (ret != SR_SUCCESSFULLY)

      {
        printf("SDF_ExternalVerify_ECC error!return is %08x %08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

        break;
      }

      if (i % 1000 == 0)
        printf("%d times test.....\n", i);
    }

    gettimeofday(endtime, 0);

    break;

#if 0
		case 7:

			printf("Please input test length :1024 or 2048:");

			scanf("%d",&relen);

			ret=SPII_GenerateSignKeyPair_RSA(pSessionHandle,indexNum,relen);

			if(ret!=SR_SUCCESSFULLY)

			{

				printf("Generate %d Sign RSA KeyPair failed and return is %08x,%08x\n",indexNum,ret,SPII_GetErrorInfo(pSessionHandle));

				SDF_ReleasePrivateKeyAccessRight(pSessionHandle,indexNum);

				break;

			}

			ret=SDF_ExportSignPublicKey_RSA(pSessionHandle,indexNum,&rsapk);

			if(ret!=SR_SUCCESSFULLY)

			{

				printf("SDF_ExportSignPublicKey_RSA error!return is %08x\n",ret);

				SDF_CloseSession(pSessionHandle);

				SDF_CloseDevice(DeviceHandle);

				return;

			}

			SPII_RsaPadding(pSessionHandle,rsapk.bits,data,16,pachdata,&relen,1);

			gettimeofday(starttime,0);

			for(i=0;i<testtime;i++)

			{

				ret=SDF_InternalPrivateKeyOperation_RSA(pSessionHandle,indexNum,pachdata,relen,sigdata,&len);

				if(ret!=SR_SUCCESSFULLY)

				{

					printf("SDF_InternalPrivateKeyOperation_RSA error!return is %08x\n",ret);

					break;

				}

				if(i%1000==0)

					printf("%d times test.....\n",i);

			}

			gettimeofday(endtime,0);

			ret=SDF_ExternalPublicKeyOperation_RSA(pSessionHandle,&rsapk,sigdata,len,endata,&relen);

			if(ret!=SR_SUCCESSFULLY)

			{

				printf("SDF_ExternalPublicKeyOperation_RSA error!return is %08x\n",ret);

				break;

			}

			ret=SPII_RsaEreasePadding(pSessionHandle,rsapk.bits,endata,relen,pachdata,&len,1);

			if(ret!=SR_SUCCESSFULLY)

			{

				printf("SPII_RsaEreasePadding error!\n");

				break;

				}

			if(memcmp(data,pachdata,len)!=0)

			{

				printf("Compare error!\n");

				printbuff(data,16);

				printbuff(pachdata,len);



			}

			break;

		case 8:

			printf("Please input test length :1024 or 2048:");

			scanf("%d",&relen);

			ret=SPII_GenerateSignKeyPair_RSA(pSessionHandle,indexNum,relen);

			if(ret!=SR_SUCCESSFULLY)

			{

				printf("Generate %d Sign RSA KeyPair failed and return is %08x,%08x\n",indexNum,ret,SPII_GetErrorInfo(pSessionHandle));

				SDF_ReleasePrivateKeyAccessRight(pSessionHandle,indexNum);

				break;

			}

			ret=SDF_ExportSignPublicKey_RSA(pSessionHandle,indexNum,&rsapk);

			if(ret!=SR_SUCCESSFULLY)

			{

				printf("SDF_ExportSignPublicKey_RSA error!return is %08x\n",ret);

				SDF_CloseSession(pSessionHandle);

				SDF_CloseDevice(DeviceHandle);

				return;

			}

			SPII_RsaPadding(pSessionHandle,rsapk.bits,data,16,pachdata,&relen,1);

			ret=SDF_InternalPrivateKeyOperation_RSA(pSessionHandle,indexNum,pachdata,relen,sigdata,&len);

			if(ret!=SR_SUCCESSFULLY)

			{

				printf("SDF_InternalPrivateKeyOperation_RSA error!return is %08x\n",ret);

				break;

			}

		//	printf("signdata len is %d,publickey->bits is %d\n",len,rsapk.bits);

			gettimeofday(starttime,0);

			for(i=0;i<testtime;i++)

			{

				ret=SDF_ExternalPublicKeyOperation_RSA(pSessionHandle,&rsapk,sigdata,len,endata,&relen);

				if(ret!=SR_SUCCESSFULLY)

				{

					printf("SDF_ExternalPublicKeyOperation_RSA error!return is %08x %08x\n",ret,SPII_GetErrorInfo(pSessionHandle));

					printf("signdata len is %d,publickey->bits is %d\n",len,rsapk.bits);

					break;

				}

				ret=SPII_RsaEreasePadding(pSessionHandle,rsapk.bits,endata,relen,pachdata,&relen,1);

			if(ret!=SR_SUCCESSFULLY)

			{

					printf("SPII_RsaEreasePadding error!\n");

					break;

				}

				if(memcmp(data,pachdata,relen)!=0)

				{

					printf("Compare error!\n");

					printbuff(data,16);

					printbuff(pachdata,len);

					break;

				}

				if(i%1000==0)

					printf("%d times test.....\n",i);

			}

			gettimeofday(endtime,0);

			break;

#endif
  case 10:

    ret = SDF_GenerateKeyPair_ECC(pSessionHandle, SGD_SM2_1, 256, &eccpk,
                                  &eccvk);

    if (ret != SR_SUCCESSFULLY)

    {
      printf("SDF_GenerateKeyPair_ECC error!return is %08x\n", ret);

      break;
    }

    eccendata = malloc(sizeof(ECCCipher) + 16);

    //	printf("signdata len is %d,publickey->bits is
    //%d\n",len,rsapk.bits);

    gettimeofday(starttime, 0);

    for (i = 0; i < testtime; i++)

    {
      ret = SDF_ExternalEncrypt_ECC(pSessionHandle, SGD_SM2_3, &eccpk, data,
                                    16, eccendata);

      if (ret != SR_SUCCESSFULLY)

      {
        printf("SDF_ExternalEncrypt_ECC error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

        // free(eccendata);

        break;
      }

      if (i % 1000 == 0)
        printf("%d times test.....\n", i);
    }

    gettimeofday(endtime, 0);

    ret = SDF_ExternalDecrypt_ECC(pSessionHandle, SGD_SM2_3, &eccvk,
                                  eccendata, pachdata, &relen);

    if (ret != SR_SUCCESSFULLY)

      printf("SDF_ExternalDecrypt_ECC error!return is %08x,%08x\n", ret,
             SPII_GetErrorInfo(pSessionHandle));

    if (memcmp(data, pachdata, relen) != 0)

    {
      printf("Compare error!\n");

      printbuff(data, 16);

      printbuff(pachdata, len);
    }

    free(eccendata);

    break;

  case 11:

    ret = SDF_GenerateKeyPair_ECC(pSessionHandle, SGD_SM2_1, 256, &eccpk,
                                  &eccvk);

    if (ret != SR_SUCCESSFULLY)

    {
      printf("SDF_GenerateKeyPair_ECC error!return is %08x\n", ret);

      break;
    }

    eccendata = malloc(sizeof(ECCCipher) + 16);

    //	printf("signdata len is %d,publickey->bits is
    //%d\n",len,rsapk.bits);

    ret = SDF_ExternalEncrypt_ECC(pSessionHandle, SGD_SM2_3, &eccpk, data, 16,
                                  eccendata);

    if (ret != SR_SUCCESSFULLY)

    {
      printf("SDF_ExternalEncrypt_ECC error!return is %08x,%08x\n", ret,
             SPII_GetErrorInfo(pSessionHandle));

      free(eccendata);

      break;
    }

    gettimeofday(starttime, 0);

    for (i = 0; i < testtime; i++)

    {
      ret = SDF_ExternalDecrypt_ECC(pSessionHandle, SGD_SM2_3, &eccvk,
                                    eccendata, pachdata, &relen);

      if (ret != SR_SUCCESSFULLY)

        printf("SDF_ExternalDecrypt_ECC error!return is %08x,%08x\n", ret,
               SPII_GetErrorInfo(pSessionHandle));

      if (memcmp(data, pachdata, relen) != 0)

      {
        printf("Compare error!\n");

        printbuff(data, 16);

        printbuff(pachdata, len);

        break;
      }

      if (i % 1000 == 0)
        printf("%d times test.....\n", i);
    }

    gettimeofday(endtime, 0);

    free(eccendata);

    break;
  }

  ret = SDF_CloseSession(pSessionHandle);

  if (ret != SR_SUCCESSFULLY)

    printf("SDF_CloseSession error! return is %08x \n", ret);

  else

    printf("Close Session succeed!\n");

  ret = SDF_CloseDevice(DeviceHandle);

  if (ret != SR_SUCCESSFULLY)

    printf("SDF_CloseDevice error! return is %08x \n", ret);

  else

    printf("CloseDevice succeed!\n");

  return;
}

void CapabilityTest()

{
  int len, select, alog, testtime;

  struct timeval now, end;

  while (1)

  {
    printf("      SM1  ---------------------- 1\n");

    printf("      SM4  ---------------------- 2\n");

#if 0
		printf("      SSF33 --------------------- 3\n");

		printf("      3DES ---------------------- 4\n");

#endif
    printf("      ECC Sign ------------------ 5\n");

    printf("      ECC Verify ---------------- 6\n");

#if 0
		printf("      RSA Sign ------------------ 7\n");

		printf("      RSA Verify----------------- 8\n");

#endif
    printf("      SM3 ----------------------- 9\n");

    printf("      ECC Encrypt --------------- 10\n");

    printf("      ECC Decrypt --------------- 11\n");

#if 0
		printf("      DES ----------------------- 12\n");
#endif
    printf("      ECC SignEx ---------------- 13\n");

    printf("      Quit ---------------------- 0\n");

    printf("Please input you select:");

    scanf("%d", &select);

    switch (select)

    {
    case 1:

      EnCapTest(SGD_SM1_ECB, &now, &end, &len, &testtime);

      CapabilityStat(&now, &end, len, testtime);

      break;

    case 2:

      EnCapTest(SGD_SM4_ECB, &now, &end, &len, &testtime);

      CapabilityStat(&now, &end, len, testtime);

      break;

#if 0
			case 3:

				EnCapTest(SGD_SSF33_ECB,&now,&end,&len,&testtime);

				CapabilityStat(&now,&end,len,testtime);

				break;

			case 4:

				EnCapTest(SGD_3DES_ECB,&now,&end,&len,&testtime);

				CapabilityStat(&now,&end,len,testtime);

				break;

			case 12:

				EnCapTest(SGD_DESPII_ECB,&now,&end,&len,&testtime);

				CapabilityStat(&now,&end,len,testtime);

				break;

#endif
    case 8:

    case 5:

    case 6:

    case 7:

    case 10:

    case 11:
    case 13:

      SignTest(select, &now, &end, &testtime);

      CapabilityStat(&now, &end, 0, testtime);

      break;

    case 9:

      EnCapTest(SGD_SM3, &now, &end, &len, &testtime);

      CapabilityStat(&now, &end, len, testtime);

      break;

    case 0:

    default:

      return;
    }
  }
}

void StatusChange()
{
  unsigned short ds, ps;
  unsigned short CardFlag;
  unsigned int status;
  HANDLE DeviceHandle;
  status = SDF_OpenDevice(&DeviceHandle);
  if (status != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenDevice error!return is %08x\n", status);
    return;
  }
  status = SPII_GetDeviceStatus(DeviceHandle, &ds, &ps);
  if (status != SR_SUCCESSFULLY)
  {
    printf("GetDeviceStatus failed and return is %08x\n", status);
    return;
  }
  switch (ds)
  {
  case 0:
    printf("Before Factory status!\n");
    break;
  case 1:
    printf("Factory status!\n");
    break;
  case 2:
    printf("Init status!\n");
    break;
  case 3:
    printf("Ready status!\n");
    break;
  default:
    printf("error status!\n");
    break;
  }
  switch (ps)
  {
  case 0:
    printf("Nobody load in!\n");
    break;
  case 1:
    printf("Administrator load in!\n");
    break;
  case 2:
    printf("Administrator2 load in!\n");
    break;
  case 3:
    printf("Assistant1 load in!\n");
    break;
  case 4:
    printf("Assistant2 load in!\n");
    break;
  default:
    printf("error Permission!\n");
    break;
  }

  SDF_CloseDevice(DeviceHandle);
  return;
}

#if 0
int SM9KepairGenerateTest(HANDLE pSessionHandle)
{
		int Gskid=0,status=0,mastkeyIndex=0,usrIndex=0,uiUserIDLen;
		 SM9UserEncPrivateKey  pucenPrivateKey;
		 SM9UserSignPrivateKey pucsiPrivateKey;
		 unsigned char pucUserID[1024]={"Alice"};
		unsigned char pincode[16]={"wuxipiico"};
		while(1)
		{
				printf("      Generate MastKey -------------------1\n");
				printf("      Generate UserKey store -------------2\n");
				printf("      Quit -------------------------------0\n");
				printf("Please input you select:");
				scanf("%d",&Gskid);
				switch(Gskid)
				{
					case 1:
						for(mastkeyIndex=1;mastkeyIndex<=KEYPAIR_MAX_INDEX;mastkeyIndex++)
						{
							status=SDF_GetPrivateKeyAccessRight(pSessionHandle,mastkeyIndex,pincode,9);
							if(status!=SR_SUCCESSFULLY)
							{
								printf("SDF_GenPrivateKeyAccessRight error!return is %08x\n",status);
								return 0;
								}
							status=SDF_GenerateSignMastKey_SM9 (pSessionHandle,mastkeyIndex);
							if(status!=SR_SUCCESSFULLY)
							{
								printf("SDF_GenerateSignMastKey_SM9 error!return is %08x\n",status);
								return 0;
							}
							status=SDF_GenerateEncMastKey_SM9 (pSessionHandle,mastkeyIndex);
							if(status!=SR_SUCCESSFULLY)
							{
								printf("SDF_GenerateEncMastKey_SM9 error!return is %08x\n",status);
								return 0;
							}
							PrintPer("Generate SM9 MastKey In Card",KEYPAIR_MAX_INDEX,mastkeyIndex);
						}
						break;
					
					case 2:
						
						uiUserIDLen=5;
						for(usrIndex=1;usrIndex<=KEYPAIR_MAX_INDEX;usrIndex++)
						{
							status=SDF_GetPrivateKeyAccessRight(pSessionHandle,usrIndex,pincode,9);
							if(status!=SR_SUCCESSFULLY)
							{
								printf("SDF_GenPrivateKeyAccessRight error!return is %08x\n",status);
								return 0;
							}
							status=SDF_GenerateInternalUseSignKey_SM9(pSessionHandle,usrIndex,usrIndex,pucUserID,uiUserIDLen,1);
							if(status!=SR_SUCCESSFULLY)
							{
								printf("SDF_GenerateInternalUseSignKey_SM9 error!return is %08x,%08x\n",status,SPII_GetErrorInfo(pSessionHandle));
								return 0;
							}
							status=SDF_GenerateInternalUseEncKey_SM9 (pSessionHandle,usrIndex,usrIndex,pucUserID,uiUserIDLen,1);
							if(status!=SR_SUCCESSFULLY)
							{
								printf("SDF_GenerateInternalUseEncKey_SM9 error!return is %08x,%08x\n",status,SPII_GetErrorInfo(pSessionHandle));
								return 0;
							}
							status=SDF_ReleasePrivateKeyAccessRight(pSessionHandle,usrIndex);
							PrintPer("SM9 KeyPair Generate",KEYPAIR_MAX_INDEX,usrIndex);
					}
						break;	
					case 0:
					default:
						return 0;
						break;
					}
			
			}
	
	}
int SM9SignTest(HANDLE pSessionHandle)
{
	int mastsipkindex,Keyindex,uiPIDLength,status,endatalen,datalen;
	SM9SignMastPublicKey simpk;
	SM9Signature      pucSignature;
	unsigned char uiPID[1024],endata[128],data2[128];
	unsigned char pincode[16]={"wuxipiico"};
	char data[]="Chinese IBS standard";
	printf("Please input the test MastEnPublickey:");
	scanf("%d",&mastsipkindex);
	printf("Please input the test Keyindex:");
	scanf("%d",&Keyindex);
	printf("data is:%s\n",data);
	status=SDF_GetPrivateKeyAccessRight(pSessionHandle,Keyindex,pincode,9);
	if(status!=SR_SUCCESSFULLY)
	{
		printf("SDF_GenPrivateKeyAccessRight error!return is %08x %08x\n",status,SPII_GetErrorInfo);
		return -1;
		}
	status=SDF_ExportSignMastPublicKey_SM9 (pSessionHandle, mastsipkindex,&simpk);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_ExportSignMastPublicKey_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			return -1;
			}
	printf("SM9SignMastPublicKey->compressType:%d\n",simpk.compressType);
	printf("SM9SignMastPublicKey->bits:%d\n",simpk.bits);
	printbuff1("SM9SignMastPublicKey->xa",simpk.xa,SM9ref_MAX_LEN);
	printbuff1("SM9SignMastPublicKey->xb",simpk.xb,SM9ref_MAX_LEN);
	printbuff1("SM9SignMastPublicKey->ya",simpk.ya,SM9ref_MAX_LEN);
	printbuff1("SM9SignMastPublicKey->yb",simpk.yb,SM9ref_MAX_LEN);
	status=SDF_ExportSignID_SM9(pSessionHandle,Keyindex, uiPID,&uiPIDLength);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_ExportSignID_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			return -1;
			}	
	printbuff1("PID",uiPID,uiPIDLength);
/*	status=SDF_GenerateRandom(pSessionHandle,32,data);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_GenerateRandom error ,and return is %08x\n",status);
			return -1;
			}
//	memcpy(data,message,20);
//	printbuff1("data",data,20);*/
	status=SDF_ExportSignID_SM9(pSessionHandle,Keyindex, uiPID,&uiPIDLength);
	status=SDF_InternalIDSign_SM9(pSessionHandle,&simpk,Keyindex,(unsigned char *)data,strlen(data),&pucSignature);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_InternalIDSign_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			return -1;
			}
	else
		printf("SDF_InternalIDSign_SM9 succeed!\n");
	printbuff1("SM9Signature->h",pucSignature.h,SM9ref_MAX_LEN);
	printbuff1("SM9Signature->x",pucSignature.x,SM9ref_MAX_LEN);
	printbuff1("SM9Signature->y",pucSignature.y,SM9ref_MAX_LEN);
	 status=SDF_ExternalMastKeyVerify_SM9(pSessionHandle,&simpk,uiPID,uiPIDLength,(unsigned char *)data,strlen(data),&pucSignature);		
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_ExternalMastKeyVerify_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			return -1;
			}	
	else
		printf("SDF_InternalIDSign_SM9&SDF_ExternalMastKeyVerify_SM9 succeed!\n");	
		//////////////////////////////////////////////////////////////////////////////////////////////
	status=SDF_InternalKeySign_SM9(pSessionHandle,mastsipkindex,Keyindex,(unsigned char *)data,strlen(data),&pucSignature);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_InternalKeySign_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			return -1;
			}
	else
		printf("SDF_InternalkeySign_SM9 succeed!\n");
	printbuff1("SM9Signature->h",pucSignature.h,SM9ref_MAX_LEN);
	printbuff1("SM9Signature->x",pucSignature.x,SM9ref_MAX_LEN);
	printbuff1("SM9Signature->y",pucSignature.y,SM9ref_MAX_LEN);
	status=SDF_InternalMastKeyVerify_SM9(pSessionHandle,mastsipkindex,uiPID,uiPIDLength,(unsigned char *)data,strlen(data),&pucSignature);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_InternalMastKeyVerify_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			return -1;
			}
	else
		printf("SDF_InternalKeySign_SM9&SDF_InternalMastKeyVerify_SM9 succeed!\n");	
	////////////////////////////////////////////////////////////////////////////////////////////////
	status=SDF_InternalIDSign_SM9(pSessionHandle,&simpk,Keyindex,(unsigned char *)data,strlen(data),&pucSignature);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_InternalIDSign_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			return -1;
			}
	else
		printf("SDF_InternalIDSign_SM9 succeed!\n");
	printbuff1("SM9Signature->h",pucSignature.h,SM9ref_MAX_LEN);
	printbuff1("SM9Signature->x",pucSignature.x,SM9ref_MAX_LEN);
	printbuff1("SM9Signature->y",pucSignature.y,SM9ref_MAX_LEN);
	 status=SDF_InternalIDVerify_SM9(pSessionHandle,&simpk,Keyindex,(unsigned char *)data,strlen(data),&pucSignature);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_InternalIDVerify_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			return -1;
			}	
	else
		printf("SDF_InternalIDSign_SM9&SDF_InternalIDVerify_SM9 succeed!\n");	
		//////////////////////////////////////////////////////////////////////////////////////////////
	status=SDF_InternalKeySign_SM9(pSessionHandle,mastsipkindex,Keyindex,(unsigned char *)data,strlen(data),&pucSignature);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_InternalKeySign_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			return -1;
			}
	else
		printf("SDF_InternalKeySign_SM9 succeed!\n");
	printbuff1("SM9Signature->h",pucSignature.h,SM9ref_MAX_LEN);
	printbuff1("SM9Signature->x",pucSignature.x,SM9ref_MAX_LEN);
	printbuff1("SM9Signature->y",pucSignature.y,SM9ref_MAX_LEN);
	//pucSignature.y[0]=0x0f;
	status=SDF_InternalKeyVerify_SM9(pSessionHandle,mastsipkindex,Keyindex,(unsigned char *)data,strlen(data),&pucSignature);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_InternalKeyVerify_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			return -1;
			}
	else
		printf("SDF_InternalKeyVerify_SM9&SDF_InternalMastKeyVerify_SM9 succeed!\n");	
		return 0;
	}
int SM9MessageEDTest(HANDLE pSessionHandle)
{
	int mastenpkindex,Keyindex,uiPIDLength,status,endatalen,datalen,i,alogi,alog;
	SM9EncMastPublicKey enmpk;
	SM9Cipher      *pucKey;
	unsigned char pincode[16]={"wuxipiico"};
	unsigned char uiPID[1024],data[128],endata[128],data2[128],IV[16];
	printf("Please input the test MastEnPublickey:");
	scanf("%d",&mastenpkindex);
	printf("Please input the test Keyindex:");
	scanf("%d",&Keyindex);
	printf("Please input the test alog:\n1)SGD_SM9_8_ECB\n2)SGD_SM9_8_CBC\n3)SGD_SM9_8\n: ");
	scanf("%d",&alogi);
	switch(alogi)
	{
		case 1:
		default:
			alog=SGD_SM9_8_ECB;
			break;
		case 2:
			alog=SGD_SM9_8_CBC;
			for(i=0;i<16;i++) IV[i]=i*3;
			break;
		case 3:
			alog=SGD_SM9_8;
			break;
	
	}
	status=SDF_GetPrivateKeyAccessRight(pSessionHandle,Keyindex,pincode,9);
	if(status!=SR_SUCCESSFULLY)
	{
		printf("SDF_GenPrivateKeyAccessRight error!return is %08x %08x\n",status,SPII_GetErrorInfo(pSessionHandle));
		return -1;
		}
	status=SDF_ExportEncMastPublicKey_SM9 (pSessionHandle, mastenpkindex,&enmpk);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_ExportEncMastPublicKey_SM9 error ,and return is %08x\n",status);
			return -1;
			}
	printf("SM9EncMastPublicKey->bits:%d\n",enmpk.bits);
	printbuff1("SM9EncMastPublicKey->x",enmpk.x,SM9ref_MAX_LEN);
	printbuff1("SM9EncMastPublicKey->y",enmpk.y,SM9ref_MAX_LEN);
	status=SDF_ExportEncID_SM9(pSessionHandle,Keyindex, uiPID,&uiPIDLength);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_ExportEncID_SM9 error ,and return is %08x\n",status);
			return -1;
			}	
	printbuff1("PID",uiPID,uiPIDLength);
	printf("Please input the test length(1~128):");
	scanf("%d",&datalen);
	status=SDF_GenerateRandom(pSessionHandle,datalen,data);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_GenerateRandom error ,and return is %08x\n",status);
			return -1;
			}
	printbuff1("data",data,datalen);
	pucKey=malloc(sizeof(SM9Cipher)+32+datalen);		
	status=SDF_ExternalMastKeyEncrypt_SM9(pSessionHandle,alog,&enmpk,uiPID,uiPIDLength,IV,data,datalen,pucKey);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_ExternalMastKeyEncrypt_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo(pSessionHandle));
			free(pucKey);
			return -1;
			}
	printf("SM9Cipher->enType:%08x\n",pucKey->enType);
	printbuff1("SM9Cipher->x",pucKey->x,SM9ref_MAX_LEN);
	printbuff1("SM9Cipher->y",pucKey->y,SM9ref_MAX_LEN);
	printbuff1("SM9Cipher->h",pucKey->h,SM9ref_MAX_LEN);
	printf("SM9Cipher->L:%d\n",pucKey->L);
	printbuff1("SM9Cipher->C",pucKey->C,pucKey->L);
	status=SDF_DecryptWithID_SM9(pSessionHandle,alog,Keyindex,uiPID,uiPIDLength,pucKey,endata,&endatalen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_DecryptWithID_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo(pSessionHandle));
			free(pucKey);
			return -1;
			}
	if(datalen!=endatalen||memcmp(endata,data,endatalen)!=0)
		{
			printf("SDF_ExternalMastKeyEncrypt_SM9&SDF_DecryptWithID_SM9 compare error\n");
			free(pucKey);
			return -1;
			}
			else
				printf("SDF_ExternalMastKeyEncrypt_SM9&SDF_DecryptWithID_SM9 succeed!\n");
	//////////////////////////////////////////////////////////////////////////////////////////////
	status=SDF_InternalMastKeyEncrypt_SM9(pSessionHandle,alog,mastenpkindex,uiPID,uiPIDLength,IV,data,datalen,pucKey);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_InternalMastKeyEncrypt_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo(pSessionHandle));
			free(pucKey);
			return -1;
			}
	printf("SM9Cipher->enType:%08x\n",pucKey->enType);
	printbuff1("SM9Cipher->x",pucKey->x,SM9ref_MAX_LEN);
	printbuff1("SM9Cipher->y",pucKey->y,SM9ref_MAX_LEN);
	printbuff1("SM9Cipher->h",pucKey->h,SM9ref_MAX_LEN);
	printf("SM9Cipher->L:%d\n",pucKey->L);
	printbuff1("SM9Cipher->C",pucKey->C,pucKey->L);
	status=SDF_DecryptWithID_SM9(pSessionHandle,alog,Keyindex,uiPID,uiPIDLength,pucKey,endata,&endatalen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_DecryptWithID_SM9 error ,and return is %08x\n",status);
			free(pucKey);
			return -1;
			}
	if(datalen!=endatalen||memcmp(endata,data,endatalen)!=0)
		{
			printf("SDF_InternalMastKeyEncrypt_SM9&SDF_DecryptWithID_SM9 compare error\n");
			free(pucKey);
			return -1;
			}
			else
				printf("SDF_InternalMastKeyEncrypt_SM9&SDF_DecryptWithID_SM9 succeed!\n");
	//////////////////////////////////////////////////////////////////////////////////////////////
	status=SDF_InternalIDEncrypt_SM9(pSessionHandle,alog,&enmpk,Keyindex,IV,data,datalen,pucKey);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_InternalIDEncrypt_SM9 error ,and return is %08x\n",status);
			free(pucKey);
			return -1;
			}
	printf("SM9Cipher->enType:%08x\n",pucKey->enType);
	printbuff1("SM9Cipher->x",pucKey->x,SM9ref_MAX_LEN);
	printbuff1("SM9Cipher->y",pucKey->y,SM9ref_MAX_LEN);
	printbuff1("SM9Cipher->h",pucKey->h,SM9ref_MAX_LEN);
	printf("SM9Cipher->L:%d\n",pucKey->L);
	printbuff1("SM9Cipher->C",pucKey->C,pucKey->L);
	status=SDF_DecryptWithIndex_SM9(pSessionHandle,alog,Keyindex,pucKey,endata,&endatalen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_DecryptWithIndex_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo(pSessionHandle));
			free(pucKey);
			return -1;
			}
	if(datalen!=endatalen||memcmp(endata,data,endatalen)!=0)
		{
			printf("SDF_InternalIDEncrypt_SM9&SDF_DecryptWithIndex_SM9 compare error\n");
			free(pucKey);
			return -1;
			}
			else
				printf("SDF_InternalIDEncrypt_SM9&SDF_DecryptWithID_SM9 succeed!\n");
		////////////////////////////////////////////////////////////////////////////////////////////
		status=SDF_InternalKeyEncrypt_SM9(pSessionHandle,alog,mastenpkindex,Keyindex,IV,data,datalen,pucKey);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_InternalKeyEncrypt_SM9 error ,and return is %08x\n",status);
			free(pucKey);
			return -1;
			}
	printf("SM9Cipher->enType:%08x\n",pucKey->enType);
	printbuff1("SM9Cipher->x",pucKey->x,SM9ref_MAX_LEN);
	printbuff1("SM9Cipher->y",pucKey->y,SM9ref_MAX_LEN);
	printbuff1("SM9Cipher->h",pucKey->h,SM9ref_MAX_LEN);
	printf("SM9Cipher->L:%d\n",pucKey->L);
	printbuff1("SM9Cipher->C",pucKey->C,pucKey->L);
	status=SDF_DecryptWithIndex_SM9(pSessionHandle,alog,Keyindex,pucKey,endata,&endatalen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_DecryptWithIndex_SM9 error ,and return is %08x\n",status);
			free(pucKey);
			return -1;
			}
	if(datalen!=endatalen||memcmp(endata,data,endatalen)!=0)
		{
			printf("SDF_InternalKeyEncrypt_SM9&SDF_DecryptWithIndex_SM9 compare error\n");
			printbuff1("data is :",data,datalen);
			printbuff1("endata is :",endata,endatalen);
			free(pucKey);
			return -1;
			}
			else
				printf("SDF_InternalKeyEncrypt_SM9&SDF_DecryptWithID_SM9 succeed!\n");
		free(pucKey);
		return 0;
	}
int SM9SKtest(HANDLE pSessionHandle)
{
	int mastenpkindex,Keyindex,uiPIDLength,status,endatalen,datalen,alogi,alog,i;	
	SM9EncMastPublicKey enmpk;
	HANDLE pKeyHandle1,pKeyHandle2;
	SM9Cipher      *pucKey;
	unsigned char uiPID[1024],data[128],endata[128],data2[128],iv[16];
	unsigned char pincode[16]={"wuxipiico"};
	printf("Please input the test MastEnPublickey:");
	scanf("%d",&mastenpkindex);
	printf("Please input the test Keyindex:");
	scanf("%d",&Keyindex);
	printf("Please input the test alog:\n1)SGD_SM9_8_ECB\n2)SGD_SM9_8_CBC\n3)SGD_SM9_8\n: ");
	scanf("%d",&alogi);
	switch(alogi)
	{
		case 1:
		default:
			alog=SGD_SM9_8_ECB;
			break;
		case 2:
			alog=SGD_SM9_8_CBC;
			for(i=0;i<16;i++)
				iv[i]=i;
			break;
		case 3:
			alog=SGD_SM9_8;
			break;
	
	}
	status=SDF_GetPrivateKeyAccessRight(pSessionHandle,Keyindex,pincode,9);
	if(status!=SR_SUCCESSFULLY)
	{
		printf("SDF_GenPrivateKeyAccessRight error!return is %08x %08x\n",status,SPII_GetErrorInfo);
		return -1;
		}
	status=SDF_ExportEncMastPublicKey_SM9 (pSessionHandle, mastenpkindex,&enmpk);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_ExportEncMastPublicKey_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			return -1;
			}
	status=SDF_ExportEncID_SM9(pSessionHandle,Keyindex, uiPID,&uiPIDLength);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_ExportEncID_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			return -1;
			}	
	pucKey=malloc(sizeof(SM9Cipher)+32+128);		
	status=SDF_ExternalMastKeyGenerateKey_SM9(pSessionHandle,alog,128,iv,&enmpk,uiPID,uiPIDLength,pucKey,&pKeyHandle1);
		if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_ExternalMastKeyGenerateKey_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			return -1;
			}
	status=SDF_ImportKeyWithID_SM9(pSessionHandle,alog,Keyindex,uiPID,uiPIDLength,pucKey,&pKeyHandle2);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_ImportKeyWithID_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo(pSessionHandle));
			free(pucKey);
			return -1;
			}
	status=SDF_GenerateRandom(pSessionHandle,128,data);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_GenerateRandom error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			return -1;
			}
	status=SDF_Encrypt(pSessionHandle,pKeyHandle1,SGD_SM4_ECB,NULL,data,128,endata,&endatalen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_Encrypt error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			return -1;
			}
	status=SDF_Decrypt(pSessionHandle,pKeyHandle2,SGD_SM4_ECB,NULL,endata,endatalen,data2,&datalen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_Decrypt error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			return -1;
			}
	if(datalen!=128||memcmp(data2,data,128)!=0)
		{
			printf("SDF_Encrypt&SDF_Decrypt compare error\n");
			free(pucKey);
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			return -1;
			}
			else
				printf("SDF_ExternalMastKeyGenerateKey_SM9&SDF_ImportKeyWithID_SM9 succeed!\n");
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
	/////////////////////////////////////////////////////////////////////////////////////////
	status=SDF_InternalMastKeyGenerateKey_SM9(pSessionHandle,alog,128,iv,mastenpkindex,uiPID,uiPIDLength,pucKey,&pKeyHandle1);
		if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_InternalMastKeyGenerateKey_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			return -1;
			}
	status=SDF_ImportKeyWithID_SM9(pSessionHandle,alog,Keyindex,uiPID,uiPIDLength,pucKey,&pKeyHandle2);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_ImportKeyWithID_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			return -1;
			}
	status=SDF_Encrypt(pSessionHandle,pKeyHandle1,SGD_SM4_ECB,NULL,data,128,endata,&endatalen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_Encrypt error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			return -1;
			}
	status=SDF_Decrypt(pSessionHandle,pKeyHandle2,SGD_SM4_ECB,NULL,endata,endatalen,data2,&datalen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_Decrypt error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			return -1;
			}
	if(datalen!=128||memcmp(data2,data,128)!=0)
		{
			printf("SDF_Encrypt&SDF_Decrypt compare error\n");
			free(pucKey);
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			return -1;
			}
		else
				printf("SDF_InternalMastKeyGenerateKey_SM9&SDF_ImportKeyWithID_SM9 succeed!\n");
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
		//////////////////////////////////////////////////////////////////////////////////////
		status=SDF_InternalIDGenerateKey_SM9(pSessionHandle,alog,128,iv,&enmpk,Keyindex,pucKey,&pKeyHandle1);
		if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_InternalIDGenerateKey_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			return -1;
			}
	status=SDF_ImportKeyWithIndex_SM9(pSessionHandle,alog,Keyindex,pucKey,&pKeyHandle2);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_ImportKeyWithIndex_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			return -1;
			}
	status=SDF_Encrypt(pSessionHandle,pKeyHandle1,SGD_SM4_ECB,NULL,data,128,endata,&endatalen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_Encrypt error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			return -1;
			}
	status=SDF_Decrypt(pSessionHandle,pKeyHandle2,SGD_SM4_ECB,NULL,endata,endatalen,data2,&datalen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_Decrypt error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			return -1;
			}
	if(datalen!=128||memcmp(data2,data,128)!=0)
		{
			printf("SDF_Encrypt&SDF_Decrypt compare error\n");
			free(pucKey);
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			return -1;
			}
		else
				printf("SDF_InternalIDGenerateKey_SM9&SDF_ImportKeyWithIndex_SM9 succeed!\n");
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
	/////////////////////////////////////////////////////////////////////////////////////////////////
	status=SDF_InternalKeyGenerateKey_SM9(pSessionHandle,alog,128,iv,mastenpkindex,Keyindex,pucKey,&pKeyHandle1);
		if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_InternalKeyGenerateKey_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			return -1;
			}
	status=SDF_ImportKeyWithIndex_SM9(pSessionHandle,alog,Keyindex,pucKey,&pKeyHandle2);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_ImportKeyWithIndex_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			return -1;
			}
	status=SDF_Encrypt(pSessionHandle,pKeyHandle1,SGD_SM4_ECB,NULL,data,128,endata,&endatalen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_Encrypt error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			return -1;
			}
	status=SDF_Decrypt(pSessionHandle,pKeyHandle2,SGD_SM4_ECB,NULL,endata,endatalen,data2,&datalen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_Decrypt error ,and return is %08x %08x\n",status,SPII_GetErrorInfo);
			free(pucKey);
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			return -1;
			}
	if(datalen!=128||memcmp(data2,data,128)!=0)
		{
			printf("SDF_Encrypt&SDF_Decrypt compare error\n");
			free(pucKey);
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			return -1;
			}
		else
				printf("SDF_InternalKeyGenerateKey_SM9&SDF_ImportKeyWithIndex_SM9 succeed!\n");
			SDF_DestroyKey(pSessionHandle,pKeyHandle2);
			SDF_DestroyKey(pSessionHandle,pKeyHandle1);
			free(pucKey);
			return SR_SUCCESSFULLY;
	}

int SM9CapabilityTest(HANDLE pSessionHandle)
{
	int Gskid,testtimes;
	int mastpkindex,Keyindex,uiPIDLength,status,endatalen,datalen,i,uiUserIDLen;
		 SM9UserEncPrivateKey  pucenPrivateKey;
		 SM9UserSignPrivateKey pucsiPrivateKey;
	SM9EncMastPublicKey enmpk;
	SM9Cipher      *pucKey;
	SM9SignMastPublicKey simpk;
	SM9Signature      pucSignature;
	struct timeval starttime,endtime;
	unsigned char pincode[16]={"wuxipiico"};
	unsigned char uiPID[1024],data[128],endata[128],data2[128],IV[16];
	unsigned char pucUserID[1024];
	printf("Please input the test MastPublickeyID:");
	scanf("%d",&mastpkindex);
	printf("Please input the test Keyindex:");
	scanf("%d",&Keyindex);
	status=SDF_GetPrivateKeyAccessRight(pSessionHandle,Keyindex,pincode,9);
	if(status!=SR_SUCCESSFULLY)
	{
		printf("SDF_GenPrivateKeyAccessRight error!return is %08x %08x\n",status,SPII_GetErrorInfo(pSessionHandle));
		return -1;
		}
	datalen=32;
	status=SDF_GenerateRandom(pSessionHandle,datalen,data);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_GenerateRandom error ,and return is %08x\n",status);
			return -1;
			}

	while(1)
	{
		printf("              Encrypt with MastKeyID -------------1\n");
		printf("              Encrypt with MastKeyStruct ---------2\n");
		printf("              Sign with MastKeyID ----------------3\n");
		printf("              Sign with MastKeyStruct ------------4\n");
		printf("              Generate Key -----------------------5\n");
		printf("              Quit -------------------------------0\n");
		printf("Please input your select:");
		scanf("%d",&Gskid);
		switch(Gskid)
		{
			case 1:
				status=SDF_ExportEncID_SM9(pSessionHandle,Keyindex, uiPID,&uiPIDLength);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_ExportEncID_SM9 error ,and return is %08x\n",status);
					return -1;
				}	
				pucKey=malloc(sizeof(SM9Cipher)+32+datalen);		
				printf("Please input the test time:");
				scanf("%d",&testtimes);
	                	gettimeofday(&starttime,NULL);
				printf("Start .....\n");
				for(i=0;i<testtimes;i++)
				{
					PrintPer("Encrypt with MastKeyID",testtimes,i);
					status=SDF_InternalMastKeyEncrypt_SM9(pSessionHandle,SGD_SM9_8_ECB,mastpkindex,uiPID,uiPIDLength,NULL,data,datalen,pucKey);
				//	status=SDF_InternalKeyEncrypt_SM9(pSessionHandle,SGD_SM9_8_ECB,mastpkindex,Keyindex,NULL,data,datalen,pucKey);
					if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_InternalKeyEncrypt_SM9 error ,and return is %08x\n",status);
						free(pucKey);
						return -1;
					}
				}
	               		gettimeofday(&endtime,NULL);
 				CapabilityStat(&starttime,&endtime,0,testtimes);
	                	gettimeofday(&starttime,NULL);
				for(i=0;i<testtimes;i++)
				{
				//	status=SDF_DecryptWithIndex_SM9(pSessionHandle,SGD_SM9_8_ECB,Keyindex,pucKey,endata,&endatalen);
					status=SDF_DecryptWithID_SM9(pSessionHandle,SGD_SM9_8_ECB,Keyindex,uiPID,uiPIDLength,pucKey,endata,&endatalen);
					if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_DecryptWithIndex_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo(pSessionHandle));
						free(pucKey);
						return -1;
					}
					if(datalen!=endatalen||memcmp(endata,data,endatalen)!=0)
					{		
						printf("SDF_InternalIDEncrypt_SM9&SDF_DecryptWithIndex_SM9 compare error\n");
						free(pucKey);
						return -1;
					}
					PrintPer("Decrypt ",testtimes,i);
				}
	                	gettimeofday(&endtime,NULL);
 				CapabilityStat(&starttime,&endtime,0,testtimes);
				free(pucKey);
				break;

			case 2:
				status=SDF_ExportEncID_SM9(pSessionHandle,Keyindex, uiPID,&uiPIDLength);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_ExportEncID_SM9 error ,and return is %08x\n",status);
					return -1;
				}	
				printf("Please input the test time:");
				scanf("%d",&testtimes);
				pucKey=malloc(sizeof(SM9Cipher)+32+datalen);		
				status=SDF_ExportEncMastPublicKey_SM9 (pSessionHandle, mastpkindex,&enmpk);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_ExportEncMastPublicKey_SM9 error ,and return is %08x\n",status);
					return -1;
				}
				else
					printf("SDF_ExportEncMastPublicKey_SM9 succeed!\n");
	                	gettimeofday(&starttime,NULL);
				for(i=0;i<testtimes;i++)
				{
				//	status=SDF_InternalIDEncrypt_SM9(pSessionHandle,SGD_SM9_8_ECB,&enmpk,Keyindex,NULL,data,datalen,pucKey);
					status=SDF_ExternalMastKeyEncrypt_SM9(pSessionHandle,SGD_SM9_8_ECB,&enmpk,uiPID,uiPIDLength,NULL,data,datalen,pucKey);
					if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_InternalIDEncrypt_SM9 error ,and return is %08x\n",status);
						free(pucKey);
						return -1;
					}
					PrintPer("Encrypt with MastKeystruct",testtimes,i);
				}
	                	gettimeofday(&endtime,NULL);
 				CapabilityStat(&starttime,&endtime,0,testtimes);
	                	gettimeofday(&starttime,NULL);
				for(i=0;i<testtimes;i++)
				{
				//	status=SDF_DecryptWithIndex_SM9(pSessionHandle,SGD_SM9_8_ECB,Keyindex,pucKey,endata,&endatalen);
					status=SDF_DecryptWithID_SM9(pSessionHandle,SGD_SM9_8_ECB,Keyindex,uiPID,uiPIDLength,pucKey,endata,&endatalen);
					if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_DecryptWithIndex_SM9 error ,and return is %08x %08x\n",status,SPII_GetErrorInfo(pSessionHandle));
						free(pucKey);
						return -1;
					}
					if(datalen!=endatalen||memcmp(endata,data,endatalen)!=0)
					{		
						printf("SDF_InternalIDEncrypt_SM9&SDF_DecryptWithIndex_SM9 compare error\n");
						free(pucKey);
						return -1;
					}
					PrintPer("Decrypt ",testtimes,i);
					}		
	                	gettimeofday(&endtime,NULL);
 				CapabilityStat(&starttime,&endtime,0,testtimes);
				free(pucKey);
				break;
			case 3:	
				status=SDF_ExportSignID_SM9(pSessionHandle,Keyindex, uiPID,&uiPIDLength);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_ExportSignID_SM9 error ,and return is %08x\n",status);
					return -1;
					}	
				printf("Please input the test time:");
				scanf("%d",&testtimes);
	                	gettimeofday(&starttime,NULL);
				for(i=0;i<testtimes;i++)
				{
					status=SDF_InternalKeySign_SM9(pSessionHandle,mastpkindex,Keyindex,data,32,&pucSignature);
					if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_InternalIDSign_SM9 error ,and return is %08x\n",status);
						return -1;
					}
					PrintPer("Sign MastPKID",testtimes,i);

				}
	                	gettimeofday(&endtime,NULL);
 				CapabilityStat(&starttime,&endtime,0,testtimes);
	                	gettimeofday(&starttime,NULL);
				for(i=0;i<testtimes;i++)
				{
				//	status=SDF_InternalKeyVerify_SM9(pSessionHandle,mastpkindex,Keyindex,data,32,&pucSignature);
					status=SDF_InternalMastKeyVerify_SM9(pSessionHandle,mastpkindex,uiPID,uiPIDLength,data,32,&pucSignature);
					if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_InternalIDVerify_SM9 error ,and return is %08x\n",status);
						return -1;
					}
	
					PrintPer("Verify MastPKID",testtimes,i);
					}		
	                	gettimeofday(&endtime,NULL);
 				CapabilityStat(&starttime,&endtime,0,testtimes);
				break;

			case 4:
				status=SDF_ExportSignID_SM9(pSessionHandle,Keyindex, uiPID,&uiPIDLength);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_ExportSignID_SM9 error ,and return is %08x\n",status);
					return -1;
					}	
				status=SDF_ExportSignMastPublicKey_SM9 (pSessionHandle, mastpkindex,&simpk);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_ExportSignMastPublicKey_SM9 error ,and return is %08x\n",status);
					return -1;
					}
				printf("Please input the test time:");
				scanf("%d",&testtimes);
	                	gettimeofday(&starttime,NULL);
				for(i=0;i<testtimes;i++)
				{
					status=SDF_InternalIDSign_SM9(pSessionHandle,&simpk,Keyindex,data,32,&pucSignature);
					if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_InternalIDSign_SM9 error ,and return is %08x\n",status);
						return -1;
					}
					PrintPer("Sign MastStruct",testtimes,i);

				}
	                	gettimeofday(&endtime,NULL);
 				CapabilityStat(&starttime,&endtime,0,testtimes);
	                	gettimeofday(&starttime,NULL);
				for(i=0;i<testtimes;i++)
				{
	 			//	status=SDF_InternalIDVerify_SM9(pSessionHandle,&simpk,Keyindex,data,32,&pucSignature);
	 				status=SDF_ExternalMastKeyVerify_SM9(pSessionHandle,&simpk,uiPID,uiPIDLength,data,32,&pucSignature);		
					if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_InternalIDVerify_SM9 error ,and return is %08x\n",status);
						return -1;
					}
	
					PrintPer("Verify MastStruct",testtimes,i);
					}		
	                	gettimeofday(&endtime,NULL);
 				CapabilityStat(&starttime,&endtime,0,testtimes);
				break;
			case 5:		
				printf("Please input the pucUserID:");
						scanf("%s",&pucUserID);
						uiUserIDLen=strlen(pucUserID);		
					printf("Please input the test time:");
				scanf("%d",&testtimes);
	                	gettimeofday(&starttime,NULL);
	       printf("Generate UseSignKey Test:");         	
				for(i=0;i<testtimes;i++)
				{
						status=SDF_GenerateUseSignKey_SM9 (pSessionHandle,Keyindex,pucUserID,uiUserIDLen,&pucsiPrivateKey);
						if(status!=SR_SUCCESSFULLY)
						{
							printf("SDF_GenerateUseSignKey_SM9 error!return is %08x\n",status);
							return -1;
						}
						PrintPer("Gen UseSignKey",testtimes,i);
				}
	                	gettimeofday(&endtime,NULL);
 				CapabilityStat(&starttime,&endtime,0,testtimes);
				printf("Generate UseEncKey Test:");         	
				for(i=0;i<testtimes;i++)
				{
						status=SDF_GenerateUseEncKey_SM9 (pSessionHandle,Keyindex,pucUserID,uiUserIDLen,&pucenPrivateKey);
						if(status!=SR_SUCCESSFULLY)
						{
							printf("SDF_GenerateUseEncKey_SM9 error!return is %08x\n",status);
							return -1;
						}
					PrintPer("Gen UseEncKey",testtimes,i);

				}
	                	gettimeofday(&endtime,NULL);
 				CapabilityStat(&starttime,&endtime,0,testtimes);

			default:
				return 0;

		}

	}

}
int SM9ImportKeyTest(HANDLE pSessionHandle)
{

	int Gskid=0,status=0,uiUserIDLen=0,puiDataLength,Gsel=0,uitype=0,alog=0;
	unsigned int uiKeyIndex=1;
	unsigned int mastkeyIndex=1;
	SM9SignMastPrivateKey smvk;
	SM9EncMastPrivateKey emvk;
	 SM9UserEncPrivateKey  euvk;
	 SM9UserSignPrivateKey suvk;
	 SM9EncMastPublicKey empk;
	 SM9SignMastPublicKey smpk;
	 unsigned char IV[16]={0};
	 unsigned char stdsmvk[32]={0x00,0x01,0x30,0xE7,0x84,0x59,0xD7,0x85,0x45,0xCB,0x54,0xC5,0x87,0xE0,0x2C,0xF4,
	 	0x80,0xCE,0x0B,0x66,0x34,0x0F,0x31,0x9F,0x34,0x8A,0x1D,0x5B,0x1F,0x2D,0xC5,0xF4};
	 	unsigned char stdsuvk[64]={0xA5,0x70,0x2F,0x05,0xCF,0x13,0x15,0x30,0x5E,0x2D,0x6E,0xB6,0x4B,0x0D,0xEB,0x92,0x3D,0xB1,0xA0,0xBC,0xF0,0xCA,0xFF,0x90,0x52,0x3A,0xC8,0x75,0x4A,0xA6,0x98,0x20,
	 		0x78,0x55,0x9A,0x84,0x44,0x11,0xF9,0x82,0x5C,0x10,0x9F,0x5E,0xE3,0xF5,0x2D,0x72,0x0D,0xD0,0x17,0x85,0x39,0x2A,0x72,0x7B,0xB1,0x55,0x69,0x52,0xB2,0xB0,0x13,0xD3};
	 
	 unsigned char stdsign[96]={0x82,0x3C,0x4B,0x21,0xE4,0xBD,0x2D,0xFE,0x1E,0xD9,0x2C,0x60,0x66,0x53,0xE9,0x96,0x66,0x85,0x63,0x15,0x2F,0xC3,0x3F,0x55,0xD7,0xBF,0xBB,0x9B,0xD9,0x70,0x5A,0xDB,
0x73,0xBF,0x96,0x92,0x3C,0xE5,0x8B,0x6A,0xD0,0xE1,0x3E,0x96,0x43,0xA4,0x06,0xD8,0xEB,0x98,0x41,0x7C,0x50,0xEF,0x1B,0x29,0xCE,0xF9,0xAD,0xB4,0x8B,0x6D,0x59,0x8C,
0x85,0x67,0x12,0xF1,0xC2,0xE0,0x96,0x8A,0xB7,0x76,0x9F,0x42,0xA9,0x95,0x86,0xAE,0xD1,0x39,0xD5,0xB8,0xB3,0xE1,0x58,0x91,0x82,0x7C,0xC2,0xAC,0xED,0x9B,0xAA,0x05};
	unsigned char stdemvk[32]={0x00,0x01,0xED,0xEE,0x37,0x78,0xF4,0x41,0xF8,0xDE,0xA3,0xD9,0xFA,0x0A,0xCC,0x4E,0x07,0xEE,0x36,0xC9,0x3F,0x9A,0x08,0x61,0x8A,0xF4,0xAD,0x85,0xCE,0xDE,0x1C,0x22};
	unsigned char stdeuvk[128]={0x94,0x73,0x6A,0xCD,0x2C,0x8C,0x87,0x96,0xCC,0x47,0x85,0xE9,0x38,0x30,0x1A,0x13,0x9A,0x05,0x9D,0x35,0x37,0xB6,0x41,0x41,0x40,0xB2,0xD3,0x1E,0xEC,0xF4,0x16,0x83,
															0x11,0x5B,0xAE,0x85,0xF5,0xD8,0xBC,0x6C,0x3D,0xBD,0x9E,0x53,0x42,0x97,0x9A,0xCC,0xCF,0x3C,0x2F,0x4F,0x28,0x42,0x0B,0x1C,0xB4,0xF8,0xC0,0xB5,0x9A,0x19,0xB1,0x58,
															0x7A,0xA5,0xE4,0x75,0x70,0xDA,0x76,0x00,0xCD,0x76,0x0A,0x0C,0xF7,0xBE,0xAF,0x71,0xC4,0x47,0xF3,0x84,0x47,0x53,0xFE,0x74,0xFA,0x7B,0xA9,0x2C,0xA7,0xD3,0xB5,0x5F,
															0x27,0x53,0x8A,0x62,0xE7,0xF7,0xBF,0xB5,0x1D,0xCE,0x08,0x70,0x47,0x96,0xD9,0x4C,0x9D,0x56,0x73,0x4F,0x11,0x9E,0xA4,0x47,0x32,0xB5,0x0E,0x31,0xCD,0xEB,0x75,0xC1};
															
	unsigned char stdendata[128]={0x24,0x45,0x47,0x11,0x64,0x49,0x06,0x18,0xE1,0xEE,0x20,0x52,0x8F,0xF1,0xD5,0x45,0xB0,0xF1,0x4C,0x8B,0xCA,0xA4,0x45,0x44,0xF0,0x3D,0xAB,0x5D,0xAC,0x07,0xD8,0xFF,
																0x42,0xFF,0xCA,0x97,0xD5,0x7C,0xDD,0xC0,0x5E,0xA4,0x05,0xF2,0xE5,0x86,0xFE,0xB3,0xA6,0x93,0x07,0x15,0x53,0x2B,0x80,0x00,0x75,0x9F,0x13,0x05,0x9E,0xD5,0x9A,0xC0,
																0xE0,0x5B,0x6F,0xAC,0x6F,0x11,0xB9,0x65,0x26,0x8C,0x99,0x4F,0x00,0xDB,0xA7,0xA8,0xBB,0x00,0xFD,0x60,0x58,0x35,0x46,0xCB,0xDF,0x46,0x49,0x25,0x08,0x63,0xF1,0x0A,
																0xFD,0x3C,0x98,0xDD,0x92,0xC4,0x4C,0x68,0x33,0x26,0x75,0xA3,0x70,0xCC,0xEE,0xDE,0x31,0xE0,0xC5,0xCD,0x20,0x9C,0x25,0x76,0x01,0x14,0x9D,0x12,0xB3,0x94,0xA2,0xBE};
	SM9Signature stdsignstr;
	SM9Cipher *stdendatastr,*envk;
	unsigned char pincode[16]={"wuxipiico"};
	unsigned char pucSUserID[]="Alice";
	unsigned char pucEUserID[]="Bob";
	unsigned char messages[]="Chinese IBS standard";
	unsigned char smessages[]="Chinese IBE standard";
	unsigned char pucData[232],pucData2[256];
	HANDLE keyhandle;
	SM9PairSignEnvelopedKey *usenkp;
	SM9PairEncEnvelopedKey *ueenkp;
	int i;
	while(1)
	{
		printf("These operate should run by Administrator in InitStatus\n");
		printf("============SM9 Import key Test====================\n");
		printf("        ImportSignMastPrivateKey ----------1\n");
		printf("        ImportEnMastPrivateKey ------------2\n");
		printf("        BackupAsmyKey ---------------------3\n");
		printf("        ImportSignKeyPair -----------------4\n");
		printf("        ImportEncKeyPair ------------------5\n");
		printf("        Import&Test all KeyPair -----------6\n");
		printf("        Quit ------------------------------0\n");
		printf("Please input you select:");
		scanf("%d",&Gskid);
		switch(Gskid)
		{
			case 1:
				status=SDF_GetPrivateKeyAccessRight(pSessionHandle,mastkeyIndex,pincode,9);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_GenPrivateKeyAccessRight error!return is %08x\n",status);
					return -1;
					}
				memcpy(smvk.s,stdsmvk,SM9ref_MAX_LEN);
				smvk.bits=256;
				status=SDF_ImportSignMastPrivateKey_SM9(pSessionHandle,mastkeyIndex,&smvk);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_ImportSignMastPrivateKey_SM9 error,return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
					return;
				}
				printf("SDF_ImportSignMasrtPrivateKey_SM9 Succeed!\n");
				status=SDF_ExportSignMastPublicKey_SM9(pSessionHandle,mastkeyIndex,&smpk);
				if(status!=SR_SUCCESSFULLY)
				{
						printf("SDF_ExportSignMastPublicKey_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
						return -1;
					}
				else
					{
						printbuff1("Mast sign publickey:",smpk.xa,SM9ref_MAX_LEN);
						printbuff(smpk.xb,SM9ref_MAX_LEN);
						printbuff(smpk.ya,SM9ref_MAX_LEN);
						printbuff(smpk.yb,SM9ref_MAX_LEN);
						}
				uiUserIDLen=strlen(pucSUserID);
				status=SDF_GenerateUseSignKey_SM9 (pSessionHandle,mastkeyIndex,pucSUserID,uiUserIDLen,&suvk);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_GenerateUseSignKey_SM9 error,return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
					return;
				}
				printf("SDF_GenerateUseSignKey_SM9 Succeed!\n");
				printbuff1("user sign privateKey:",suvk.x,SM9ref_MAX_LEN);
				printbuff(suvk.y,SM9ref_MAX_LEN);
				status=SDF_GenerateInternalUseSignKey_SM9(pSessionHandle,mastkeyIndex,uiKeyIndex,pucSUserID,uiUserIDLen,1);
				if(status!=SR_SUCCESSFULLY)
				{
						printf("SDF_GenerateInternalUseSignKey_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
						return -1;
					}
				else
				printf("SDF_GenerateInternalUseSignKey_SM9 succeed!\n");
			
				memcpy(stdsignstr.h,stdsign,SM9ref_MAX_LEN);
				memcpy(stdsignstr.x,stdsign+SM9ref_MAX_LEN,SM9ref_MAX_LEN);
				memcpy(stdsignstr.y,stdsign+2*SM9ref_MAX_LEN,SM9ref_MAX_LEN);
				printbuff1("std sign data:",stdsignstr.h,SM9ref_MAX_LEN);
				printbuff(stdsignstr.x,SM9ref_MAX_LEN);
				printbuff(stdsignstr.y,SM9ref_MAX_LEN);
				status=SDF_ExternalMastKeyVerify_SM9(pSessionHandle,&smpk,pucSUserID,uiUserIDLen,messages,strlen(messages),&stdsignstr);
					if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_ExternalMastKeyVerify_SM9 error ,and return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
						return -1;
					}
				else
					printf("std Signdata SDF_ExternalMastKeyVerify_SM9 succeed!\n");
				status=SDF_InternalMastKeyVerify_SM9(pSessionHandle,mastkeyIndex,pucSUserID,uiUserIDLen,messages,strlen(messages),&stdsignstr);
					if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_InternalIDVerify_SM9 error ,and return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
						return -1;
					}
				else
					printf("std Signdata SDF_InternalMastKeyVerify_SM9 succeed!\n");
				status=SDF_InternalKeySign_SM9(pSessionHandle,mastkeyIndex,uiKeyIndex,messages,strlen(messages),&stdsignstr);
					if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_InternalKeySign_SM9 error ,and return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
						return -1;
					}
				else
					printf("SDF_InternalKeySign_SM9 succeed!\n");
				printbuff1("Sign data is :",stdsignstr.h,SM9ref_MAX_LEN);
				printbuff(stdsignstr.x,SM9ref_MAX_LEN);
				printbuff(stdsignstr.y,SM9ref_MAX_LEN);
			status=SDF_InternalMastKeyVerify_SM9(pSessionHandle,mastkeyIndex,pucSUserID,uiUserIDLen,messages,strlen(messages),&stdsignstr);
			if(status!=SR_SUCCESSFULLY)
			{
					printf("SDF_InternalIDVerify_SM9 error ,and return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
					return -1;
				}
					else
			printf("SDF_InternalMastKeyVerify_SM9 succeed!\n");	
				break;
		case 2:
				status=SDF_GetPrivateKeyAccessRight(pSessionHandle,mastkeyIndex,pincode,9);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_GenPrivateKeyAccessRight error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
					return -1;
					}
				memcpy(emvk.s,stdemvk,SM9ref_MAX_LEN);
				emvk.bits=256;
				status=SDF_ImportEncMastPrivateKey_SM9(pSessionHandle,mastkeyIndex,&emvk);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_ImportEncMastPrivateKey_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
					return -1;
					}
				status=SDF_ExportEncMastPublicKey_SM9(pSessionHandle,mastkeyIndex,&empk);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_ExportEncMastPublicKey_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
					return -1;
					}
				else
					{
						printbuff1("Mast Publickey is :",empk.x,SM9ref_MAX_LEN);
						printbuff(empk.y,SM9ref_MAX_LEN);
						
						}
				status=SDF_GenerateUseEncKey_SM9 (pSessionHandle,mastkeyIndex,pucEUserID,strlen(pucEUserID),&euvk);
				if(status!=SR_SUCCESSFULLY)
				{
						printf("SDF_GenerateUseEncKey_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
						return -1;
						}
				else
				printf("SDF_GenerateUseEncKey_SM9 succeed!\n");
				printbuff1("user encrypt privateKey:",euvk.xa,SM9ref_MAX_LEN);
				printbuff(euvk.xb,SM9ref_MAX_LEN);
				printbuff(euvk.ya,SM9ref_MAX_LEN);
				printbuff(euvk.yb,SM9ref_MAX_LEN);
				status=SDF_GenerateInternalUseEncKey_SM9(pSessionHandle,mastkeyIndex,uiKeyIndex,pucEUserID,strlen(pucEUserID),1);
						if(status!=SR_SUCCESSFULLY)
						{
							printf("SDF_GenerateInternalUseEncKey_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
							return -1;
						}
						else
							printf("SDF_GenerateInternalUseEncKey_SM9 succeed!\n");
				stdendatastr=malloc(sizeof(SM9Cipher)+32+strlen(messages));	
				stdendatastr->enType=SGD_SM9_8_ECB;
				stdendatastr->L=SM9ref_MAX_LEN;
				memcpy(stdendatastr->x,stdendata,SM9ref_MAX_LEN);
				memcpy(stdendatastr->y,stdendata+SM9ref_MAX_LEN,SM9ref_MAX_LEN);
				memcpy(stdendatastr->C,stdendata+2*SM9ref_MAX_LEN,SM9ref_MAX_LEN);
				memcpy(stdendatastr->h,stdendata+3*SM9ref_MAX_LEN,SM9ref_MAX_LEN);
				status=SDF_DecryptWithID_SM9(pSessionHandle,SGD_SM9_8_ECB,mastkeyIndex,pucEUserID,strlen(pucEUserID),stdendatastr,pucData,&puiDataLength);
				if(status!=SR_SUCCESSFULLY)
				{
							printf("SDF_DecryptWithID_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
							free(stdendatastr);
							return -1;
					}
				else if(puiDataLength!=strlen(smessages))
					{
							printf("SDF_DecryptWithID_SM9 return datalength error,return length is %d!\n",puiDataLength);
							free(stdendatastr);
							return -1;
						}
				else if(memcmp(smessages,pucData,puiDataLength)!=0)
					{
							printf("SDF_DecryptWithID_SM9 return data error!return is %s\n",pucData);
							free(stdendatastr);
							return -1;
						}
				else
					printf("STD EnData Decrypt Succeed!\n");
				status=SDF_InternalMastKeyEncrypt_SM9(pSessionHandle,SGD_SM9_8_ECB,mastkeyIndex,pucEUserID,strlen(pucEUserID),NULL,smessages,strlen(smessages),stdendatastr);
				if(status!=SR_SUCCESSFULLY)
				{
							printf("SDF_InternalMastKeyEncrypt_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
							free(stdendatastr);
							return -1;
					}
				printf("STD Message Encrypt Succeed!\n");
				printf("SM9Cipher->enType:%08x\n",stdendatastr->enType);
				printbuff1("SM9Cipher->x",stdendatastr->x,SM9ref_MAX_LEN);
				printbuff1("SM9Cipher->y",stdendatastr->y,SM9ref_MAX_LEN);
				printbuff1("SM9Cipher->h",stdendatastr->h,SM9ref_MAX_LEN);
				printf("SM9Cipher->L:%d\n",stdendatastr->L);
				printbuff1("SM9Cipher->C",stdendatastr->C,stdendatastr->L);
				status=SDF_DecryptWithID_SM9(pSessionHandle,SGD_SM9_8_ECB,mastkeyIndex,pucEUserID,strlen(pucEUserID),stdendatastr,pucData,&puiDataLength);
				if(status!=SR_SUCCESSFULLY)
				{
							printf("SDF_DecryptWithID_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
							free(stdendatastr);
							return -1;
					}
				else if(puiDataLength!=strlen(smessages))
					{
							printf("SDF_DecryptWithID_SM9 return datalength error,return length is %d!\n",puiDataLength);
							free(stdendatastr);
							return -1;
						}
				else if(memcmp(smessages,pucData,puiDataLength)!=0)
					{
							printf("SDF_DecryptWithID_SM9 return data error!return is %s\n",pucData);
							free(stdendatastr);
							return -1;
						}
					else
					printf("EnMessage Decrypt Succeed!\n");	
					free(stdendatastr);		
					break;
			case 3:
				printf("Please input the test keyIndex(0~999):");
				scanf("%d",&uiKeyIndex);
				mastkeyIndex=uiKeyIndex;
				status=SDF_GetPrivateKeyAccessRight(pSessionHandle,uiKeyIndex,pincode,9);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_GenPrivateKeyAccessRight error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
					return -1;
					}
				status=SDF_GetPrivateKeyAccessRight(pSessionHandle,mastkeyIndex,pincode,9);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SDF_GenPrivateKeyAccessRight error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
					return -1;
					}
				status=SDF_ExportEncMastPublicKey_SM9 (pSessionHandle, mastkeyIndex,&empk);
				if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_ExportEncMastPublicKey_SM9 error ,and return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
						return -1;
						}
				status=SDF_GenerateRandom(pSessionHandle,16,IV);
				if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_GenerateRandom error ,and return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
						return -1;
						}
					envk=malloc(sizeof(SM9Cipher)+170);	
					printf("Please select the Type of KeyPair:\n1)SignMast 2)EncMast 3)SignUser 4)EncUser\nPlease input select:");
					scanf("%d",&Gsel);
					switch(Gsel)
					{
						case 1:
						default:
							uitype=SIGN_MAST_KEYPAIR;
							printf("Export the Sign Mast Key Pair:\n");
							break;
						case 2:
							uitype=ENC_MAST_KEYPAIR;
							printf("Export the Enc Mast Key Pair:\n");
							break;
						case 3:
							uitype=SIGN_USER_KEYPAIR;
							printf("Export the SIGN USER Key Pair:\n");
							break;
						case 4:
							uitype=ENC_USER_KEYPAIR;
							printf("Export the Enc USER Key Pair:\n");
							break;
													
						}
					printf("Please input the Export Alog:\n1)SM9_ECB 2)SM9_CBC 3)SM9\nPlease input you select:");
					scanf("%d",&Gsel);
					switch(Gsel)
					{
						case 1:
						default:
							alog=SGD_SM9_8_ECB;
							break;
						case 2:
							alog=SGD_SM9_8_CBC;
							break;
						case 3:
							alog=SGD_SM9_8;
							break;
						}
						if(alog==SGD_SM9_8_CBC)
							printbuff1("IV:",IV,16);
					status=SDF_BackupAsmyKey(pSessionHandle,alog,uitype,uiKeyIndex,&empk,IV,pucEUserID,strlen(pucEUserID),pucData,&puiDataLength,envk);
					if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_BackupAsmyKey error ,and return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
						free(envk);
						return -1;
						}	
						printbuff1("Export PK",pucData,puiDataLength);
						printf("Encrypt VK enType:%08x\n",envk->enType);
					printbuff1("Encrypt VK x:",envk->x,SM9ref_MAX_LEN);
					printbuff1("Encrypt VK y:",envk->y,SM9ref_MAX_LEN);
					printbuff1("Encrypt VK h:",envk->h,SM9ref_MAX_LEN);
					printf("Encrypt VK L:%08x\n",envk->L);
					printbuff1("Encrypt VK C:",envk->C,envk->L);
					status=SDF_DecryptWithID_SM9(pSessionHandle,alog,mastkeyIndex,pucEUserID,strlen(pucEUserID),envk,pucData2,&puiDataLength);
					if(status!=SR_SUCCESSFULLY)
					{
								printf("SDF_DecryptWithID_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
								free(envk);
								return -1;
						}	
					printbuff1("export vk is :",pucData2,puiDataLength);	
						
					free(envk);
					break;
			case 4:
					mastkeyIndex=1;
					status=SDF_GenerateRandom(pSessionHandle,16,pucData);
					if(status!=SR_SUCCESSFULLY)
					{
								printf("SDF_GenerateRandom error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
								return -1;
						}	
					else
						printf("SDF_GenerateRandom succeed!\n");
					status=SDF_ImportKey(pSessionHandle,pucData,16,&keyhandle);
					if(status!=SR_SUCCESSFULLY)
					{
								printf("SDF_ImportKey error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
								return -1;
						}	
						else
						printf("SDF_ImportKey succeed!\n");
					usenkp=malloc(sizeof(SM9PairSignEnvelopedKey)+32);	
					status=SDF_Encrypt(pSessionHandle,keyhandle,SGD_SM4_ECB,NULL,stdsuvk,64,usenkp->encryptedPriKey,&puiDataLength);
					if(status!=SR_SUCCESSFULLY)
					{
								printf("SDF_Encrypt error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
								SDF_DestroyKey(pSessionHandle,keyhandle);
								free(usenkp);
								return -1;
						}	
					else
						printf("SDF_Encrypt succeed!\n");
					SDF_DestroyKey(pSessionHandle,keyhandle);
					status=SDF_InternalMastKeyEncrypt_SM9(pSessionHandle,SGD_SM9_8_ECB,mastkeyIndex,pucSUserID,strlen(pucSUserID),NULL,pucData,16,&(usenkp->pairCipher));
					if(status!=SR_SUCCESSFULLY)
					{
								printf("SDF_InternalMastKeyEncrypt_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
								free(usenkp);
								return -1;
						}
					else
						printf("SDF_InternalMastKeyEncrypt_SM9 succeed!\n");
					memcpy(usenkp->userID,pucSUserID,strlen(pucSUserID))	;
					usenkp->userIDLen=strlen(pucSUserID);
					status=SDF_ExportSignMastPublicKey_SM9(pSessionHandle,mastkeyIndex,&(usenkp->encMastPubKey));
					if(status!=SR_SUCCESSFULLY)
					{
								printf("SDF_ExportEncMastPublicKey_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
								free(usenkp);
								return -1;
						}
					else
						printf("SDF_ExportSignMastPublicKey_SM9 succeed!\n");
						usenkp->symmAlgID=SGD_SM4_ECB;
						usenkp->aSymmAlgID=SGD_SM9_8_ECB;	
					status=SDF_ImportSignKeyPair_SM9(pSessionHandle,mastkeyIndex,mastkeyIndex+1,mastkeyIndex+1,pincode,strlen(pincode),pincode,strlen(pincode),usenkp);
					if(status!=SR_SUCCESSFULLY)
					{
								printf("SDF_ImportSignKeyPair_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
								free(usenkp);
								return -1;
						}
					else
						printf("SDF_ImportSignKeyPair_SM9 succeed!\n");
					free(usenkp);
					memcpy(stdsignstr.h,stdsign,SM9ref_MAX_LEN);
					memcpy(stdsignstr.x,stdsign+SM9ref_MAX_LEN,SM9ref_MAX_LEN);
					memcpy(stdsignstr.y,stdsign+2*SM9ref_MAX_LEN,SM9ref_MAX_LEN);
					status=SDF_InternalMastKeyVerify_SM9(pSessionHandle,mastkeyIndex+1,pucSUserID,strlen(pucSUserID),messages,strlen(messages),&stdsignstr);
					if(status!=SR_SUCCESSFULLY)
					{
							printf("SDF_InternalMastKeyVerify_SM9 Verify Std data error ,and return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
							return -1;
						}
					else
						printf("SDF_InternalMastKeyVerify_SM9 Verify Std data succeed!\n");
					status=SDF_InternalKeySign_SM9(pSessionHandle,mastkeyIndex+1,uiKeyIndex+1,messages,strlen(messages),&stdsignstr);
					if(status!=SR_SUCCESSFULLY)
					{
						printf("SDF_InternalKeySign_SM9 error ,and return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
						return -1;
					}
				else
					printf("SDF_InternalKeySign_SM9 succeed!\n");
				printbuff1("Sign data is :",stdsignstr.h,SM9ref_MAX_LEN);
				printbuff(stdsignstr.x,SM9ref_MAX_LEN);
				printbuff(stdsignstr.y,SM9ref_MAX_LEN);
				status=SDF_InternalMastKeyVerify_SM9(pSessionHandle,mastkeyIndex+1,pucSUserID,strlen(pucSUserID),messages,strlen(messages),&stdsignstr);
				if(status!=SR_SUCCESSFULLY)
				{
						printf("SDF_InternalIDVerify_SM9 error ,and return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
						return -1;
					}
						else
				printf("SDF_InternalMastKeyVerify_SM9 succeed!\n");	
				break;
			case 5:
				mastkeyIndex=1;
			status=SDF_GenerateRandom(pSessionHandle,16,pucData);
					if(status!=SR_SUCCESSFULLY)
					{
								printf("SDF_GenerateRandom error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
								return -1;
						}	
					else
						printf("SDF_GenerateRandom succeed!\n");
			status=SDF_ImportKey(pSessionHandle,pucData,16,&keyhandle);
					if(status!=SR_SUCCESSFULLY)
					{
								printf("SDF_ImportKey error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
								return -1;
						}	
					else
						printf("SDF_ImportKey succeed!\n");
					ueenkp=malloc(sizeof(SM9PairEncEnvelopedKey)+32);	
					status=SDF_Encrypt(pSessionHandle,keyhandle,SGD_SM4_ECB,NULL,stdsuvk,128,ueenkp->encryptedPriKey,&puiDataLength);
					if(status!=SR_SUCCESSFULLY)
					{
								printf("SDF_Encrypt error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
								SDF_DestroyKey(pSessionHandle,keyhandle);
								free(ueenkp);
								return -1;
						}	
						else
						printf("SDF_Encrypt succeed!\n");
						SDF_DestroyKey(pSessionHandle,keyhandle);
					status=SDF_InternalMastKeyEncrypt_SM9(pSessionHandle,SGD_SM9_8_ECB,mastkeyIndex,pucEUserID,strlen(pucEUserID),NULL,pucData,16,&(ueenkp->pairCipher));
					if(status!=SR_SUCCESSFULLY)
					{
								printf("SDF_InternalMastKeyEncrypt_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
								free(ueenkp);
								return -1;
						}
							else
						printf("SDF_InternalMastKeyEncrypt_SM9 succeed!\n");
					memcpy(ueenkp->userID,pucEUserID,strlen(pucEUserID))	;
					ueenkp->userIDLen=strlen(pucEUserID);
					status=SDF_ExportEncMastPublicKey_SM9(pSessionHandle,mastkeyIndex,&(ueenkp->encMastPubKey));
					if(status!=SR_SUCCESSFULLY)
					{
								printf("SDF_ExportEncMastPublicKey_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
								free(ueenkp);
								return -1;
						}
						else
						printf("SDF_ExportEncMastPublicKey_SM9 succeed!\n");
						ueenkp->symmAlgID=SGD_SM4_ECB;
						ueenkp->aSymmAlgID=SGD_SM9_8_ECB;	
					status=SDF_ImportEncKeyPair_SM9(pSessionHandle,mastkeyIndex,mastkeyIndex+1,mastkeyIndex+1,pincode,strlen(pincode),pincode,strlen(pincode),ueenkp);
					if(status!=SR_SUCCESSFULLY)
					{
								printf("SDF_ImportSignKeyPair_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
								free(ueenkp);
								return -1;
						}
							else
						printf("SDF_ImportEncKeyPair_SM9 succeed!\n");
					free(ueenkp);
					
				stdendatastr=malloc(sizeof(SM9Cipher)+32+strlen(messages));	
				stdendatastr->enType=SGD_SM9_8_ECB;
				stdendatastr->L=SM9ref_MAX_LEN;
				memcpy(stdendatastr->x,stdendata,SM9ref_MAX_LEN);
				memcpy(stdendatastr->y,stdendata+SM9ref_MAX_LEN,SM9ref_MAX_LEN);
				memcpy(stdendatastr->C,stdendata+2*SM9ref_MAX_LEN,SM9ref_MAX_LEN);
				memcpy(stdendatastr->h,stdendata+3*SM9ref_MAX_LEN,SM9ref_MAX_LEN);
				status=SDF_DecryptWithID_SM9(pSessionHandle,SGD_SM9_8_ECB,mastkeyIndex+1,pucEUserID,strlen(pucEUserID),stdendatastr,pucData,&puiDataLength);
				if(status!=SR_SUCCESSFULLY)
				{
							printf("SDF_DecryptWithID_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
							free(stdendatastr);
							return -1;
					}
				else if(puiDataLength!=strlen(smessages))
					{
							printf("SDF_DecryptWithID_SM9 return datalength error,return length is %d!\n",puiDataLength);
							free(stdendatastr);
							return -1;
						}
				else if(memcmp(smessages,pucData,puiDataLength)!=0)
					{
							printf("SDF_DecryptWithID_SM9 return data error!return is %s\n",pucData);
							free(stdendatastr);
							return -1;
						}
				else
						printf("SDF_DecryptWithID_SM9 succeed!\n");
				status=SDF_InternalMastKeyEncrypt_SM9(pSessionHandle,SGD_SM9_8_ECB,mastkeyIndex+1,pucEUserID,strlen(pucEUserID),NULL,messages,strlen(messages),stdendatastr);
				if(status!=SR_SUCCESSFULLY)
				{
							printf("SDF_InternalMastKeyEncrypt_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
							free(stdendatastr);
							return -1;
					}
				else
						printf("SDF_InternalMastKeyEncrypt_SM9 succeed!\n");	
				printf("SM9Cipher->enType:%08x\n",stdendatastr->enType);
				printbuff1("SM9Cipher->x",stdendatastr->x,SM9ref_MAX_LEN);
				printbuff1("SM9Cipher->y",stdendatastr->y,SM9ref_MAX_LEN);
				printbuff1("SM9Cipher->h",stdendatastr->h,SM9ref_MAX_LEN);
				printf("SM9Cipher->L:%d\n",stdendatastr->L);
				printbuff1("SM9Cipher->C",stdendatastr->C,stdendatastr->L);
				status=SDF_DecryptWithID_SM9(pSessionHandle,SGD_SM9_8_ECB,mastkeyIndex+1,pucEUserID,strlen(pucEUserID),stdendatastr,pucData,&puiDataLength);
				if(status!=SR_SUCCESSFULLY)
				{
							printf("SDF_DecryptWithID_SM9 error!return is %08x\n",SPII_GetErrorInfo(pSessionHandle));
							free(stdendatastr);
							return -1;
					}
				else if(puiDataLength!=strlen(messages))
					{
							printf("SDF_DecryptWithID_SM9 return datalength error,return length is %d!\n",puiDataLength);
							free(stdendatastr);
							return -1;
						}
				else if(memcmp(messages,pucData,puiDataLength)!=0)
					{
							printf("SDF_DecryptWithID_SM9 return data error!return is %s\n",pucData);
							free(stdendatastr);
							return -1;
						}
					else
						printf("SDF_DecryptWithID_SM9 succeed!\n");		
					free(stdendatastr);		
					break;
			case 6:
				memcpy(smvk.s,stdsmvk,SM9ref_MAX_LEN);
				smvk.bits=256;
				memcpy(emvk.s,stdemvk,SM9ref_MAX_LEN);
				emvk.bits=256;
				printf("Please input your test mod:\n1)input std keypair  2)Test all keypair\n");
				printf("Please input your select:");
				scanf("%d",&Gsel);
				printf("\n");
				switch(Gsel)
				{
					case 1:
						uitype=1;
						break;
					case 2:
					default:
						uitype=0;
						break;
					}
				for(i=0;i<=KEYPAIR_MAX_INDEX;i++)
				{
							status=SDF_GetPrivateKeyAccessRight(pSessionHandle,i,pincode,9);
							if(status!=SR_SUCCESSFULLY)
							{
								printf("NO %d KeyPair SDF_GetPrivateKeyAccessRight error!return is %08x,%08x\n",i,status,SPII_GetErrorInfo(pSessionHandle));
								return -1;
								}
							if(uitype)
								{
										status=SDF_ImportSignMastPrivateKey_SM9(pSessionHandle,i,&smvk);
										if(status!=SR_SUCCESSFULLY)
										{
											printf("NO %d KeyPair SDF_ImportSignMastPrivateKey_SM9 error,return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
											return;
										}
						//				printf("SDF_ImportSignMasrtPrivateKey_SM9 Succeed!\n");
									
										status=SDF_GenerateInternalUseSignKey_SM9(pSessionHandle,i,i,pucSUserID,strlen(pucSUserID),1);
										if(status!=SR_SUCCESSFULLY)
										{
												printf("NO %d KeyPair SDF_GenerateInternalUseSignKey_SM9 error!return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
												return -1;
											}
										status=SDF_ImportEncMastPrivateKey_SM9(pSessionHandle,i,&emvk);
										if(status!=SR_SUCCESSFULLY)
										{
											printf("NO %d KeyPair SDF_ImportEncMastPrivateKey_SM9 error!return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
											return -1;
											}
							
										status=SDF_GenerateInternalUseEncKey_SM9(pSessionHandle,i,i,pucEUserID,strlen(pucEUserID),1);
												if(status!=SR_SUCCESSFULLY)
												{
													printf("NO %d KeyPair SDF_GenerateInternalUseEncKey_SM9 error!return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
													return -1;
												}
									}
							else
								{
											memcpy(stdsignstr.h,stdsign,SM9ref_MAX_LEN);
											memcpy(stdsignstr.x,stdsign+SM9ref_MAX_LEN,SM9ref_MAX_LEN);
											memcpy(stdsignstr.y,stdsign+2*SM9ref_MAX_LEN,SM9ref_MAX_LEN);
								
											status=SDF_InternalMastKeyVerify_SM9(pSessionHandle,i,pucSUserID,strlen(pucSUserID),messages,strlen(messages),&stdsignstr);
												if(status!=SR_SUCCESSFULLY)
												{
													printf("NO %d KeyPair SDF_InternalIDVerify_SM9 error ,and return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
													return -1;
												}
								
											status=SDF_InternalKeySign_SM9(pSessionHandle,i,i,messages,strlen(messages),&stdsignstr);
												if(status!=SR_SUCCESSFULLY)
												{
													printf("NO %d KeyPair SDF_InternalKeySign_SM9 error ,and return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
													return -1;
												}
				
										status=SDF_InternalKeyVerify_SM9(pSessionHandle,i,i,messages,strlen(messages),&stdsignstr);
										if(status!=SR_SUCCESSFULLY)
										{
												printf("NO %d KeyPair SDF_InternalIDVerify_SM9 error ,and return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
												return -1;
											}
												stdendatastr=malloc(sizeof(SM9Cipher)+32+strlen(messages));	
										stdendatastr->enType=SGD_SM9_8_ECB;
										stdendatastr->L=SM9ref_MAX_LEN;
										memcpy(stdendatastr->x,stdendata,SM9ref_MAX_LEN);
										memcpy(stdendatastr->y,stdendata+SM9ref_MAX_LEN,SM9ref_MAX_LEN);
										memcpy(stdendatastr->C,stdendata+2*SM9ref_MAX_LEN,SM9ref_MAX_LEN);
										memcpy(stdendatastr->h,stdendata+3*SM9ref_MAX_LEN,SM9ref_MAX_LEN);
										status=SDF_DecryptWithID_SM9(pSessionHandle,SGD_SM9_8_ECB,i,pucEUserID,strlen(pucEUserID),stdendatastr,pucData,&puiDataLength);
										if(status!=SR_SUCCESSFULLY)
										{
													printf("NO %d KeyPair SDF_DecryptWithID_SM9 error!return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
													free(stdendatastr);
													return -1;
											}
										else if(puiDataLength!=strlen(smessages))
											{
													printf("NO %d KeyPair SDF_DecryptWithID_SM9 return datalength error,return length is %d!\n",i,puiDataLength);
													free(stdendatastr);
													return -1;
												}
										else if(memcmp(smessages,pucData,puiDataLength)!=0)
											{
													printf("NO %d KeyPair SDF_DecryptWithID_SM9 return data error!return is %s\n",i,pucData);
													free(stdendatastr);
													return -1;
												}
										
										status=SDF_InternalKeyEncrypt_SM9(pSessionHandle,SGD_SM9_8_ECB,i,i,NULL,smessages,strlen(smessages),stdendatastr);
										if(status!=SR_SUCCESSFULLY)
										{
													printf("NO %d KeyPair SDF_InternalMastKeyEncrypt_SM9 error!return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
													free(stdendatastr);
													return -1;
											}
										status=SDF_DecryptWithID_SM9(pSessionHandle,SGD_SM9_8_ECB,i,pucEUserID,strlen(pucEUserID),stdendatastr,pucData,&puiDataLength);
										if(status!=SR_SUCCESSFULLY)
										{
													printf("NO %d KeyPair SDF_DecryptWithID_SM9 error!return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
													free(stdendatastr);
													return -1;
											}
										else if(puiDataLength!=strlen(smessages))
											{
													printf("NO %d KeyPair SDF_DecryptWithID_SM9 return datalength error,return length is %d!\n",i,puiDataLength);
													free(stdendatastr);
													return -1;
												}
										else if(memcmp(smessages,pucData,puiDataLength)!=0)
											{
													printf("NO %d KeyPair SDF_DecryptWithID_SM9 return data error!return is %s\n",i,pucData);
													free(stdendatastr);
													return -1;
												}
											free(stdendatastr);
										}
					
									PrintPer("Import all SM9 Mast key User KeyPair and Test it",KEYPAIR_MAX_INDEX,i);
					}
			case 0:
						return 0;
			default:
						break;
		}



	}
}
int SM9Agreement(HANDLE pSessionHandle)
{
	SM9EncMastPublicKey smpk,smtpk,rmtpk,rmpk;
	unsigned char sPID[1024],rPID[1024],endata[128],data2[128];
	unsigned char data[48]={0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
				0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
                                0x86,0x90,0x29,0x3b,0x85,0x0c,0xfc,0x4b,0xc0,0xb6,0x54,0x00,0xee,0x92,0xcb,0xd3};
	unsigned char pincode[16]={"wuxipiico"};
	HANDLE keyHandle1,keyHandle2,argmHandle;
	unsigned int suiISKIndex=1,ruiISKIndex=2;
	unsigned int spidlen,rpidlen,enlen,len;
	int status=0;
	status=SDF_ExportEncMastPublicKey_SM9 (pSessionHandle,suiISKIndex,&smpk);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("Export Sender Mast Encrypt Key error!return is %08x\n",status);
			return -1;
			}
	else
		printf("Export Sender Mast Encrypt Key succeed!\n");
	status=SDF_ExportEncMastPublicKey_SM9 (pSessionHandle,ruiISKIndex,&rmpk);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("Export Receiver Mast Encrypt Key error!return is %08x\n",status);
			return -1;
			}
	else
		printf("Export Receiver Mast Encrypt Key succeed!\n");
	status=SDF_ExportEncID_SM9 (pSessionHandle,suiISKIndex, sPID,&spidlen	);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("Export Sender ID error!return is %08x\n",status);
			return -1;
			}
	else
		printf("Export Sender ID succeed!\n");
	status=SDF_ExportEncID_SM9 (pSessionHandle,ruiISKIndex, rPID,&rpidlen	);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("Export receiver ID error!return is %08x\n",status);
			return -1;
			}
	else
		printf("Export receiver ID succeed!\n");
	status=SDF_GetPrivateKeyAccessRight(pSessionHandle,suiISKIndex,pincode,strlen(pincode));
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_GetPrivateKeyAccessRight error!return is %08x\n",status);
			return -1;
			}
	else
		printf("Get %d Private Key Access Right succeed!\n",suiISKIndex);
	status=SDF_GetPrivateKeyAccessRight(pSessionHandle,ruiISKIndex,pincode,strlen(pincode));
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_GetPrivateKeyAccessRight error!return is %08x\n",status);
			return -1;
			}
	else
		printf("Get %d Private Key Access Right succeed!\n",ruiISKIndex);
	status=SDF_GenerateAgreementDataWithSM9(pSessionHandle,suiISKIndex,128,rPID,rpidlen,sPID,spidlen,&rmpk,&smtpk,&argmHandle);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_GenerateAgreementDataWithSM9 error!return is %08x %08x\n",status,SPII_GetErrorInfo(pSessionHandle));
			return -1;
			}
	else
		printf("SDF_GenerateAgreementDataWithSM9 succeed!\n");
	printbuff(smpk.x,SM9ref_MAX_LEN);
	printbuff(smpk.y,SM9ref_MAX_LEN);
	status=SDF_GenerateAgreementDataAndKeyWithSM9(pSessionHandle,ruiISKIndex,128,rPID,rpidlen,sPID,spidlen,&smpk,&smtpk,&rmtpk,&keyHandle1);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_GenerateAgreementDataAndKeyWithSM9 error!return is %08x %08x\n",status,SPII_GetErrorInfo(pSessionHandle));
			status=SPII_DestroyAgreementHandle(pSessionHandle,argmHandle);
			if(status!=SR_SUCCESSFULLY) printf("SPII_DestroyAgreementHandle error!return is %08x\n",status);
			return -1;
			}
	else
		printf("SDF_GenerateAgreementDataAndKeyWithSM9 succeed!\n");
	status=SDF_GenerateKeyWithSM9(pSessionHandle,argmHandle,&rmtpk,&keyHandle2);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_GenerateKeyWithSM9 error!return is %08x,%08x\n",status,SPII_GetErrorInfo(pSessionHandle));
			status=SPII_DestroyAgreementHandle(pSessionHandle,argmHandle);
			if(status!=SR_SUCCESSFULLY) printf("SPII_DestroyAgreementHandle error!return is %08x\n",status);
			status=SDF_DestroyKey(pSessionHandle,keyHandle1);
			return -1;
			}
	else
		printf("SDF_GenerateKeyWithSM9 succeed!\n");
	status=SPII_DestroyAgreementHandle(pSessionHandle,argmHandle);
	if(status!=SR_SUCCESSFULLY) printf("SPII_DestroyAgreementHandle error!return is %08x\n",status);
	status=SDF_Encrypt(pSessionHandle,keyHandle1,SGD_SM4_ECB,NULL,data,48,endata,&enlen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_Encrypt error!return is %08x\n",status);
			SDF_DestroyKey(pSessionHandle,keyHandle1);
			SDF_DestroyKey(pSessionHandle,keyHandle2);
			return -1;
			
			}
	else
		printf("SDF_Encrypt succeed!\n");
	if(enlen!=48)
		{
			printf("SDF_Encrypt return endata length error!return length is %d\n",enlen);
			SDF_DestroyKey(pSessionHandle,keyHandle1);
			SDF_DestroyKey(pSessionHandle,keyHandle2);
			return -1;
			}
	status=SDF_Decrypt(pSessionHandle,keyHandle2,SGD_SM4_ECB,NULL,endata,enlen,data2,&len);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_Decrypt error!return is %08x,%08x\n",status,SPII_GetErrorInfo(pSessionHandle));
			SDF_DestroyKey(pSessionHandle,keyHandle1);
			SDF_DestroyKey(pSessionHandle,keyHandle2);
			return -1;
			
			}
	else
		printf("SDF_Decrypt succeed!\n");
	SDF_DestroyKey(pSessionHandle,keyHandle1);
	SDF_DestroyKey(pSessionHandle,keyHandle2);
	if(len!=48&&(memcmp(data2,data,len)!=0))
		printf("Compare error ,the Agreement Key is defierent!\n");
	else
		printf("SM9 Agreement  Succeed!\n");
		return 0;
	
	}
int SM9TestAllKeyPair(HANDLE pSessionHandle)
{
	int Gskid=0,status=0,uiUserIDLen=0,puiDataLength,Gsel=0,uitype=0,alog=0,i;
	unsigned int uiKeyIndex=1;
	unsigned int mastkeyIndex=1;
	SM9SignMastPrivateKey smvk;
	SM9EncMastPrivateKey emvk;
	 SM9UserEncPrivateKey  euvk;
	 SM9UserSignPrivateKey suvk;
	 SM9EncMastPublicKey empk;
	 SM9SignMastPublicKey smpk;
	 unsigned char IV[16]={0};
	 	SM9Signature stdsignstr;
	SM9Cipher *stdendatastr,*envk;
	unsigned char pincode[16]={"wuxipiico"};
	unsigned char pucEUserID[100];
	unsigned char messages[]="Chinese IBS standard";
	unsigned char smessages[]="Chinese IBE standard";
	unsigned char pucData[232],pucData2[256];
	 for(i=1;i<=KEYPAIR_MAX_INDEX;i++)
				{
							status=SDF_GetPrivateKeyAccessRight(pSessionHandle,i,pincode,9);
							if(status!=SR_SUCCESSFULLY)
							{
								printf("NO %d KeyPair SDF_GetPrivateKeyAccessRight error!return is %08x,%08x\n",i,status,SPII_GetErrorInfo(pSessionHandle));
								return -1;
								}
							
						
								stdendatastr=malloc(sizeof(SM9Cipher)+32+strlen(messages));	
								status=SDF_InternalKeyEncrypt_SM9(pSessionHandle,SGD_SM9_8_ECB,i,i,NULL,smessages,strlen(smessages),stdendatastr);
								if(status!=SR_SUCCESSFULLY)
								{
											printf("NO %d KeyPair SDF_InternalMastKeyEncrypt_SM9 error!return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
													free(stdendatastr);
												return -1;
										}
								status=SDF_ExportEncID_SM9 (pSessionHandle,i, pucEUserID,&uiUserIDLen			);
									if(status!=SR_SUCCESSFULLY)
										{
													printf("NO %d KeyPair SDF_ExportEncID_SM9 error!return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
													free(stdendatastr);
													return -1;
											}
								status=SDF_DecryptWithID_SM9(pSessionHandle,SGD_SM9_8_ECB,i,pucEUserID,uiUserIDLen,stdendatastr,pucData,&puiDataLength);
									if(status!=SR_SUCCESSFULLY)
										{
													printf("NO %d KeyPair SDF_DecryptWithID_SM9 error!return is %08x,%08x\n",i,status,SPII_GetErrorInfo(pSessionHandle));
													
													free(stdendatastr);
													return -1;
											}
										else if(puiDataLength!=strlen(smessages))
											{
													printf("NO %d KeyPair SDF_DecryptWithID_SM9 return datalength error,return length is %d!\n",i,puiDataLength);
													free(stdendatastr);
													return -1;
												}
										else if(memcmp(smessages,pucData,puiDataLength)!=0)
											{
													printf("NO %d KeyPair SDF_DecryptWithID_SM9 return data error!return is %s\n",i,pucData);
													free(stdendatastr);
													return -1;
												}
											free(stdendatastr);
										status=SDF_InternalKeySign_SM9(pSessionHandle,i,i,messages,strlen(messages),&stdsignstr);
										if(status!=SR_SUCCESSFULLY)
										{
													printf("NO %d KeyPair SDF_InternalKeySign_SM9 error ,and return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
													return -1;
											}
										status=SDF_InternalKeyVerify_SM9(pSessionHandle,i,i,messages,strlen(messages),&stdsignstr);
										if(status!=SR_SUCCESSFULLY)
										{
													printf("NO %d KeyPair SDF_InternalIDVerify_SM9 error ,and return is %08x\n",i,SPII_GetErrorInfo(pSessionHandle));
													return -1;
											}
					
									PrintPer("Import all SM9 Mast key User KeyPair and Test it",KEYPAIR_MAX_INDEX,i);
					}
	 
	}
int SM9EncapsulePack(HANDLE pSessionHandle)
{
	SM9KeyPackage pucEncapCipher;
	SM9EncMastPublicKey pucEncMastPubKey;
	unsigned char PID[1024],endata[128],data2[128];
	unsigned char data[48]={0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
				0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
                                0x86,0x90,0x29,0x3b,0x85,0x0c,0xfc,0x4b,0xc0,0xb6,0x54,0x00,0xee,0x92,0xcb,0xd3};
	unsigned char pincode[16]={"wuxipiico"};
	HANDLE keyHandle1,keyHandle2;
	unsigned int uiISKIndex=1;
	unsigned int pidlen,enlen,len;
	int status=0;
	status=SDF_ExportEncMastPublicKey_SM9 (pSessionHandle,uiISKIndex,&pucEncMastPubKey);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("Export Sender Mast Encrypt Key error!return is %08x\n",status);
			return -1;
			}
	else
		printf("Export Sender Mast Encrypt Key succeed!\n");
	status=SDF_ExportEncID_SM9 (pSessionHandle,uiISKIndex, PID,&pidlen	);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("Export Sender ID error!return is %08x\n",status);
			return -1;
			}
	else
		printf("Export Sender ID succeed!\n");
	status=SDF_GetPrivateKeyAccessRight(pSessionHandle,uiISKIndex,pincode,strlen(pincode));
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_GetPrivateKeyAccessRight error!return is %08x\n",status);
			return -1;
			}
	else
		printf("Get %d Private Key Access Right succeed!\n",uiISKIndex);
	status= SDF_KeyEncapsulePack_SM9(pSessionHandle, &pucEncMastPubKey,PID,pidlen,128,&pucEncapCipher,&keyHandle1);
	if(status!=SR_SUCCESSFULLY)
		{
				printf("SDF_KeyEncapsulePack_SM9 error!return is %08x,%08x\n",status,SPII_GetErrorInfo(pSessionHandle));
				return -1;
			}
		else
		printf("SDF_KeyEncapsulePack_SM9 succeed!\n");						
	status= SDF_KeyEncapsuleUnpack_SM9(pSessionHandle,uiISKIndex,PID,pidlen,128,&pucEncapCipher,&keyHandle2);
		if(status!=SR_SUCCESSFULLY)
		{
				printf("SDF_KeyEncapsuleUnpack_SM9 error!return is %08x %08x\n",status,SPII_GetErrorInfo(pSessionHandle));
					SDF_DestroyKey(pSessionHandle,keyHandle2);
				return -1;
			}
	else
		printf("SDF_KeyEncapsuleUnpack_SM9 succeed!\n");	
		status=SDF_Encrypt(pSessionHandle,keyHandle1,SGD_SM4_ECB,NULL,data,48,endata,&enlen);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_Encrypt error!return is %08x\n",status);
			SDF_DestroyKey(pSessionHandle,keyHandle1);
			SDF_DestroyKey(pSessionHandle,keyHandle2);
			return -1;
			
			}
	else
		printf("SDF_Encrypt succeed!\n");
	if(enlen!=48)
		{
			printf("SDF_Encrypt return endata length error!return length is %d\n",enlen);
			SDF_DestroyKey(pSessionHandle,keyHandle1);
			SDF_DestroyKey(pSessionHandle,keyHandle2);
			return -1;
			}
	status=SDF_Decrypt(pSessionHandle,keyHandle2,SGD_SM4_ECB,NULL,endata,enlen,data2,&len);
	if(status!=SR_SUCCESSFULLY)
		{
			printf("SDF_Decrypt error!return is %08x\n",status);
			SDF_DestroyKey(pSessionHandle,keyHandle1);
			SDF_DestroyKey(pSessionHandle,keyHandle2);
			return -1;
			
			}
	else
		printf("SDF_Decrypt succeed!\n");
	SDF_DestroyKey(pSessionHandle,keyHandle1);
	SDF_DestroyKey(pSessionHandle,keyHandle2);
	if(len!=48&&(memcmp(data2,data,len)!=0))
		printf("Compare error ,the EncapsulePack Key is defierent!\n");
	else
		printf("SM9 EncapsulePack  Succeed!\n");		
		return 0;
	}
void SM9Test()
{
	HANDLE DeviceHandle,pSessionHandle;
	int Gskid=0,status=0,uiUserIDLen;
	unsigned int mastkeyIndex;
	SM9UserEncPrivateKey  pucenPrivateKey;
	SM9UserSignPrivateKey pucsiPrivateKey;
	unsigned char pucUserID[1024];
	status=SDF_OpenDevice(&DeviceHandle);
	if(status!=SR_SUCCESSFULLY)
	{
		printf("SDF_OpenDevice error!return is %08x\n",status);
		return;
	}
	status=SDF_OpenSession(DeviceHandle,&pSessionHandle);
	if(status!=SR_SUCCESSFULLY)
	{
		printf("SDF_OpenSession error!return is %08x\n",status);
		SDF_CloseDevice(DeviceHandle);
		return;
	}
	while(1)
	{
		printf("============SM9 Test====================\n");
		printf("      SK Encrypt&Decrypt Test ------------1\n");
		printf("      Message Encrypt&Decrypt Test -------2\n");
		printf("      Sign Test --------------------------3\n");
		printf("      KeyPair Generate -------------------4\n");
		printf("      Capability test --------------------5\n");
		printf("      Import Key test --------------------6\n");
		printf("      Agreement --------------------------7\n");
		printf("      EncapsulePack ----------------------8\n");
		printf("      Test All Key Pair In Card ----------9\n");
		printf("      Quit -------------------------------0\n");
		printf("Please input you select:");
		scanf("%d",&Gskid);
		switch(Gskid)
		{
			case 9:
				status=SM9TestAllKeyPair(pSessionHandle);
				if(status!=SR_SUCCESSFULLY)
					{
						printf("SM9TestAllKeyPair error!\n");
						}
						break;
			case 1:
				status=SM9SKtest(pSessionHandle);
				if(status!=SR_SUCCESSFULLY)
					{
						printf("SM9SKtest error!\n");
						}
						break;
			case 2:
				status=SM9MessageEDTest(pSessionHandle);
				if(status!=SR_SUCCESSFULLY)
					{
						printf("SM9MessageEDTest error!\n");
						}
						break;
			case 3:
				status=SM9SignTest(pSessionHandle);
				if(status!=SR_SUCCESSFULLY)
					{
						printf("SM9SignTest error!\n");
						}
						break;
			case 4:
						printf("Please input the test mastkey(0~1024):");
						scanf("%d",&mastkeyIndex);
						printf("Please input the pucUserID:");
						scanf("%s",&pucUserID);
						uiUserIDLen=strlen(pucUserID);
						status=SDF_GenerateUseSignKey_SM9 (pSessionHandle,mastkeyIndex,pucUserID,uiUserIDLen,&pucsiPrivateKey);
						if(status!=SR_SUCCESSFULLY)
						{
							printf("SDF_GenerateUseSignKey_SM9 error!return is %08x\n",status);
							break;
						}
						else
							printf("SDF_GenerateUseSignKey_SM9 succeed!\n");
						status=SDF_GenerateUseEncKey_SM9 (pSessionHandle,mastkeyIndex,pucUserID,uiUserIDLen,&pucenPrivateKey);
						if(status!=SR_SUCCESSFULLY)
						{
							printf("SDF_GenerateUseEncKey_SM9 error!return is %08x\n",status);
							break;
						}
						else
							printf("SDF_GenerateUseEncKey_SM9 succeed!\n");
						break;
			case 5:
				status=SM9CapabilityTest(pSessionHandle);
				if(status!=SR_SUCCESSFULLY)
					{
						printf("SM9CapabilityTest error!\n");
						}
						break;
			case 6:
				status=SM9ImportKeyTest(pSessionHandle);
				if(status!=SR_SUCCESSFULLY)
					{
						printf("SM9ImportKeyTest error!\n");
						}
						break;
			case 7:
				status=SM9Agreement(pSessionHandle);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SM9 Agreement error!\n");
					}
					break;
			case 8:
				status=SM9EncapsulePack(pSessionHandle);
				if(status!=SR_SUCCESSFULLY)
				{
					printf("SM9 EncapsulePack error!\n");
					}
					break;
			default:
				SDF_CloseSession(pSessionHandle);
				SDF_CloseDevice(DeviceHandle);
						return;
			}

		}

	}

	void ADDFunTest()
{
	HANDLE DeviceHandle,pSessionHandle;
	int i=0,status=0,uiUserIDLen,ret;
	unsigned int mastkeyIndex;
	ECCrefPublicKey		enpk,tp;
	ECCrefPrivateKey  envk,tv;
	unsigned char pucUserID[1024];
	unsigned char pincode[50]={"wuxipiico"}; 
	status=SDF_OpenDevice(&DeviceHandle);
	if(status!=SR_SUCCESSFULLY)
	{
		printf("SDF_OpenDevice error!return is %08x\n",status);
		return;
	}
	status=SDF_OpenSession(DeviceHandle,&pSessionHandle);
	if(status!=SR_SUCCESSFULLY)
	{
		printf("SDF_OpenSession error!return is %08x\n",status);
		SDF_CloseDevice(DeviceHandle);
		return;
	}
	for(i=1;i<KEYPAIR_MAX_INDEX;i++)
	{
		ret=SDF_GetPrivateKeyAccessRight(pSessionHandle,i,pincode,strlen(pincode));
		if(ret!=SR_SUCCESSFULLY)
			{
				printf("SDF_GetPrivateKeyAccessRight error!return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
				return;
				}
		ret=SDF_GenerateKeyPair_ECC(pSessionHandle,SGD_SM2_3,256,&enpk,&envk);
		if(ret!=SR_SUCCESSFULLY)
		{
			printf("SDF_GenerateKeyPair_ECC %d failed and return is %08x,%08x\n",i,ret,SPII_GetErrorInfo(pSessionHandle));
			return;
		}
		ret=SPII_ImportKeyPair_ECC(pSessionHandle,SGD_SM2_1,i,&enpk,&envk);
		if(ret!=SR_SUCCESSFULLY)
			{
				printf("SPII_ImportKeyPair_ECC SGD_SM2_1 error!return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
				return;
				}
		ret=SDF_ExportSignPublicKey_ECC(pSessionHandle,i,&tp);
		if(ret!=SR_SUCCESSFULLY)
			{
				printf("SDF_ExportSignPublicKey_ECC error!return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
				return;
				}
		if(memcmp(&tp,&enpk,sizeof(ECCrefPublicKey))!=0)
			{
				printf("pk compare error!\n");
				return;
				}
		ret=SPII_ExportPrivateKey_ECC(pSessionHandle,SGD_SM2_1,i,&tv);
		if(ret!=SR_SUCCESSFULLY)
			{
				printf("SPII_ExportPrivateKey_ECC SGD_SM2_1 error!return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
				return;
				}
		if(memcmp(&tv,&envk,sizeof(ECCrefPrivateKey))!=0)
			{
				printf("vk compare error!\n");
				printeccvk("vk output",&tv);
				printeccvk("vk input",&envk);
				return;
				}
		ret=SDF_GenerateKeyPair_ECC(pSessionHandle,SGD_SM2_3,256,&enpk,&envk);
		if(ret!=SR_SUCCESSFULLY)
		{
			printf("SDF_GenerateKeyPair_ECC %d failed and return is %08x,%08x\n",i,ret,SPII_GetErrorInfo(pSessionHandle));
			return;
		}
		ret=SPII_ImportKeyPair_ECC(pSessionHandle,SGD_SM2_3,i,&enpk,&envk);
		if(ret!=SR_SUCCESSFULLY)
			{
				printf("SPII_ImportKeyPair_ECC SGD_SM2_3 error!return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
				return;
				}
		ret=SDF_ExportEncPublicKey_ECC(pSessionHandle,i,&tp);
		if(ret!=SR_SUCCESSFULLY)
			{
				printf("SDF_ExportSignPublicKey_ECC error!return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
				return;
				}
		if(memcmp(&tp,&enpk,sizeof(ECCrefPublicKey))!=0)
			{
				printf("pk compare error!\n");
				return;
				}
		ret=SPII_ExportPrivateKey_ECC(pSessionHandle,SGD_SM2_3,i,&tv);
		if(ret!=SR_SUCCESSFULLY)
			{
				printf("SPII_ExportPrivateKey_ECC SGD_SM2_3 error!return is %08x,%08x\n",ret,SPII_GetErrorInfo(pSessionHandle));
				return;
				}
		if(memcmp(&tv,&envk,sizeof(ECCrefPrivateKey))!=0)
			{
				printf("vk compare error!\n");
				return;
				}
		
 			PrintPer("Private key write and read",KEYPAIR_MAX_INDEX,i);
		}
		SDF_CloseSession(pSessionHandle);
		SDF_CloseDevice(DeviceHandle);
		return;
		}
#endif

void LinkTest()
{
  HANDLE DeviceHandle;
  unsigned char *data, *endata;
  int i, Alogmod, length, testtime, ret, enlen, sec, msec;
  struct timeval now, end;
  float sptime, rate;

  ret = SDF_OpenDevice(&DeviceHandle);
  if (ret != SR_SUCCESSFULLY)
  {
    printf("SDF_OpenDevice error!return is %08x\n", ret);
    return;
  }
  else
    printf("OpenDevice succeed!the DeviceHandle is %x\n", DeviceHandle);

  printf("Please input you test length:");
  scanf("%d", &length);
  printf("Please input you test times:");
  scanf("%d", &testtime);
  data = (unsigned char *)malloc(length);
  if (data == NULL)
  {
    printf("malloc error!\n");
    goto ErrorReturn;
  }
  for (i = 0; i < length; i++)
    data[i] = i;
  endata = (unsigned char *)malloc(length);
  if (endata == NULL)
  {
    free(data);
    printf("malloc error!\n");
    goto ErrorReturn;
  }
  gettimeofday(&now, 0);
  for (i = 0; i < testtime; i++)
  {
    ret = SPII_LoopTest(DeviceHandle, data, length, endata, &enlen);
    if (ret != SR_SUCCESSFULLY)
    {
      printf("SPII_LoopTest error! and the return is %08x\n", ret);
      free(data);
      free(endata);
      goto ErrorReturn;
    }
    if (memcmp(data, endata, enlen) != 0)
    {
      printf("Times [%d] data err!\n", i);
      printf("Shoud be:\n");
      printbuff(data, enlen);
      printf("Return be:\n");
      printbuff(endata, enlen);
      free(data);
      free(endata);
      goto ErrorReturn;
    }

    if (i % 10000 == 0)
      printf("%d Times test....\n", i);
  }
  gettimeofday(&end, 0);
  if ((end.tv_usec - now.tv_usec) < 0)
  {
    msec = end.tv_usec / 1000.0 + 1000 - now.tv_usec / 1000.0;
    sec = end.tv_sec - now.tv_sec - 1;
  }
  else
  {
    msec = end.tv_usec / 1000.0 - now.tv_usec / 1000.0;
    sec = end.tv_sec - now.tv_sec;
  }
  sptime = ((float)msec / 1000 + sec);
  printf("Spend time is %4.2f sec.\n", sptime);

  rate = testtime * length * 8 / 1024;
  rate = rate / sptime / 1024;
  printf("The rate is %4.2f Mbps!\n", rate);
  free(data);
  free(endata);

ErrorReturn:
  SDF_CloseDevice(DeviceHandle);
}

main()
{
  unsigned char Gdata[DATALEN], Grece[DATALEN];
  int Gdatalen, Grecelen, Gi;
  int Gskid = 0;
  FILE *pvk1;
  FILE *pvk2;
  for (Gi = 0; Gi < DATALEN; Gi++)
    Gdata[Gi] = 0x10 + Gi;
  while (1)
  {
    unsigned char se[2];
    printf(
        "       ====================== PIICO API Test Program================= "
        "\n");
    printf("   Copyrigth 2013 WuXi PIICO information Technology Co.,Ltd \n\n");
    printf("                 ResetDevice --------------- 1\n");
    printf("                 Device Manage ------------- 2\n");
    printf("                 key Manage ---------------- 3\n");
    printf("                 SM2 Algo ------------------ 4\n");
    printf("                 SM1&SM4&SM3 Algo ---------- 5\n");
    printf("                 File Ope ------------------ 6\n");
    printf("                 INIT Card ----------------- 7\n");
    printf("                 Capability test ----------- 8\n");
#if 0		
	  	printf("                 SM9 test ------------------ 9\n");
	  	printf("		 AddFun test --------------- 10\n");
#endif
    printf("                 link test -----------------11\n");
    printf("                 Quit  --------------------- 0\n");
    printf("Please input you select:");
    scanf("%d", &Gskid);
    switch (Gskid)
    {
    case 1:
      Otherope();
      break;
    case 2:
      DeviceManage();
      break;
    case 3:
      KeyManage();
      break;
    case 4:
      ECCTest();
      break;
    case 5:
      SymAlgoTest();
      break;
    case 7:
      INITCARD();
      break;
    case 6:
      FileTest();
      break;
    case 8:
      CapabilityTest();
      break;
#if 0				
			case 9:				
				SM9Test();
				break;
			case 10:
				ADDFunTest();
				break;
#endif
    case 11:
      LinkTest();
      break;

    case 0:
      return;
    default:
      break;
    }
  }
}
