#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdbool.h>
#include <termios.h>
#include "piico_define.h"
#include "piico_error.h"
#include "api.h"
#define L_LEVER 1
#define DEBUG_LEVER 0
#define D_LIN()\
        if(L_LEVER<DEBUG_LEVER)\
        {\
                 printf("\n[INFO][%s][%s][%s][Line %d]\n",__TIME__,__FILE__,__FUNCTION__,__LINE__);\
        }      

#define DEFAULT_PIN       "wuxipiico"

unsigned char pincode[100]={DEFAULT_PIN};

int CreateDir(const char *sPathName)  
{  
  char DirName[256];  
  strcpy(DirName, sPathName);  
  int i,len = strlen(DirName);
  for(i=1; i<len; i++)  
  {  
      if(DirName[i]=='/')  
      {  
          DirName[i] = 0; 
          if(access(DirName, W_OK)!=0)  
          {  
              if(mkdir(DirName, 0755)==-1)  
              {   
                  printf("mkdir   error\n");   
                  return -1;   
              }  
          }  
          DirName[i] = '/';  

      }  
  }  

  return 0;  
} 
int mygetch()
{
    struct termios oldt, newt;
    int ch;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
}
 
int getpasswd(char *passwd, int size)
{
    int c, n = 0;
    do
    {
        c = mygetch();
        if (c != '\n' && c != '\r' && c != 127)
        {
            passwd[n] = c;
            printf("*");
            n++;
        }
        else if ((c != '\n' | c != '\r') && c == 127)//判断是否是回车或则退格
        {
            if (n > 0)
            {
                n--;
                printf("\b \b");//输出退格
            }
        }
    }while (c != '\n' && c != '\r' && n < (size - 1));
    passwd[n] = '\0';//消除一个多余的回车
    return n;
}
int readfile(char *file,unsigned char *buf,int *len)
{
	int i;
	int filelen;
	FILE *fp=fopen(file,"rb");
	if(fp==NULL)
	{
	        printf("fopen error!\n");
	        return -1;
	}
	//printf("fp:%x\n",fp);
	fseek(fp,0,SEEK_END);
	filelen=ftell(fp);
	*len=filelen;
	fseek(fp,0,SEEK_SET);
	fread(buf,filelen,1,fp);
	fclose(fp);
	return 0;
}
int wrtiefile(char *file,unsigned char *buf,int len)
{

    FILE *fp=fopen(file,"wb");
    if(!fp) return -1;
    fwrite(buf,len,1,fp);
    fclose(fp);
    return 0;
}
void PrintPer(char *info,int totl,int step)
{
    float p;
    int tmp,hz;
    //hz=500;
	//if(step%hz!=0)
    //{
        p=(float)step/totl*100;
        if(step==0)
            printf("%s totle is %d, %.2f %%finished!....--\n",info,totl,p);
        else
        {
            printf("\033[1A");
            printf("\033[K");
            tmp=(step)%4;
            switch(tmp)
            {
                case 0:
        		printf("%s totle is %d, %.2f %%finished!....|\n",info,totl,p);
                        break;
                case 1:
        		printf("%s totle is %d, %.2f %%finished!..../\n",info,totl,p);
                        break;
                case 2:
        		printf("%s totle is %d, %.2f %%finished!....--\n",info,totl,p);
                        break;
                case 3:
        		printf("%s totle is %d, %.2f %%finished!....\\ \n",info,totl,p);
                        break;
            }
        }
    //}

}

void generateKEK(HANDLE phSessionHandle,unsigned int startindex,unsigned int endindex)
{
	int ret,i;
	for(i=startindex;i<=endindex;i++)
	{
	 	ret= SPII_GenerateKEK(phSessionHandle,i,16);
	    if(ret!=SR_SUCCESSFULLY)
		{
	         printf("SPII_GenerateKEK %d error! return is %08x ,%08x\n",i,ret, SPII_GetErrorInfo(phSessionHandle));
	         break;
		}
	    PrintPer("KEK  Generate all",endindex-startindex+1,i-startindex+1);
	}
	return;
}
void generatekeypair(HANDLE phSessionHandle,unsigned int startindex,unsigned int endindex)
{
	int ret,len,indexNum,keybits,relen;

    unsigned char key[16]={0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
    unsigned char keypairfile[1000],enkey[1000];
    unsigned char ensk[1000],padkey[256];
    ECCrefPrivateKey envk;
    ECCrefPublicKey enpk,signpk;
    ECCCipher *enR;

	for(indexNum=startindex;indexNum<=endindex;indexNum++)
	{
        ret=SDF_GetPrivateKeyAccessRight(phSessionHandle,indexNum,pincode,strlen(pincode));
        if(ret!=SR_SUCCESSFULLY)
        {
           printf("SDF_GetPrivateKeyAccessRight error! return is %08x,%08x\n",ret, SPII_GetErrorInfo(phSessionHandle));
           break;
		}
		ret=SPII_GenerateSignKeyPair_ECC(phSessionHandle,indexNum);
		if(ret!=SR_SUCCESSFULLY)
		{
		   printf("Generate %d Sign ECC KeyPair failed and return is %08x,%08x\n",indexNum,ret,SPII_GetErrorInfo(phSessionHandle));
		   SDF_ReleasePrivateKeyAccessRight(phSessionHandle,indexNum);
		   break;
		}
		D_LIN();
		ret=SDF_ExportSignPublicKey_ECC(phSessionHandle,indexNum,&signpk);
		if(ret!=SR_SUCCESSFULLY)
		{
		   printf("SDF_ExportSignPublicKey_ECC %d failed and return is %08x,%08x\n",indexNum,ret,SPII_GetErrorInfo(phSessionHandle));
		   SDF_ReleasePrivateKeyAccessRight(phSessionHandle,indexNum);
		   break;
		}
		D_LIN();
		ret=SDF_GenerateKeyPair_ECC(phSessionHandle,SGD_SM2_3,256,&enpk,&envk);
		if(ret!=SR_SUCCESSFULLY)
		{
			printf("SDF_GenerateKeyPair_ECC %d failed and return is %08x,%08x\n",indexNum,ret,SPII_GetErrorInfo(phSessionHandle));
			SDF_ReleasePrivateKeyAccessRight(phSessionHandle,indexNum);
			break;
		}
		D_LIN();
		ret=SDF_GenerateRandom(phSessionHandle,16,keypairfile);
		if(ret!=SR_SUCCESSFULLY)
		{
			printf("SDF_GenerateRandom %d failed and return is %08x,%08x\n",indexNum,ret,SPII_GetErrorInfo(phSessionHandle));
			SDF_ReleasePrivateKeyAccessRight(phSessionHandle,indexNum);
			break;
		}
		D_LIN();
		enR=malloc(sizeof(ECCCipher)+16);
		ret=SDF_ExternalEncrypt_ECC(phSessionHandle,SGD_SM2_3,&signpk,keypairfile,16,enR);
		if(ret!=SR_SUCCESSFULLY)
		{
			printf("SDF_ExternalEncrypt_ECC %d failed and return is %08x,%08x\n",indexNum,ret,SPII_GetErrorInfo(phSessionHandle));
			SDF_ReleasePrivateKeyAccessRight(phSessionHandle,indexNum);
			free(enR);
			break;
		}
		D_LIN();
		ret=SPII_EncryptEx(phSessionHandle,envk.K,64,keypairfile,16,NULL,0,SGD_SM4_ECB,enkey,&len);
		if(ret!=SR_SUCCESSFULLY)
		{
		    printf("SDF_ExternalEncrypt_ECC %d failed and return is %08x,%08x\n",indexNum,ret,SPII_GetErrorInfo(phSessionHandle));
		    SDF_ReleasePrivateKeyAccessRight(phSessionHandle,indexNum);
		    free(enR);
		    break;
		}
		D_LIN();
		ret=SPII_NVELOPEDKEY(phSessionHandle,indexNum,SGD_SM2_3,SGD_SM4_ECB,enR,&enpk,enkey,len);
		if(ret!=SR_SUCCESSFULLY)
		{
		    printf("SPII_NVELOPEDKEY %d failed and return is %08x,%08x\n",indexNum,ret,SPII_GetErrorInfo(phSessionHandle));
		    SDF_ReleasePrivateKeyAccessRight(phSessionHandle,indexNum);
		    free(enR);
		    break;

		}
		D_LIN();
		free(enR);
		ret=SDF_ReleasePrivateKeyAccessRight(phSessionHandle,indexNum);
		if(ret!=SR_SUCCESSFULLY)
		{
		    printf("SDF_ReleasePrivateKeyAccessRight error! return is %08x ,%08x\n",ret, SPII_GetErrorInfo(phSessionHandle));
		    break;
		}
		PrintPer("SM2 Key Pair Generate all",endindex-startindex+1,indexNum-startindex+1);
			
		D_LIN();
	}
	D_LIN();
}

void print_usage()
{
        printf("NRtool :Example\n");
		printf("-s		the State of Encrypt Card\n");
		printf("-rs		Regist super Administrator\n");
		printf("-ra		Regist Administrator\n");
		printf("-ro		Regist Operator\n");
		printf("-li		Login in\n");
		printf("-l		Init Administrator login in\n");
		printf("-ic [-p] [pin]	init the keyContain Device, with -p parameter user PrivateKeyAccessRight(pin) can be used\n");
		printf("-gd [-p] [pin]	Generate the Device Key Pair, with -p parameter user PrivateKeyAccessRight(pin) can be used\n");
		printf("-gu [-p] [pin]	Generate the User Key Pair, with -p parameter user PrivateKeyAccessRight(pin) can be used\n");
		printf("-gk		Generate the KEK\n");
		printf("-bu		Back up Key,the next parameter is the storage directory!\n");
		printf("-rd		Restore the device key,the next parameter is the storage directory!\n");
		printf("-ru		Restore the user keypair and kek ,the next parameter is storage directory!\n");
		printf("-ri		Reset Device\n");
		printf("-mp		modify the Private Key Access Right,the next parameter is the index of keyPair\n");
		printf("-mk		modify the user pin\n");

}

void main(int argc,char *argv[])
{
	int ret,i;
	HANDLE phDeviceHandle,phSessionHandle;
	unsigned int deviceID,AuthStates,arglen,filelen,ChallengerLength;
	unsigned char Challenger[16];
	unsigned char pin[130]={0};
	unsigned char opin[130]={0};
	unsigned char keypairfile[1000],enkey[1000],skeyid[50];
	unsigned int startindex, endindex,opinlen,pinlen,backupkeyfilelength,len;
	unsigned short ds,ps;
	ECCrefPublicKey  enpk,signpk,entpk;
	ECCrefPrivateKey        envk;
	ECCCipher *enmk;

	if(argc<2)
	{
	    printf("please use with '-h' to get help:\n");
	    return;
	}
	ret=SDF_OpenDevice(&phDeviceHandle);
	if(ret!=0)
	{
		printf("OpenDevice Error!return is %08x\n",ret);
		return ;
	}
	ret=SDF_OpenSession(phDeviceHandle, &phSessionHandle);
	if(ret!=0)
	{
		printf("OpenDevice Error!return is %08x\n",ret);
		SDF_CloseDevice(phDeviceHandle);
		return;
	}
	if(strcmp(argv[1],"-s")==0)
	{
		ret=SPII_GetDeviceStatus(phDeviceHandle,&ds,&ps);
		if(ret!=SR_SUCCESSFULLY)
		{
			printf("GetDeviceStatus failed and return is %08x\n",ret);
			goto errorreturn;
		}
		switch(ds)
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
		switch(ps)
		{
			case 0:
			        printf("Nobody load in!\n");
			        break;
			case 1:
			        printf("Super Administrator load in!\n");
			        break;
			case 2:
			        printf("Administrator load in!\n");
			        break;
			case 3:
			        printf("Assistant load in!\n");
			        break;
			case 4:
			        printf("Assistant load in!\n");
			        break;
			case 5:
					printf("Init Administrator load in!\n");
					break;
			default:
			        printf("error Permission!\n");
			        break;
		}

		goto errorreturn;
		

	}
	if(strcmp(argv[1],"-l")==0)
	{
		ret=SPII_GetChallenger(phSessionHandle,Challenger,&ChallengerLength);
		if(ret!=SR_SUCCESSFULLY)
		{
			printf("SPII_GetChallenger failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
			goto errorreturn;
		}
		printf("Please input the PIN of Init administrator(<20 bytes):");
		pinlen=getpasswd(pin, 20);
		printf("\n");
		ret=SPII_Authentiation(phSessionHandle,Challenger,ChallengerLength,pin,strlen(pin));
		if(ret!=SR_SUCCESSFULLY)
			printf("SPII_Authentiation failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
		else
			printf("SPII login Init  administrator Succeed!\n");
		goto errorreturn;
	}
	if(strcmp(argv[1],"-rs")==0)
	{

		printf("Please input the PIN of Super Administrator (<20 bytes):");
		pinlen=getpasswd(pin, 20);
		printf("\n");
		ret=SPII_Regsvr(phSessionHandle,2,pin,strlen(pin),NULL,NULL,1);
		if(ret!=SR_SUCCESSFULLY)
			printf("SPII_Regsvr super administrator failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
		else
			printf("SPII_Regsvr super administrator Succeed!\n");
		goto errorreturn;
	}
	if(strcmp(argv[1],"-ra")==0)
    {

		printf("Please input the PIN of Administrator(<20 bytes):");
		pinlen=getpasswd(pin, 20);
		printf("\n");
		ret=SPII_Regsvr(phSessionHandle,2,pin,strlen(pin),NULL,NULL,2);
		if(ret!=SR_SUCCESSFULLY)
			printf("SPII_Regsvr administrator failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
		else
			printf("SPII_Regsvr administrator Succeed!\n");
		goto errorreturn;
    }
	if(strcmp(argv[1],"-ro")==0)
	{

		printf("Please input the PIN of Operator(<20 bytes):");
		pinlen=getpasswd(pin, 20);
		printf("\n");
		ret=SPII_Regsvr(phSessionHandle,2,pin,strlen(pin),NULL,NULL,3);
		if(ret!=SR_SUCCESSFULLY)
	 		printf("SPII_Regsvr Operator failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
		else
	 		printf("SPII_Regsvr Operator Succeed!\n");
		goto errorreturn;
	}
	if(strcmp(argv[1],"-li")==0)
	{
		printf("\nPlease input the login PIN (<20 bytes):");
		pinlen=getpasswd(pin, 20);
		printf("\n");
		printf("Please select the login ID:\n1:supper Administartor\n2:Administartor \n3:Operator\n");
		printf("Please input your select:");
		scanf("%d",&deviceID);
		ret=SPII_LoadinWithPassword(phSessionHandle,pin,pinlen,deviceID);
		if(ret!=SR_SUCCESSFULLY)
			printf("SPII_LoadinWithPassword failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
		else
			printf("Load in Card Succeed!\n");
		goto errorreturn;

	}
    
	if(strcmp(argv[1],"-ic")==0)
	{
    	
    	if(argc==3) {
    		if(strcmp(argv[2],"-p")==0){
    			strcpy(pincode,"3.1415926");
    			printf("Usr PIN \"%s\" used\n",pincode);
    		}else{
        		print_usage();
        		goto errorreturn;
    		}
    	}
    	
    	if(argc==4) {
    		if(strcmp(argv[2],"-p")==0){
    			strcpy(pincode,argv[3]);
    			if(strlen(pincode)<8)
    			{
    				printf("Usr PIN too short,need >= 8\n");
    				goto errorreturn;
    			}
    			printf("Usr PIN \"%s\" used\n",pincode);
    		}
    		else{
        		print_usage();
        		goto errorreturn;
    		}
    	}

    	
		ret=SPII_Init_FileSystem(phSessionHandle);
		if(ret!=SR_SUCCESSFULLY)
		{
			printf("SPII_Init_FileSystem error! return is %08x ,%08x\n",ret, SPII_GetErrorInfo(phSessionHandle));
			goto errorreturn;

		}
		printf("\n");
		for(i=0;i<=KEYPAIR_MAX_INDEX;i++)
		{
            ret=SPII_Init_KeyContainerWithPrivateKeyAccessRight(phDeviceHandle,i,pincode,strlen(pincode));
			if(ret!=SR_SUCCESSFULLY)
			{
				printf("SPII_Init_KeyContainer %d error! return is %08x \n",i,ret);
				goto errorreturn;
			}
			PrintPer("Init KeyContainer",KEYPAIR_MAX_INDEX+1,i+1);
		}
		ret=SPII_FSTOIS(phDeviceHandle);
		if(ret!=0)
			printf("SPII_FSTOIS failed,and return is %08x \n",ret);
		goto errorreturn;
	}
	if(strcmp(argv[1],"-gd")==0)
	{
    	if(argc==3) {
    		if(strcmp(argv[2],"-p")==0){
    			strcpy(pincode,"3.1415926");
    			printf("Usr PIN \"%s\" used\n",pincode);
    		}else{
        		print_usage();
        		goto errorreturn;
    		}
    	}
    	
    	if(argc==4) {
    		if(strcmp(argv[2],"-p")==0){
    			strcpy(pincode,argv[3]);
    			if(strlen(pincode)<8)
    			{
    				printf("Usr PIN too short,need >= 8\n");
    				goto errorreturn;
    			}
    			printf("Usr PIN \"%s\" used\n",pincode);
    		}
    		else{
        		print_usage();
        		goto errorreturn;
    		}
    	}

		generatekeypair(phSessionHandle,0,0);
		ret=SPII_ISTORS(phDeviceHandle);
		if(ret!=0)
			printf("SPII_ISTORS failed,and return is %08x \n",ret);
		goto errorreturn;
	}
	if(strcmp(argv[1],"-gu")==0)
	{
    	if(argc==3) {
    		if(strcmp(argv[2],"-p")==0){
    			strcpy(pincode,"3.1415926");
    			printf("Usr PIN \"%s\" used\n",pincode);
    		}else{
        		print_usage();
        		goto errorreturn;
    		}
    	}
    	
    	if(argc==4) {
    		if(strcmp(argv[2],"-p")==0){
    			strcpy(pincode,argv[3]);
    			if(strlen(pincode)<8)
    			{
    				printf("Usr PIN too short,need >= 8\n");
    				goto errorreturn;
    			}
    			printf("Usr PIN \"%s\" used\n",pincode);
    		}
    		else{
        		print_usage();
        		goto errorreturn;
    		}
    	}
    	
		printf("\n");
		generatekeypair(phSessionHandle,1,KEYPAIR_MAX_INDEX);
		goto errorreturn;
	}
	if(strcmp(argv[1],"-gk")==0)
	{
		printf("\n");
		generateKEK(phSessionHandle,0,KEK_MAX_INDEX);
	 	goto errorreturn;
	}
	if(strcmp(argv[1],"-bu")==0)
	{
		if(argc<2)
		{
			printf("please use with '-h' to get help:\n");
			goto errorreturn;
		}
		if(argv[2]==NULL)
		{
			printf("The object folder cann't be NULL\nplease use with '-h' to get help:\n");
			goto errorreturn;
		}
		CreateDir(argv[2]);
		enmk=malloc(sizeof(ECCCipher)+48);
		for(i=1;i<4;i++)
		{
			ret=SDF_GenerateKeyPair_ECC(phSessionHandle,SGD_SM2_1,256,&enpk,&envk);
			if(ret!=SR_SUCCESSFULLY)
			{
				printf("Card Generate enc Key failed and return is %08x\n",ret);
				free(enmk);
				goto errorreturn;
			}
			ret=SPII_BackUpBK(phSessionHandle,1,NULL,0,i,&enpk,enmk);
			if(ret!=SR_SUCCESSFULLY)
			{
				printf("SPII_BackUpBK  %d failed and return is %08x %08x\n",i,ret,SPII_GetErrorInfo(phSessionHandle));
				free(enmk);
				goto errorreturn;
			}
			printf("UserID is %d\n",i);
			sprintf(skeyid,"%sSPII_BackUpBK%d.bin",argv[2],i);
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
				printf("write %d SPII_BackUpBK to file error!\n",i);
				free(enmk);
				goto errorreturn;
			 }
			 printf("SPII_BackUpBK  %d succeed!\n",i);
		}
		free(enmk);
		printf("\n");
		for(i=0;i<=KEYPAIR_MAX_INDEX;i++)
		{

			ret=SPII_BackUpECCEnc(phSessionHandle,i,keypairfile,&filelen);
			if(ret!=0)
			{
				printf("backup %d EnEccKeyPair error,and return is %08x\n\n\n",i,ret);
				goto errorreturn;
			}
			sprintf(skeyid,"%sEEkeypair%d.bin",argv[2],i);
			ret=wrtiefile(skeyid,keypairfile,filelen);
			if(ret!=0)
			{
				printf("write %d ECC Enc KeyPair to file error!\n",i);
				goto errorreturn;
			}
			ret=SPII_BackUpECCSign(phSessionHandle,i,keypairfile,&filelen);
			if(ret!=0)
			{
				printf("backup %d SignEccKeyPair error,and return is %08x\n\n\n",i,ret);
				goto errorreturn;
			}
			sprintf(skeyid,"%sESkeypair%d.bin",argv[2],i);
			ret=wrtiefile(skeyid,keypairfile,filelen);
			if(ret!=0)
            {
                printf("write %d ECC Sign KeyPair to file error!\n",i);
				goto errorreturn;                                                        
			}
			PrintPer("backup SM2 key all",KEYPAIR_MAX_INDEX+1,i+1);

		}

        printf("Backup ECC Key succeed!\n");
		for(i=0;i<=KEK_MAX_INDEX;i++)
		{
		ret=SPII_BackUpKEK(phSessionHandle,i,keypairfile,&filelen);
		if(ret!=0)
		{
		printf("backup %d KEK error,and return is %08x\n\n\n",i,ret);
		goto errorreturn;                                                
		}
		sprintf(skeyid,"%sKEK%d.bin",argv[2],i);
		ret=wrtiefile(skeyid,keypairfile,filelen);
		if(ret!=0)
		{
		printf("write %d KEK to file error!\n",i);
		goto errorreturn;
		}
		PrintPer("backup KEK key all",KEK_MAX_INDEX+1,i+1);
		}
        printf("Backup KEK Key succeed!\n");
        goto errorreturn;                        
		
	}
	if(strcmp(argv[1],"-rd")==0)
	{

		if(argc<2)
		{
			printf("please use with '-h' to get help:\n");
			goto errorreturn;
		}
		if(argv[2]==NULL)
		{
			printf("The object folder cann't be NULL\nplease use with '-h' to get help:\n");
			goto errorreturn;
		}
		ret=SPII_GenerateTmpPK(phSessionHandle,&entpk);
		if(ret!=SR_SUCCESSFULLY)
		{
			printf("SPII_GenerateTmpPK failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
			goto errorreturn;	
		}	
        enmk=malloc(sizeof(ECCCipher)+48);
		for(i=1;i<3;i++)
		{
			sprintf(skeyid,"%sSPII_BackUpBK%d.bin",argv[2],i);
			ret=readfile(skeyid,keypairfile,&filelen);
			if(ret!=0)
			{
				printf("write %d Read PK VK from file error!\n",i);
				free(enmk);
				goto errorreturn;	
			}
			memcpy(&enpk,keypairfile,sizeof(ECCrefPublicKey));
			memcpy(&envk,keypairfile+sizeof(ECCrefPublicKey),sizeof(ECCrefPrivateKey));
			memcpy(enmk,keypairfile+sizeof(ECCrefPublicKey)+sizeof(ECCrefPrivateKey),sizeof(ECCCipher)+48);
			ret=SDF_ExternalDecrypt_ECC(phSessionHandle,SGD_SM2_3,&envk,enmk,enkey,&len);
			if(ret!=SR_SUCCESSFULLY)
			{
				printf("SDF_ExternalDecrypt_ECC enmk failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
				free(enmk);
				goto errorreturn;	
			}
			if(len!=48)
			{
				printf("SDF_ExternalDecrypt_ECC enmk data length error,return length is %d\n",len);
				free(enmk);
				goto errorreturn;	
			}
			else
				printf("SDF_ExternalDecrypt_ECC enmk Succeed!\n");
			ret=SDF_ExternalEncrypt_ECC(phSessionHandle,SGD_SM2_3,&entpk,enkey,len,enmk);
			if(ret!=SR_SUCCESSFULLY)
			{
				printf("SDF_ExternalEncrypt_ECC mk failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
				free(enmk);
				goto errorreturn;	
			}
			else
				printf("SDF_ExternalEncrypt_ECC mk Succeed!\n");
			ret=SPII_RestoreBK(phSessionHandle,1,NULL,0,enmk);
			if(ret!=SR_SUCCESSFULLY)
			{
				printf("SPII_RestoreBK mk failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
				free(enmk);
				goto errorreturn;	
			}
			else
				printf("SPII_RestoreBK %d succeed!\n",i);
		}
		free(enmk);
		printf("the Restore starting.....\n");
		i=0;
		sprintf(skeyid,"%sEEkeypair%d.bin",argv[2],i);
		ret=readfile(skeyid,keypairfile,&filelen);
		if(ret!=0)
		{
			printf("read %d ECC Enc KeyPair to file error!\n",i);
			goto errorreturn;	
		}
		ret=SPII_RestoreECCEnc(phSessionHandle,i,keypairfile,filelen);
		if(ret!=0)
		{
			printf("Restore %d EnEccKeyPair error,and return is %08x\n",i,ret);
			goto errorreturn;	
		}
					
		sprintf(skeyid,"%sESkeypair%d.bin",argv[2],i);
		ret=readfile(skeyid,keypairfile,&filelen);
		if(ret!=0)
		{
			printf("read %d ECC Sign KeyPair to file error!\n",i);
			goto errorreturn;	
		}	
		ret=SPII_RestoreECCSign(phSessionHandle,i,keypairfile,filelen);
		if(ret!=0)
		{
			printf("Restore %d SignEccKeyPair error,and return is %08x\n",i,ret);
			goto errorreturn;	
		}
		printf("Restore Device Key succeed!\n");
		ret=SPII_ISTORS(phDeviceHandle);
		if(ret!=0) printf("SPII_ISTORS failed,and return is %08x \n",ret);
			goto errorreturn;	
					
	}
	if(strcmp(argv[1],"-ru")==0)
	{
		if(argc<2)
		{
			printf("please use with '-h' to get help:\n");
			goto errorreturn;
		}
		if(argv[2]==NULL)
		{
			printf("The object folder cann't be NULL\nplease use with '-h' to get help:\n");
			goto errorreturn;
		}
		ret=SPII_GenerateTmpPK(phSessionHandle,&entpk);
		if(ret!=SR_SUCCESSFULLY)
		{       
			printf("SPII_GenerateTmpPK failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
			goto errorreturn;
		}
    	enmk=malloc(sizeof(ECCCipher)+48);
		for(i=1;i<3;i++)
		{
			sprintf(skeyid,"%sSPII_BackUpBK%d.bin",argv[2],i);
			ret=readfile(skeyid,keypairfile,&filelen);
			if(ret!=0)
			{
				printf("write %d Read PK VK from file error!\n",i);
				free(enmk);
				goto errorreturn;
			}
       		memcpy(&enpk,keypairfile,sizeof(ECCrefPublicKey));
       		memcpy(&envk,keypairfile+sizeof(ECCrefPublicKey),sizeof(ECCrefPrivateKey));
       		memcpy(enmk,keypairfile+sizeof(ECCrefPublicKey)+sizeof(ECCrefPrivateKey),sizeof(ECCCipher)+48);
       		ret=SDF_ExternalDecrypt_ECC(phSessionHandle,SGD_SM2_3,&envk,enmk,enkey,&len);
			if(ret!=SR_SUCCESSFULLY)
			{
				printf("SDF_ExternalDecrypt_ECC enmk failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
				free(enmk);
				goto errorreturn;
			}
			if(len!=48)
			{
				printf("SDF_ExternalDecrypt_ECC enmk data length error,return length is %d\n",len);
				free(enmk);
				goto errorreturn;
			}
        	else
				printf("SDF_ExternalDecrypt_ECC enmk Succeed!\n");
			ret=SDF_ExternalEncrypt_ECC(phSessionHandle,SGD_SM2_3,&entpk,enkey,len,enmk);
			if(ret!=SR_SUCCESSFULLY)
			{
				printf("SDF_ExternalEncrypt_ECC mk failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
				free(enmk);
				goto errorreturn;
			}
        	else
           		printf("SDF_ExternalEncrypt_ECC mk Succeed!\n");
	    	ret=SPII_RestoreBK(phSessionHandle,1,NULL,0,enmk);
			if(ret!=SR_SUCCESSFULLY)
			{
				printf("SPII_RestoreBK mk failed and return is %08x,%08x\n",ret,SPII_GetErrorInfo(phSessionHandle));
				free(enmk);
				goto errorreturn;
			}
			else
				printf("SPII_RestoreBK %d succeed!\n",i);
		}
		free(enmk);
			
		printf("the Restore starting.....\n");
		printf("\n");
		for(i=1;i<=KEYPAIR_MAX_INDEX;i++)
		{
			sprintf(skeyid,"%sEEkeypair%d.bin",argv[2],i);
			ret=readfile(skeyid,keypairfile,&filelen);
			if(ret!=0)
			{
				printf("read %d ECC Enc KeyPair to file error!\n",i);
				goto errorreturn;
			}
			ret=SPII_RestoreECCEnc(phSessionHandle,i,keypairfile,filelen);
			if(ret!=0)
			{
				printf("Restore %d EnEccKeyPair error,and return is %08x\n",i,ret);
				goto errorreturn;	
			}
			sprintf(skeyid,"%sESkeypair%d.bin",argv[2],i);
			ret=readfile(skeyid,keypairfile,&filelen);
			if(ret!=0)
			{
				printf("read %d ECC Sign KeyPair to file error!\n",i);
				goto errorreturn;
			}	
			ret=SPII_RestoreECCSign(phSessionHandle,i,keypairfile,filelen);
			if(ret!=0)
			{
				printf("Restore %d SignEccKeyPair error,and return is %08x\n",i,ret);
				goto errorreturn;
			}

		
            PrintPer("Restore user SM2 key all",KEYPAIR_MAX_INDEX,i);
		}
		printf("Restore All user SM2 key succeed!\n");
		for(i=0;i<=KEK_MAX_INDEX;i++)
		{
			sprintf(skeyid,"%sKEK%d.bin",argv[2],i);
			ret=readfile(skeyid,keypairfile,&filelen);
			if(ret!=0)
			{
				printf("read %d KEK to file error!\n",i);
				goto errorreturn;
			}		
			ret=SPII_RestoreKEK(phSessionHandle,i,keypairfile,filelen);
			if(ret!=0)
			{
				printf("Restore %d KEK error,and return is %08x\n",i,ret);
				goto errorreturn;
			}
			PrintPer("Restore user KEK key all",KEK_MAX_INDEX+1,i+1);
		}
		printf("Restore All user KEK key succeed!\n");
		goto errorreturn;
	}
	if(strcmp(argv[1],"-ri")==0)
	{
		printf("This operation will take a few times,please wait for 30 seconds!\n");
		ret=SPII_Init_Device(phDeviceHandle);
		if(ret!=SR_SUCCESSFULLY)
			printf("Init Card failed and return is %08x\n",ret);
		goto errorreturn;

	}			
	if(strcmp(argv[1],"-mp")==0)
	{
		if(argc<2)
		{
			printf("please use with '-h' to get help:\n");
			goto errorreturn;
		}
		arglen=strlen(argv[2]);
		deviceID=0;
		if(arglen>5)
		{
			printf(".the Key Index out of the range(0~9999).");
			goto errorreturn;	
		}
		for(i=0;i<strlen(argv[2]);i++)
		{
			if(argv[2][i]<0x30||argv[2][i]>0x39)
			{
				printf("..the Key Index out of the range(0~9999).");
				goto errorreturn;	
			}
			deviceID=deviceID*10+argv[2][i]-0x30;

		}
		if(deviceID<0||deviceID>KEYPAIR_MAX_INDEX)
		{
			printf("...the Key Index out of the range(0~9999).");
			goto errorreturn;	
		}
		printf("Please input the Old PIN of Private Key Access Right:");
		opinlen=getpasswd(opin, 130);
		printf("\n");
		printf("Please input the New PIN of Private Key Access Right:");
		pinlen=getpasswd(pin, 130);
		printf("\n");
		ret=SPII_ChangePrivateKeyAccessRight(phSessionHandle,deviceID,opin,opinlen,pin,pinlen);
		if(ret!=SR_SUCCESSFULLY)
			printf("SPII_ChangePrivateKeyAccessRight error! return is %08x ,%08x\n",ret, SPII_GetErrorInfo(phSessionHandle));
		goto errorreturn;	
		
	}
    
    if(strcmp(argv[1],"-mk")==0){
            
		printf("Please input the Old PIN:");
		opinlen=getpasswd(opin, 130);
		printf("\n");
		printf("Please input the New PIN:");
		pinlen=getpasswd(pin, 130);
		printf("\n");
		ret=SPII_ModifyPin(phSessionHandle,opin,opinlen,pin,pinlen);
		if(ret!=SR_SUCCESSFULLY)
			printf("SPII_ModifyPin error! return is %08x ,%08x\n",ret, SPII_GetErrorInfo(phSessionHandle));
        goto errorreturn;    

    } else {
	print_usage();
        goto errorreturn ;
    }
	

	
errorreturn:
	SDF_CloseSession(phSessionHandle);
	SDF_CloseDevice(phDeviceHandle);
	return ;
}
