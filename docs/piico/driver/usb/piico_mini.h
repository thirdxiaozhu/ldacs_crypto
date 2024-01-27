
#ifndef PIICO_MINI_H
#define PIICO_MINI_H
#include <linux/kernel.h>
#include <linux/string.h>
#define MINI_IOCX_RW      0x802	//_IOWR(SKEL_IOC_MAGIC, 1, int)


/* our private defines. if this grows any larger, use your own .h file */
#define MAX_TRANSFER		(4096-256)
#define BUFFER_SZ		(4096)
#define WRITES_IN_FLIGHT	1

/*
#define SR_SUCCESSFULLY					0				//函数返回成功
#define SR_HOST_MEMORY					-6				//分配内存错误
#define SR_POINT_ERRO					-7				//无效的指针
#define SR_PARAM_LENTH_ERRO				-21				//参数长度错误(不符合要求的格式)

//#define  LITTLE_ENDIAN
#ifdef LITTLE_ENDIAN
#define USHORT_TO_STR(pto,from)                               \
	do{                                                     \
		*((unsigned char *)(pto)    ) = (unsigned char )(((from) & 0x00ff)     );\
		*((unsigned char *)(pto) + 1) = (unsigned char )(((from) & 0xff00) >> 8 );\
	}while(0)
#define STR_TO_USHORT(pfrom)                            \
	((unsigned short )*(unsigned char *)(pfrom) + (((unsigned short )*((unsigned char *)(pfrom) + 1)) << 8))
#else
#define USHORT_TO_STR(pto,from)                               \
	do{                                                     \
	*((unsigned char *)(pto)    ) = (unsigned char )(((from) & 0xff00) >> 8 );\
	*((unsigned char *)(pto) + 1) = (unsigned char )(((from) & 0x00ff)     );\
	}while(0)
#define STR_TO_USHORT(pfrom)                            \
	((*((unsigned char *)(pfrom)    ) << 8) + *((unsigned char *)(pfrom) + 1))
#endif
*/


/* Structure to user paramter of ioctl proccess */
struct usr_parm {
    uint8_t *idata;
    uint8_t *odata;
    uint32_t ilen;
    uint32_t olen;
    uint32_t rlen;    
};

#endif


