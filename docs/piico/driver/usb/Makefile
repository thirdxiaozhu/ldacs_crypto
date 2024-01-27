obj-m       := piico_ccmu.o
piico_ccmu-objs := piico_mini.o	

KERNELDIR = /lib/modules/$(shell uname -r)/build
PWD = $(shell pwd)

default:
	$(MAKE) -C   $(KERNELDIR) M=$(PWD) modules

install:
	insmod piico_ccmu.ko

uninstall:
	rmmod piico_ccmu.ko

clean:
	rm -rf *.o *~ core *.order *.symvers .depend .*.cmd *.ko *.mod.c *.mod .tmp_versions 

