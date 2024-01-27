# pcie driver and test by wencheng
#!/bin/bash
#ENABLE_DEBUG=1

lspci -d 1dab:
cd /root/pcie-drv/tool
./confdrv.sh
