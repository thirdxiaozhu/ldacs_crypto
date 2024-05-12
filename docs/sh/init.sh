
#!/bin/bash
#ENABLE_DEBUG=1

echo "请以root身份登录哦"
myPWD=$(pwd)
cd /root/pcie-drv/tool
./confdrv.sh
cd "$myPWD" || exit


# lspci -d 1dab:
# sudo su
# cd /root/pcie-drv/tool
# ./confdrv.sh
# cd /home/wencheng/crypto/key_management
# ./gdacmmktool ekm egenkek keyindex [num] // 生成kek
# ./gdacmmktool km gkk // generatekeywithkek

#  cp libkm_src.so ../../lib/
 