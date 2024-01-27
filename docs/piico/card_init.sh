#!/bin/bash
    lsusb
    # make
    insmod driver/usb/piico_ccmu.ko
    piico_manager -l 2
    # echo "dmesg======================================================================"
    # echo $(dmesg)
    # echo "make install =============================================================="
    # echo $(make install)
    # ls /lib/libpiico_ccmu.so 
    # echo "change directory to examples================================================"
    # cd ./examples
    # echo "current directory:"
    # echo $(pwd)
    # echo "login as administrator,login pin : wuxipiico ==============================="
    # ./piicoToolWP -s
    # ./piicoToolWP -li
