#!/bin/bash
make
rm keystore.db
./tests/rkey_gentest 
./tests/rkey_to_ccardtest
./tests/rkey_importtest
./tests/kenabletest 
./tests/kestablish_sgwtest 
./tests/kestablish_astest
./tests/kestablish_gstest
clear
# ./tests/kupdatetest 