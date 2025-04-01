#!/bin/bash
sudo rm keystore.db 
./tests/rkey_gentest
./tests/kenabletest 
./tests/query_keytest 
./tests/sm3_hmac_test
# ./tests/rkey_to_ccardtest  
# ./tests/rkey_importtest 
# ./tests/kenabletest
# ./tests/query_keytest 
