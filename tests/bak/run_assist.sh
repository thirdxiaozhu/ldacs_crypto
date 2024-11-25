#!/bin/bash
make
rm keystore.db
./tests/rkey_gentest      # sgw
./tests/rkey_to_ccardtest # sgw
./tests/rkey_importtest   # as
./tests/kenabletest       # sgw & as
# ./tests/kestablish_sgwtest 
# ./tests/kestablish_astest
# ./tests/kestablish_gstest
# ./tests/kupdatetest 