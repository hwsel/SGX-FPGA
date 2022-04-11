#!bin/bash
#script to build the project SGX-FPGA

#build user app
cd sgx_fpga/sgx-fpga-client
./bootstrap
./configure --with-openssldir=/opt/openssl/1.1.0i
make
#build controller
cd ../sgx-fpga-controller
./bootstrap
./configure --with-openssldir=/opt/openssl/1.1.0i
#build attestation server
make
cd ../sgx-fpga-server
./bootstrap
make
#build secure monitor
cd ../../sgx_fpga_FPGA/secure_monitor
make all TARGET=hw #build in hardware mode