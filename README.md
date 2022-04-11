# SGX-FPGA: Trusted Execution Environment for CPU-FPGA Heterogeneous Architecture

SGX-FPGA is a trusted hardware isolation path enabling the ﬁrst FPGA TEE by bridging SGX enclaves and FPGAs in the heterogeneous CPU-FPGA architecture. Our paper is published on [DAC 2021](https://ieeexplore.ieee.org/document/9586207).

## Prerequisites

An host machine which supports SGX

- OS: Centos 7.6 (64-bits)

- SGX SDK and SGX PSW

- Xilinx SDAccel 2017.4 or 2018.2

ADM-PCIE-7V3 acceleration card.

Currently this project only supports ADM-PCIE-7V3 card. Migrating to more type of FPGA cards is in the future plan. 

## Set up the Environment

1. Follow the [Intel SGX installation guide](https://github.com/intel/linux-sgx) to install SGX on the host machine.

2. Go to the [Intel SGX remote attestation service website](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/attestation-services.html) to acquire your own remote attestation service and get the EPID.

3. This demo is based on the [SGX remote attestation end-to-end repo](https://github.com/intel/sgx-ra-sample), and please follow the README in this repo to make sure the environment is correct.

   ```
   $ yum install libcurl-devel
   ```

4. (Optinal) This project only supports OpenSSL 1.1.0 or higher version, and the default version is 1.1.0i. If you want to use OpenSSL with different version, please modify build.sh or manually build this project. To download OpenSSL 1.1.0i:

   ```
     $ wget https://www.openssl.org/source/openssl-1.1.0i.tar.gz
     $ tar xf openssl-1.1.0i.tar.gz
     $ cd openssl-1.1.0i
     $ ./config --prefix=/opt/openssl/1.1.0i --openssldir=/opt/openssl/1.1.0i
     $ make
     $ sudo make install
   ```

5. Install [Xilinx SDAccel](https://www.xilinx.com/products/design-tools/legacy-tools/sdaccel.html) 2017.4 or 2018.2.

6. Install the AMD-PCIE-7V3 card to the host machine, following this [guide](https://support.alpha-data.com/pub/sdaccel/platform/adm-pcie-7v3/ad-an-0071_v1_0.pdf). To run the FPGA kernel, please source the environment first.

## Build the Project

This project includes four main compoments: the user application, the controller, the attestation server, and the secure monitor on the FPGA. Currently the user application, the controller and the attestation server need the support of SGX. The folder `sgx_fpga` includes the code of the user application, the controller, and the attestation server. The folder `sgx_fpga_FPGA` includes the code of secure monitor. You can use the script to build this demo, or manually build it with more options. The script will build the secure monitor in hardware mode, and it can be changed to simulation mode.

Use the script:

```
$ ./build.sh
```

Manually build:

1. Build the user application, controller, and the attestation server. 

   ```
   $ cd sgx_fpga/sgx-fpga-client
   $ ./bootstrap
   $ ./configure --with-openssldir=/opt/openssl/1.1.0i
   $ make
   $ cd ../sgx-fpga-controller
   $ ./bootstrap
   $ ./configure --with-openssldir=/opt/openssl/1.1.0i
   $ make
   $ cd ../sgx-fpga-server
   $ ./bootstrap
   $ ./configure --with-openssldir=/opt/openssl/1.1.0i
   $ make
   ```

   To enable the attestation, please follow the steps and modify the corresponding parameters in the `policy ` file in both `sgx-fpga-client` and `sgx-fpga-controller` folders . These parameters can be obtained from the Intel attestation service website. It is necessary to register your own account to require the serive.

    * The enclave's MRSIGNER value (this is a SHA256 hash generated from the signing key)

    * The Product ID number ('''ProdID''' in `Enclave.config.xml`)

    * The software vendor's enclave version number ('''ISVSVN''' in `Enclave.config.xml`)

2. Build the FPGA secure monitor

   ```
   $ cd sgx_fpga_FPGA/secure_monitor
   $ make all TARGET=hw #build in hardware mode
   ```

## Run the Project

After all the components are built, we can run this project. The user application, the controller, and the secure monitor has the pre-generated certificates, and it will not execute the communication to the attestation server by defaullt, but you still can enable it. 

```
./sgx_fpga/sgx-fpga-controller/client
./sgx_fpga_FPGA/secure_monitor/host
./sgx_fpga/sgx-fpga-client/client
```