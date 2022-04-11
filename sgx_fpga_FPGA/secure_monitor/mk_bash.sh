echo "MK_setup"
echo ""
source /home/kora/xilinx/Vivado/2018.2/.settings64-Vivado.sh
#source /home/kora/xilinx/Vivado/2018.2/.settings64-SDK_Core_Tools.sh
source /home/kora/xilinx/SDx/2018.2/.settings64-SDx.sh
source /home/kora/xilinx/SDx/2018.2/7v3_dsa/xbinst/setup.sh


# SDx software/hardware simulation environment
#export XCL_EMULATION_MODE=sw_emu
#export XCL_EMULATION_MODE=hw_emu
#export LD_LIBRARY_PATH=$XILINX_SDX/runtime/lib/x86_64/:$LD_LIBRARY_PATH
#export PATH=$XILINX_OPENCL/runtime/bin:$PATH
#unset XILINX_SDACCEL
export XILINX_SDX=/home/kora/xilinx/SDx/2018.2

# Application on FPGA
unset XCL_EMULATION_MODE
#unset XILINX_SDX
export XILINX_OPENCL=/home/kora/xilinx/SDx/2018.2/7v3_dsa/xbinst
export LD_LIBRARY_PATH=$XILINX_OPENCL/runtime/lib/x86_64:$LD_LIBRARY_PATH
export PATH=$XILINX_OPENCL/runtime/bin:$PATH
unset XILINX_SDACCEL

