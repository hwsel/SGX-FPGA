################################################################################
COMMON_REPO := ./

# Including Common Makefile
include $(COMMON_REPO)/utility/boards.mk
include $(COMMON_REPO)/libs/xcl2/xcl2.mk
include $(COMMON_REPO)/libs/opencl/opencl.mk

# Host Application
host_SRCS=./src/host.cpp $(xcl2_SRCS)
host_HDRS=$(xcl2_HDRS)
host_CXXFLAGS=-I./src/ $(opencl_CXXFLAGS) $(xcl2_CXXFLAGS) 
host_LDFLAGS=$(opencl_LDFLAGS)

EXES=host

input_SRCS=./src/input.cl
input_CLFLAGS=--xp param:compiler.version=31 -k krnl_input -I./src 

# PUF_HDLSRCS=src/kernel_PUF_stage.xml\
# 			  scripts/gen_PUF_xo.tcl\
# 			  scripts/package_kernel_PUF_stage.tcl\
# 			  src/PUF_stage/hdl/*.sv\
# 			  src/PUF_stage/hdl/*.v\
# 			  src/PUF_stage/hdl/*.xdc
# PUF_TCL=scripts/gen_PUF_xo.tcl

secure_monitor_SRCS=./src/input.cl
secure_monitor_CLFLAGS=--xp param:compiler.version=31 -k krnl_secure_monitor -I./src 

dummy_SRCS=./src/input.cl
dummy_CLFLAGS=--xp param:compiler.version=31 -k krnl_dummy -I./src 

output_SRCS=./src/input.cl
output_CLFLAGS=--xp param:compiler.version=31 -k krnl_output -I./src 


# RTLXOS=PUF
XOS=input secure_monitor 

# Kernel
PUF_XOS=input secure_monitor #PUF
PUF_NTARGETS=sw_emu

XCLBINS=PUF

EXTRA_CLEAN=tmp_kernel_pack* packaged_kernel*

# check
check_EXE=host
check_XCLBINS=PUF
check_NTARGETS=$(PUF_NTARGETS)

CHECKS=check

#Reporting warning if targeting for sw_emu
ifneq (,$(findstring sw_emu,$(TARGETS)))
$(warning WARNING:RTL Kernels do not support sw_emu TARGETS. Please use hw_emu for running RTL kernel Emulation)
endif

include $(COMMON_REPO)/utility/rules.mk

