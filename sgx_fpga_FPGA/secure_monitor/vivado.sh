echo "XILINX Vivado 2018.2 enviroment seted"
echo ""
source /home/kora/xilinx/Vivado/2018.2/.settings64-Vivado.sh
source /home/kora/xilinx/Vivado/2018.2/.settings64-SDK_Core_Tools.sh
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


# /*******************************************************************************
# read_xdc $path_to_hdl/PUF.xdc
# adding constraint in project
# import_files -fileset constrs_1 $path_to_hdl/PUF_rtl.xdc
# *******************************************************************************/

set path_to_hdl "./src/PUF_stage/hdl"
set path_to_packaged "./packaged_kernel/PUF_stage_test"
set path_to_tmp_project "./tmp_kernel_pack_2_test"

create_project -force kernel_pack $path_to_tmp_project 
add_files -norecurse [glob $path_to_hdl/*.v $path_to_hdl/*.sv]
read_xdc $path_to_hdl/PUF_rtl.xdc
update_compile_order -fileset sources_1
update_compile_order -fileset sim_1
ipx::package_project -root_dir $path_to_packaged -vendor xilinx.com -library RTLKernel -taxonomy /KernelIP -import_files -set_current false
ipx::unload_core $path_to_packaged/component.xml
ipx::edit_ip_in_project -upgrade true -name tmp_edit_project -directory $path_to_packaged $path_to_packaged/component.xml
set_property core_revision 2 [ipx::current_core]
foreach up [ipx::get_user_parameters] {
  ipx::remove_user_parameter [get_property NAME $up] [ipx::current_core]
}
set_property sdx_kernel true [ipx::current_core]
set_property sdx_kernel_type rtl [ipx::current_core]
ipx::create_xgui_files [ipx::current_core]
ipx::associate_bus_interfaces -busif s_axi_control -clock ap_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif p0 -clock ap_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif p1 -clock ap_clk [ipx::current_core]
set_property xpm_libraries {XPM_CDC XPM_MEMORY XPM_FIFO} [ipx::current_core]
set_property supported_families { } [ipx::current_core]
set_property auto_family_support_level level_2 [ipx::current_core]
ipx::update_checksums [ipx::current_core]
ipx::save_core [ipx::current_core]
close_project -delete
