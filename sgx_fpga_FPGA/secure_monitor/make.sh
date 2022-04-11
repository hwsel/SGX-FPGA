

source mk_bash.sh
make cleanall
rm -rf _x
make all TARGETS=hw DEVICES=xilinx_adm-pcie-7v3_1ddr_3_0


