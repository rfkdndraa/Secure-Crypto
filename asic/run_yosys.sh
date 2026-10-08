#!/bin/sh
# Synthesis check + area report with Yosys, outside LibreLane.
# Usage: ./run_yosys.sh <liberty file> [a|b|c]
# In IIC-OSIC-TOOLS the IHP library is at:
#   $PDK_ROOT/ihp-sg13g2/libs.ref/sg13g2_stdcell/lib/sg13g2_stdcell_typ_1p20V_25C.lib
set -e
LIB=$1; V=${2:-c}
RTL="../rtl/sc_ascon_round.v ../rtl/sc_ascon_core.v ../rtl/sc_prng.v ../rtl/securecrypto.v"
yosys -l synth_$V.log -p "
  read_liberty -lib $LIB
  read_verilog $RTL securecrypto_$V.v
  synth -flatten -top securecrypto_$V
  dfflegalize -cell \$_DFF_PN0_ 01
  dfflibmap -liberty $LIB
  abc -liberty $LIB -D 20000
  opt_clean
  check -assert
  stat -liberty $LIB
  write_verilog -noattr securecrypto_${V}_netlist.v"
grep "Chip area" synth_$V.log | tail -1
