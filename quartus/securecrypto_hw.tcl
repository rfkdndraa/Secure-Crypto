# -----------------------------------------------------------------------------
# Platform Designer (Qsys) component for the SecureCrypto IP.
# Paths are relative to this file (../rtl/). Add the quartus/ folder
# to Platform Designer's IP search path, then connect:
#   clock -> clk_0.clk,  reset -> clk_0.clk_reset,
#   s0    -> hps_0.h2f_lw_axi_master  (lightweight HPS-to-FPGA bridge)
# HPS address = 0xFF200000 + the base offset you assign to s0.
# -----------------------------------------------------------------------------
package require -exact qsys 16.1

set_module_property NAME          securecrypto
set_module_property VERSION       1.0
set_module_property DISPLAY_NAME  "SecureCrypto Ascon-AEAD128"
set_module_property DESCRIPTION   "Ascon-AEAD128 (NIST SP 800-232) with key isolation, DOM masking and fault detection"
set_module_property GROUP         "Crypto"
set_module_property EDITABLE      false
set_module_property INTERNAL      false

add_fileset QUARTUS_SYNTH QUARTUS_SYNTH "" ""
set_fileset_property QUARTUS_SYNTH TOP_LEVEL securecrypto
add_fileset_file securecrypto.v   VERILOG PATH ../rtl/securecrypto.v TOP_LEVEL_FILE
add_fileset_file sc_ascon_core.v  VERILOG PATH ../rtl/sc_ascon_core.v
add_fileset_file sc_ascon_round.v VERILOG PATH ../rtl/sc_ascon_round.v
add_fileset_file sc_prng.v        VERILOG PATH ../rtl/sc_prng.v

add_parameter VARIANT INTEGER 2 "0 = A (unmasked), 1 = B (masked), 2 = C (masked + duplicated)"
set_parameter_property VARIANT ALLOWED_RANGES {0 1 2}
set_parameter_property VARIANT HDL_PARAMETER true
add_parameter LAB_BUILD INTEGER 1 "1 = fault injector present"
set_parameter_property LAB_BUILD ALLOWED_RANGES {0 1}
set_parameter_property LAB_BUILD HDL_PARAMETER true

# clock / reset
add_interface clock clock end
add_interface_port clock clk clk Input 1
add_interface reset reset end
set_interface_property reset associatedClock clock
set_interface_property reset synchronousEdges DEASSERT
add_interface_port reset rst_n reset_n Input 1

# Avalon-MM slave: 32-bit, word addressed, fixed read latency 1
add_interface s0 avalon end
set_interface_property s0 addressUnits WORDS
set_interface_property s0 associatedClock clock
set_interface_property s0 associatedReset reset
set_interface_property s0 readLatency 1
set_interface_property s0 readWaitTime 0
set_interface_property s0 writeWaitTime 0
set_interface_property s0 maximumPendingReadTransactions 0
add_interface_port s0 avs_address   address   Input  7
add_interface_port s0 avs_read      read      Input  1
add_interface_port s0 avs_write     write     Input  1
add_interface_port s0 avs_writedata writedata Input  32
add_interface_port s0 avs_readdata  readdata  Output 32

# status / trigger lines, exported to the top level (LEDs, GPIO header)
add_interface status conduit end
set_interface_property status associatedClock clock
add_interface_port status ent_in     ent_in     Input  32
add_interface_port status irq        done       Output 1
add_interface_port status trig       trig       Output 1
add_interface_port status sts_busy   busy       Output 1
add_interface_port status sts_done   sts_done   Output 1
add_interface_port status sts_tag_ok tag_ok     Output 1
add_interface_port status sts_fault  fault      Output 1
add_interface_port status sts_viol   viol       Output 1
add_interface_port status sts_lab    lab        Output 1
