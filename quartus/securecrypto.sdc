# SecureCrypto - DE10-Nano timing constraints
create_clock -name clk50 -period 20.000 [get_ports {FPGA_CLK1_50}]
derive_pll_clocks
derive_clock_uncertainty
# asynchronous, human-speed I/O
set_false_path -from [get_ports {KEY[*] SW[*]}]
set_false_path -to   [get_ports {LED[*] GPIO_0[*]}]
