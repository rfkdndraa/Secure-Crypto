`timescale 1ns/1ps
// ASIC top for variant C (fixed parameters so LibreLane can harden it as a macro).
// DBUF_BLOCKS=4: decrypted messages up to 63 bytes (FPGA build: 16 blocks).
module securecrypto_c (
    input  wire        clk,
    input  wire        rst_n,
    input  wire [6:0]  avs_address,
    input  wire        avs_read,
    input  wire        avs_write,
    input  wire [31:0] avs_writedata,
    output wire [31:0] avs_readdata,
    input  wire [31:0] ent_in,
    output wire        irq,
    output wire        trig,
    output wire        sts_fault,
    output wire        sts_viol
);
    securecrypto #(.VARIANT(2), .LAB_BUILD(1), .DBUF_BLOCKS(4)) u (
        .clk(clk), .rst_n(rst_n),
        .avs_address(avs_address), .avs_read(avs_read), .avs_write(avs_write),
        .avs_writedata(avs_writedata), .avs_readdata(avs_readdata),
        .ent_in(ent_in), .irq(irq), .trig(trig),
        .sts_busy(), .sts_done(), .sts_tag_ok(),
        .sts_fault(sts_fault), .sts_viol(sts_viol), .sts_lab());
endmodule
