`timescale 1ns/1ps
// -----------------------------------------------------------------------------
// SecureCrypto - DE10-Nano stand-alone top (no HPS required)
//
//   FPGA_CLK1_50 : 50 MHz system clock
//   KEY[0]       : run the KAT self-test (press)
//   KEY[1]       : reset (press)
//   SW[0]        : include the fault-injection step in the self-test
//   SW[1]        : include an illegal key-window read in the self-test
//   LED[0]       : PASS   (self-test finished, every check matched)
//   LED[1]       : FAIL   (at least one check mismatched)
//   LED[2]       : FAULT  detected by the duplication check (variant C)
//   LED[3]       : VIOL   key-window access violation logged
//   LED[4]       : running (blinks while the self-test runs)
//   LED[5]       : LAB build (fault injector present)
//   GPIO_0[0]    : scope trigger, high while the permutation runs
//   GPIO_0[1]    : operation done (irq)
//
// VARIANT is set per Quartus revision (set_parameter -name VARIANT 0/1/2).
// For the HPS-driven demo, add securecrypto.v to the GHRD Platform Designer
// system with securecrypto_hw.tcl instead of using this top.
// -----------------------------------------------------------------------------
module de10nano_top #(
    parameter VARIANT   = 2,
    parameter LAB_BUILD = 1
) (
    input  wire       FPGA_CLK1_50,
    input  wire [1:0] KEY,
    input  wire [1:0] SW,
    output wire [5:0] LED,
    output wire [1:0] GPIO_0
);
    wire clk = FPGA_CLK1_50;

    // ------------------------------------------- power-on + KEY[1] reset
    reg [2:0] rst_sync = 3'b000;
    reg [7:0] por_cnt  = 8'd0;
    wire      por_done = &por_cnt;
    always @(posedge clk) begin
        if (!por_done) por_cnt <= por_cnt + 8'd1;
        rst_sync <= {rst_sync[1:0], KEY[1] & por_done};
    end
    wire rst_n = rst_sync[2];

    // ------------------------------------------- synchronise inputs
    reg [2:0] k0_sync;
    reg [1:0] sw_s1, sw_s2;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            k0_sync <= 3'b111; sw_s1 <= 2'b00; sw_s2 <= 2'b00;
        end else begin
            k0_sync <= {k0_sync[1:0], KEY[0]};
            sw_s1   <= SW;
            sw_s2   <= sw_s1;
        end
    end
    wire go = k0_sync[2] & ~k0_sync[1];           // falling edge = press

    // ------------------------------------------- self-test + IP
    wire [6:0]  m_address;
    wire        m_read, m_write;
    wire [31:0] m_writedata, m_readdata;
    wire        running, finished, error;
    wire        irq, trig, s_busy, s_done, s_tag_ok, s_fault, s_viol, s_lab;

    sc_selftest u_st (
        .clk(clk), .rst_n(rst_n), .go(go),
        .sw_fault(sw_s2[0]), .sw_keyrd(sw_s2[1]),
        .m_address(m_address), .m_read(m_read), .m_write(m_write),
        .m_writedata(m_writedata), .m_readdata(m_readdata),
        .running(running), .finished(finished), .error(error));

    securecrypto #(.VARIANT(VARIANT), .LAB_BUILD(LAB_BUILD)) u_sc (
        .clk(clk), .rst_n(rst_n),
        .avs_address(m_address), .avs_read(m_read), .avs_write(m_write),
        .avs_writedata(m_writedata), .avs_readdata(m_readdata),
        .ent_in(32'd0),
        .irq(irq), .trig(trig), .sts_busy(s_busy), .sts_done(s_done),
        .sts_tag_ok(s_tag_ok), .sts_fault(s_fault), .sts_viol(s_viol),
        .sts_lab(s_lab));

    // fault LED stays on for the whole run once a fault was caught
    reg fault_seen;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)            fault_seen <= 1'b0;
        else if (go)           fault_seen <= 1'b0;
        else if (s_fault)      fault_seen <= 1'b1;
    end

    reg [23:0] blink = 24'd0;
    always @(posedge clk) blink <= blink + 24'd1;

    assign LED[0] = finished & ~error;
    assign LED[1] = finished &  error;
    assign LED[2] = fault_seen;
    assign LED[3] = s_viol;
    assign LED[4] = running & blink[23];
    assign LED[5] = s_lab;

    assign GPIO_0[0] = trig;
    assign GPIO_0[1] = irq;
endmodule
