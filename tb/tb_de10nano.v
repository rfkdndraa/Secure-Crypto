`timescale 1ns/1ps
// Board-level test: press KEY[0] and check the LEDs, for three switch settings.
module tb_de10nano;
    parameter VARIANT = 2;
    reg        clk = 0;
    reg  [1:0] KEY = 2'b11;
    reg  [1:0] SW  = 2'b00;
    wire [5:0] LED;
    wire [1:0] GPIO_0;
    always #10 clk = ~clk;

    de10nano_top #(.VARIANT(VARIANT)) dut (
        .FPGA_CLK1_50(clk), .KEY(KEY), .SW(SW), .LED(LED), .GPIO_0(GPIO_0));

    integer errors = 0;
    task run_selftest(input [1:0] sw, input [5:0] exp_mask, input [5:0] exp);
        integer t;
        begin
            SW = sw;
            repeat (10) @(negedge clk);
            KEY[0] = 0; repeat (5) @(negedge clk); KEY[0] = 1;
            t = 0;
            while (!(LED[0] | LED[1]) && t < 2000000) begin @(negedge clk); t = t + 1; end
            $display("VARIANT %0d SW=%b -> LED=%b (PASS=%b FAIL=%b FAULT=%b VIOL=%b LAB=%b) after %0d cycles",
                     VARIANT, sw, LED, LED[0], LED[1], LED[2], LED[3], LED[5], t);
            if ((LED & exp_mask) !== (exp & exp_mask)) begin
                errors = errors + 1;
                $display("  unexpected LEDs, expected %b under mask %b", exp, exp_mask);
            end
        end
    endtask

    initial begin
        repeat (300) @(negedge clk);          // power-on reset
        // normal run: PASS, no fault, no violation, LAB on
        run_selftest(2'b00, 6'b101111, 6'b100001);
        // fault injection: everything fails the tag check; only C flags a fault
        run_selftest(2'b01, 6'b000111, (VARIANT == 2) ? 6'b000110 : 6'b000010);
        // key read attempt: still PASS, violation LED on
        run_selftest(2'b10, 6'b001011, 6'b001001);
        if (errors == 0) $display("BOARD RESULT VARIANT %0d: PASS", VARIANT);
        else             $display("BOARD RESULT VARIANT %0d: FAIL", VARIANT);
        $finish;
    end
endmodule
