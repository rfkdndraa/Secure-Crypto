`timescale 1ns/1ps
// -----------------------------------------------------------------------------
// SecureCrypto - mask / key-generation PRNG (DEMO GRADE)
//
// Five independent xorshift64 lanes produce 320 fresh bits every clock for the
// DOM gadgets. The host can only XOR additional seed material in (it can never
// set the state), and ent_in is XORed in every cycle so a board-level entropy
// source can be attached later.
//
// LIMITATION (state it in the proposal): xorshift is not a cryptographic
// generator and there is no physical entropy source here. Leakage results are
// only meaningful if the masks are unpredictable; replace this block with a
// TRNG + SP 800-90A DRBG (or at least Trivium seeded by a TRNG) before any
// security claim.
// -----------------------------------------------------------------------------
module sc_prng (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         seed_we,
    input  wire [31:0]  seed,
    input  wire [31:0]  ent_in,
    output wire [319:0] rnd
);
    localparam [63:0] C0 = 64'h9E3779B97F4A7C15, C1 = 64'hBF58476D1CE4E5B9,
                      C2 = 64'h94D049BB133111EB, C3 = 64'hD6E8FEB86659FD93,
                      C4 = 64'hA0761D6478BD642F;

    reg [63:0] l [0:4];

    function [63:0] xs64;        // xorshift64 (13, 7, 17)
        input [63:0] x;
        reg   [63:0] y;
        begin
            y    = x ^ (x << 13);
            y    = y ^ (y >> 7);
            xs64 = y ^ (y << 17);
        end
    endfunction

    function [63:0] cst;
        input integer i;
        begin
            case (i)
                0: cst = C0; 1: cst = C1; 2: cst = C2; 3: cst = C3;
                default: cst = C4;
            endcase
        end
    endfunction

    integer i;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (i = 0; i < 5; i = i + 1) l[i] <= cst(i);
        end else begin
            for (i = 0; i < 5; i = i + 1) begin
                // a lane must never reach the all-zero fixed point
                if (l[i] == 64'd0) l[i] <= cst(i);
                else               l[i] <= xs64(l[i])
                                         ^ (seed_we ? {32'd0, seed} << (i * 8) : 64'd0)
                                         ^ ((i == 0) ? {32'd0, ent_in} : 64'd0);
            end
        end
    end

    assign rnd = {l[4], l[3], l[2], l[1], l[0]};
endmodule
