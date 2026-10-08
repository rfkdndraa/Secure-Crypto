`timescale 1ns/1ps
// -----------------------------------------------------------------------------
// SecureCrypto - Ascon permutation round logic (NIST SP 800-232)
//
// State layout (used everywhere in this project):
//   s[ 63:  0] = x0   s[127: 64] = x1   s[191:128] = x2
//   s[255:192] = x3   s[319:256] = x4
// Each 64-bit word is the little-endian integer of 8 state bytes, exactly as
// in SP 800-232 / pyascon.
//
// Three modules:
//   sc_ascon_round    : one unmasked round, purely combinational (variant A)
//   sc_ascon_dom_a    : masked round, phase A (linear pre-layer + DOM AND
//                       gadget partial products; outputs are registered by
//                       the caller)
//   sc_ascon_dom_b    : masked round, phase B (DOM compression + post-layer
//                       + linear diffusion)
// Plain Verilog-2001: synthesizable by Quartus Prime, Yosys and Verilator.
// -----------------------------------------------------------------------------

// Linear diffusion layer, applied to one share (it is linear, so share-wise).
module sc_ascon_lin (
    input  wire [319:0] i,
    output wire [319:0] o
);
    function [63:0] rotr;
        input [63:0] x;
        input integer n;
        begin
            rotr = (x >> n) | (x << (64 - n));
        end
    endfunction

    wire [63:0] x0 = i[ 63:  0];
    wire [63:0] x1 = i[127: 64];
    wire [63:0] x2 = i[191:128];
    wire [63:0] x3 = i[255:192];
    wire [63:0] x4 = i[319:256];

    assign o[ 63:  0] = x0 ^ rotr(x0, 19) ^ rotr(x0, 28);
    assign o[127: 64] = x1 ^ rotr(x1, 61) ^ rotr(x1, 39);
    assign o[191:128] = x2 ^ rotr(x2,  1) ^ rotr(x2,  6);
    assign o[255:192] = x3 ^ rotr(x3, 10) ^ rotr(x3, 17);
    assign o[319:256] = x4 ^ rotr(x4,  7) ^ rotr(x4, 41);
endmodule

// -----------------------------------------------------------------------------
// Unmasked round: constant addition -> S-box layer -> linear layer.
// r = round index 0..11 (SP 800-232 constant c_r = ((15-r)<<4) | r).
// -----------------------------------------------------------------------------
module sc_ascon_round (
    input  wire [319:0] s,
    input  wire [3:0]   r,
    output wire [319:0] o
);
    wire [7:0]  rc = {4'hf - r, r};
    wire [63:0] x0 = s[ 63:  0];
    wire [63:0] x1 = s[127: 64];
    wire [63:0] x2 = s[191:128] ^ {56'd0, rc};
    wire [63:0] x3 = s[255:192];
    wire [63:0] x4 = s[319:256];

    // pre-linear part of the S-box
    wire [63:0] a0 = x0 ^ x4;
    wire [63:0] a1 = x1;
    wire [63:0] a2 = x2 ^ x1;
    wire [63:0] a3 = x3;
    wire [63:0] a4 = x4 ^ x3;
    // non-linear part: t_i = ~a_i & a_{i+1}
    wire [63:0] t0 = ~a0 & a1;
    wire [63:0] t1 = ~a1 & a2;
    wire [63:0] t2 = ~a2 & a3;
    wire [63:0] t3 = ~a3 & a4;
    wire [63:0] t4 = ~a4 & a0;
    wire [63:0] b0 = a0 ^ t1;
    wire [63:0] b1 = a1 ^ t2;
    wire [63:0] b2 = a2 ^ t3;
    wire [63:0] b3 = a3 ^ t4;
    wire [63:0] b4 = a4 ^ t0;
    // post-linear part of the S-box
    wire [63:0] c1 = b1 ^ b0;
    wire [63:0] c0 = b0 ^ b4;
    wire [63:0] c3 = b3 ^ b2;
    wire [63:0] c2 = ~b2;

    sc_ascon_lin u_lin (.i({b4, c3, c2, c1, c0}), .o(o));
endmodule

// -----------------------------------------------------------------------------
// Masked round, phase A (2 shares, first-order Domain-Oriented Masking).
//   Input : state shares s0, s1 and 320 fresh random bits rnd.
//   Output: pre-linear shares a0/a1 and the four DOM partial products
//           (domain terms in00/in11, cross terms cr01/cr10 already re-masked).
//   The caller MUST register every output before phase B; that register stage
//   is what makes the DOM AND gadget glitch-robust.
// Round constant and the NOT of the chi-like AND are applied to share 0 only.
// -----------------------------------------------------------------------------
module sc_ascon_dom_a (
    input  wire [319:0] s0,
    input  wire [319:0] s1,
    input  wire [3:0]   r,
    input  wire [319:0] rnd,
    output wire [319:0] a0,
    output wire [319:0] a1,
    output wire [319:0] in00,
    output wire [319:0] in11,
    output wire [319:0] cr01,
    output wire [319:0] cr10
);
    wire [7:0] rc = {4'hf - r, r};

    // share 0
    wire [63:0] p0 = s0[ 63:  0];
    wire [63:0] p1 = s0[127: 64];
    wire [63:0] p2 = s0[191:128] ^ {56'd0, rc};
    wire [63:0] p3 = s0[255:192];
    wire [63:0] p4 = s0[319:256];
    // share 1
    wire [63:0] q0 = s1[ 63:  0];
    wire [63:0] q1 = s1[127: 64];
    wire [63:0] q2 = s1[191:128];
    wire [63:0] q3 = s1[255:192];
    wire [63:0] q4 = s1[319:256];

    // pre-linear layer, share-wise
    wire [63:0] u0 = p0 ^ p4, u1 = p1, u2 = p2 ^ p1, u3 = p3, u4 = p4 ^ p3;
    wire [63:0] v0 = q0 ^ q4, v1 = q1, v2 = q2 ^ q1, v3 = q3, v4 = q4 ^ q3;
    assign a0 = {u4, u3, u2, u1, u0};
    assign a1 = {v4, v3, v2, v1, v0};

    // operands of t_i = (~a_i) & a_{i+1}; ~a is applied to share 0 only
    wire [319:0] na0 = ~a0;           // share 0 of ~a
    wire [319:0] na1 =  a1;           // share 1 of ~a
    wire [319:0] b0  = {u0, u4, u3, u2, u1};   // share 0 of a_{i+1}
    wire [319:0] b1  = {v0, v4, v3, v2, v1};   // share 1 of a_{i+1}

    assign in00 = na0 & b0;
    assign in11 = na1 & b1;
    assign cr01 = (na0 & b1) ^ rnd;
    assign cr10 = (na1 & b0) ^ rnd;
endmodule

// -----------------------------------------------------------------------------
// Masked round, phase B: DOM compression, S-box post-layer, linear layer.
// All inputs come from registers written in phase A.
// -----------------------------------------------------------------------------
module sc_ascon_dom_b (
    input  wire [319:0] a0,
    input  wire [319:0] a1,
    input  wire [319:0] in00,
    input  wire [319:0] in11,
    input  wire [319:0] cr01,
    input  wire [319:0] cr10,
    output wire [319:0] o0,
    output wire [319:0] o1
);
    // t-shares: t = t0 ^ t1 = (~a_i) & a_{i+1}
    wire [319:0] t0 = in00 ^ cr01;
    wire [319:0] t1 = in11 ^ cr10;

    // x_i ^= t_{i+1}
    wire [319:0] tr0 = {t0[63:0], t0[319:64]};
    wire [319:0] tr1 = {t1[63:0], t1[319:64]};
    wire [319:0] b0  = a0 ^ tr0;
    wire [319:0] b1  = a1 ^ tr1;

    // post-linear layer; the final NOT on x2 goes on share 0 only
    wire [63:0] e0 = b0[63:0] ^ b0[319:256];
    wire [63:0] e1 = b0[127:64] ^ b0[63:0];
    wire [63:0] e2 = ~b0[191:128];
    wire [63:0] e3 = b0[255:192] ^ b0[191:128];
    wire [63:0] e4 = b0[319:256];
    wire [63:0] f0 = b1[63:0] ^ b1[319:256];
    wire [63:0] f1 = b1[127:64] ^ b1[63:0];
    wire [63:0] f2 = b1[191:128];
    wire [63:0] f3 = b1[255:192] ^ b1[191:128];
    wire [63:0] f4 = b1[319:256];

    sc_ascon_lin u_lin0 (.i({e4, e3, e2, e1, e0}), .o(o0));
    sc_ascon_lin u_lin1 (.i({f4, f3, f2, f1, f0}), .o(o1));
endmodule
