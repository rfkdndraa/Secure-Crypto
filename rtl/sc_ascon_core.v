`timescale 1ns/1ps
// -----------------------------------------------------------------------------
// SecureCrypto - Ascon-AEAD128 core (NIST SP 800-232), encrypt + decrypt
//
// Parameters
//   MASKED = 0 : unmasked, 1 round / clock                     (variant A)
//   MASKED = 1 : 2-share first-order DOM masking,
//                2 clocks / round, 320 random bits / round     (variants B, C)
//   LAB    = 1 : logic-level fault injector compiled in (lab builds only)
//
// Block interface (one 128-bit block at a time, little-endian bytes):
//   * The host splits AD and message into full 16-byte blocks followed by
//     exactly ONE final block holding 0..15 bytes (blk_last=1). This is the
//     sponge padding rule of SP 800-232, so the core never needs to add an
//     extra padding block on its own.
//   * If the operation has no AD (has_ad=0) the host sends no AD block.
//   * Every message has a final block, even an empty one (nbytes=0).
//
// Outputs
//   out_valid/out_data : ciphertext (encrypt) or plaintext (decrypt) block,
//                        bytes beyond out_nbytes forced to zero
//   tag_valid/tag      : the computed tag (the wrapper decides who may see it)
//   st0/st1, ctl       : state shares and control state, ONLY for the
//                        duplication comparator of variant C (never exported
//                        to a register)
// -----------------------------------------------------------------------------
module sc_ascon_core #(
    parameter MASKED = 0,
    parameter LAB    = 1
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         clr,          // synchronous abort + zeroize

    input  wire         start,
    input  wire         dec,
    input  wire         has_ad,
    input  wire [127:0] nonce,
    input  wire [127:0] key_s0,       // key share 0 (plain key when MASKED=0)
    input  wire [127:0] key_s1,       // key share 1 (ignored when MASKED=0)
    input  wire [319:0] rnd,          // fresh randomness (MASKED=1)

    input  wire         blk_valid,
    input  wire         blk_is_ad,
    input  wire         blk_last,
    input  wire [4:0]   blk_nbytes,   // valid bytes of the final block (0..15)
    input  wire [127:0] blk_data,
    output wire         blk_ready,
    output reg          perr,         // protocol error pulse

    output reg          out_valid,
    output reg  [127:0] out_data,
    output reg  [4:0]   out_nbytes,
    output reg          tag_valid,
    output reg  [127:0] tag,

    output wire         busy,
    output wire         computing,

    // fault injector (LAB=1): flip state bit {fi_word,fi_bit} of share 0
    // right after round number fi_round (counted from op start)
    input  wire         fi_en,
    input  wire [7:0]   fi_round,
    input  wire [2:0]   fi_word,
    input  wire [5:0]   fi_bit,

    output wire [319:0] st0,
    output wire [319:0] st1,
    output wire [15:0]  ctl
);
    // ---------------------------------------------------------------- consts
    localparam [63:0] IV = 64'h00001000808C0001;  // Ascon-AEAD128, SP 800-232

    localparam [1:0] S_IDLE = 2'd0, S_PERM = 2'd1, S_POST = 2'd2, S_WAIT = 2'd3;
    localparam [2:0] P_INIT = 3'd0, P_AD = 3'd1, P_ADLAST = 3'd2,
                     P_MSG  = 3'd3, P_FINAL = 3'd4;

    // ----------------------------------------------------------------- regs
    reg [319:0] s0, s1;          // state shares (s1 stays 0 when MASKED=0)
    reg [1:0]   state;
    reg [2:0]   post;
    reg [3:0]   rcnt;            // current round index 0..11
    reg         phase;           // masked: 0 = phase A, 1 = phase B
    reg         op_dec, ad_phase;
    reg [7:0]   rtot;            // rounds executed in this operation

    // pipeline registers of the masked round
    reg [319:0] pa0, pa1, pin00, pin11, pcr01, pcr10;

    // ------------------------------------------------------- key word shares
    wire [63:0] k0s0 = key_s0[ 63: 0], k1s0 = key_s0[127:64];
    wire [63:0] k0s1 = MASKED ? key_s1[ 63: 0] : 64'd0;
    wire [63:0] k1s1 = MASKED ? key_s1[127:64] : 64'd0;

    // ------------------------------------------------------ round datapaths
    wire [319:0] rnd_n0, rnd_n1;        // next state after a full round

    wire [319:0] da0, da1, din00, din11, dcr01, dcr10;
    generate
        if (MASKED) begin : g_masked
            sc_ascon_dom_a u_a (
                .s0(s0), .s1(s1), .r(rcnt), .rnd(rnd),
                .a0(da0), .a1(da1), .in00(din00), .in11(din11),
                .cr01(dcr01), .cr10(dcr10));
            sc_ascon_dom_b u_b (
                .a0(pa0), .a1(pa1), .in00(pin00), .in11(pin11),
                .cr01(pcr01), .cr10(pcr10), .o0(rnd_n0), .o1(rnd_n1));
        end else begin : g_plain
            sc_ascon_round u_r (.s(s0), .r(rcnt), .o(rnd_n0));
            assign rnd_n1     = 320'd0;
            assign da0 = 320'd0; assign da1 = 320'd0;
            assign din00 = 320'd0; assign din11 = 320'd0;
            assign dcr01 = 320'd0; assign dcr10 = 320'd0;
        end
    endgenerate

    // ------------------------------------------------------ fault injector
    wire [319:0] fi_vec;
    generate
        if (LAB) begin : g_fi
            assign fi_vec = (fi_en && rtot == fi_round)
                          ? ({319'd0, 1'b1} << {fi_word, fi_bit}) : 320'd0;
        end else begin : g_nofi
            assign fi_vec = 320'd0;
        end
    endgenerate

    // ----------------------------------------------------- block absorption
    // byte mask m: all ones for a full block, nbytes ones for the last block
    // pad: 0x01 right after the last valid byte (only for the final block)
    wire [127:0] mfull  = {128{1'b1}};
    wire [127:0] mpart  = ~({128{1'b1}} << {blk_nbytes[3:0], 3'b000});
    wire [127:0] m      = blk_last ? mpart : mfull;
    wire [127:0] pad    = blk_last ? ({127'd0, 1'b1} << {blk_nbytes[3:0], 3'b000})
                                   : 128'd0;
    wire [127:0] dm     = blk_data & m;

    // The rate shares are recombined ONLY in the cycle a message block is
    // absorbed (output is public ciphertext / released plaintext). Gating keeps
    // the recombining XOR quiet while the permutation is running.
    wire         take   = (state == S_WAIT) & blk_valid;
    wire         msg_go = take & ~ad_phase;
    wire [127:0] r0g    = msg_go ? s0[127:0] : 128'd0;
    wire [127:0] r1g    = msg_go ? s1[127:0] : 128'd0;
    wire [127:0] rate_plain = r0g ^ r1g;

    // new rate share 0 (share 1 of the rate never changes on absorption)
    //   encrypt / AD : s0 ^= data ^ pad
    //   decrypt      : rate := C on the valid bytes  ->  s0' = (s0&~m)^(s1&m)^C^pad
    wire [127:0] rate_enc = s0[127:0] ^ dm ^ pad;
    wire [127:0] rate_dec = (s0[127:0] & ~m) ^ (s1[127:0] & m) ^ dm ^ pad;

    // nbytes > 15 on a final block, or wrong block type, is a protocol error
    wire bad_blk = (blk_last & blk_nbytes[4]) | (blk_is_ad != ad_phase);

    // tag = (x3 ^ K0, x4 ^ K1), shares recombined only in the final POST cycle
    wire         tag_go = (state == S_POST) & (post == P_FINAL);
    wire [127:0] tg0 = tag_go ? {s0[319:256] ^ k1s0, s0[255:192] ^ k0s0} : 128'd0;
    wire [127:0] tg1 = tag_go ? {s1[319:256] ^ k1s1, s1[255:192] ^ k0s1} : 128'd0;

    // ------------------------------------------------------------- sequential
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            s0 <= 320'd0; s1 <= 320'd0;
            pa0 <= 320'd0; pa1 <= 320'd0; pin00 <= 320'd0; pin11 <= 320'd0;
            pcr01 <= 320'd0; pcr10 <= 320'd0;
            state <= S_IDLE; post <= P_INIT; rcnt <= 4'd0; phase <= 1'b0;
            op_dec <= 1'b0; ad_phase <= 1'b0; rtot <= 8'd0;
            out_valid <= 1'b0; out_data <= 128'd0; out_nbytes <= 5'd0;
            tag_valid <= 1'b0; tag <= 128'd0; perr <= 1'b0;
        end else if (clr) begin
            s0 <= 320'd0; s1 <= 320'd0;
            pa0 <= 320'd0; pa1 <= 320'd0; pin00 <= 320'd0; pin11 <= 320'd0;
            pcr01 <= 320'd0; pcr10 <= 320'd0;
            state <= S_IDLE; post <= P_INIT; rcnt <= 4'd0; phase <= 1'b0;
            op_dec <= 1'b0; ad_phase <= 1'b0; rtot <= 8'd0;
            out_valid <= 1'b0; out_data <= 128'd0; out_nbytes <= 5'd0;
            tag_valid <= 1'b0; tag <= 128'd0; perr <= 1'b0;
        end else begin
            out_valid <= 1'b0;
            tag_valid <= 1'b0;
            perr      <= 1'b0;

            case (state)
            // ---------------------------------------------------------------
            S_IDLE: if (start) begin
                // S = IV || K || N ; key enters as shares, public parts in s0
                s0 <= {nonce[127:64], nonce[63:0], k1s0, k0s0, IV};
                s1 <= {64'd0, 64'd0, k1s1, k0s1, 64'd0};
                op_dec   <= dec;
                ad_phase <= has_ad;
                rcnt     <= 4'd0;           // 12 rounds
                phase    <= 1'b0;
                post     <= P_INIT;
                rtot     <= 8'd0;
                state    <= S_PERM;
            end
            // ---------------------------------------------------------------
            S_PERM: begin
                if (MASKED && !phase) begin
                    pa0 <= da0; pa1 <= da1; pin00 <= din00; pin11 <= din11;
                    pcr01 <= dcr01; pcr10 <= dcr10;
                    phase <= 1'b1;
                end else begin
                    s0    <= rnd_n0 ^ fi_vec;
                    s1    <= rnd_n1;
                    phase <= 1'b0;
                    rtot  <= rtot + 8'd1;
                    if (rcnt == 4'd11) state <= S_POST;
                    else               rcnt  <= rcnt + 4'd1;
                end
            end
            // ---------------------------------------------------------------
            S_POST: begin
                case (post)
                P_INIT: begin
                    // S ^= 0^192 || K ;  if no AD, domain separation now
                    s0[255:192] <= s0[255:192] ^ k0s0;
                    s0[319:256] <= s0[319:256] ^ k1s0
                                 ^ (ad_phase ? 64'd0 : 64'h8000000000000000);
                    s1[255:192] <= s1[255:192] ^ k0s1;
                    s1[319:256] <= s1[319:256] ^ k1s1;
                    state <= S_WAIT;
                end
                P_ADLAST: begin
                    s0[319:256] <= s0[319:256] ^ 64'h8000000000000000;
                    ad_phase    <= 1'b0;
                    state       <= S_WAIT;
                end
                P_FINAL: begin
                    tag       <= tg0 ^ tg1;
                    tag_valid <= 1'b1;
                    state     <= S_IDLE;
                end
                default: state <= S_WAIT;     // P_AD, P_MSG
                endcase
            end
            // ---------------------------------------------------------------
            S_WAIT: if (blk_valid) begin
                if (bad_blk) begin
                    perr <= 1'b1;               // wrapper aborts the operation
                end else begin
                    s0[127:0] <= (op_dec & ~ad_phase) ? rate_dec : rate_enc;
                    if (!ad_phase) begin
                        // output block: C = S_rate ^ P (enc) or P = S_rate ^ C (dec)
                        out_data   <= (rate_plain ^ blk_data) & m;
                        out_nbytes <= blk_last ? blk_nbytes : 5'd16;
                        out_valid  <= 1'b1;
                    end
                    phase <= 1'b0;
                    state <= S_PERM;
                    if (ad_phase) begin
                        rcnt <= 4'd4;                         // 8 rounds
                        post <= blk_last ? P_ADLAST : P_AD;
                    end else if (!blk_last) begin
                        rcnt <= 4'd4;
                        post <= P_MSG;
                    end else begin
                        // finalization: S ^= 0^128 || K || 0^64, 12 rounds
                        s0[191:128] <= s0[191:128] ^ k0s0;
                        s0[255:192] <= s0[255:192] ^ k1s0;
                        s1[191:128] <= s1[191:128] ^ k0s1;
                        s1[255:192] <= s1[255:192] ^ k1s1;
                        rcnt <= 4'd0;
                        post <= P_FINAL;
                    end
                end
            end
            endcase

            // share 1 does not exist in the unmasked core
            if (!MASKED) s1 <= 320'd0;
        end
    end

    assign blk_ready = (state == S_WAIT);
    assign busy      = (state != S_IDLE);
    assign computing = (state == S_PERM) | (state == S_POST);
    assign st0       = s0;
    assign st1       = s1;
    assign ctl       = {state, post, phase, op_dec, ad_phase, rcnt, 4'd0};
endmodule
