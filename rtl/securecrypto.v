`timescale 1ns/1ps
// -----------------------------------------------------------------------------
// SecureCrypto IP - Avalon-MM slave wrapper
//
//   VARIANT 0 = A : unmasked Ascon-AEAD128
//   VARIANT 1 = B : A + 2-share DOM masking
//   VARIANT 2 = C : B + duplicated core with cycle-by-cycle share-wise compare
//   LAB_BUILD 1   : fault injector present (disabled after LIFECYCLE lock)
//
// Contains: key manager (2 write-only slots), mask PRNG, nonce policy, decrypt
// buffer (plaintext released only after the tag verifies), fault policy,
// violation / fault / cycle counters.
//
// Bus: 32-bit Avalon-MM slave, word addressing (7-bit word address),
// readLatency = 1, no waitrequest. Register map: see README.md.
// -----------------------------------------------------------------------------
module securecrypto #(
    parameter VARIANT     = 2,
    parameter LAB_BUILD   = 1,
    parameter DBUF_BLOCKS = 16,     // decrypt buffer, 16-byte blocks (max 16)
    parameter FAULT_LIMIT = 16      // faults before the IP locks itself
) (
    input  wire        clk,
    input  wire        rst_n,

    input  wire [6:0]  avs_address,
    input  wire        avs_read,
    input  wire        avs_write,
    input  wire [31:0] avs_writedata,
    output reg  [31:0] avs_readdata,

    input  wire [31:0] ent_in,        // optional entropy input (tie to 0)

    output wire        irq,           // level: operation finished
    output wire        trig,          // scope trigger: permutation running
    output wire        sts_busy,
    output wire        sts_done,
    output wire        sts_tag_ok,
    output wire        sts_fault,
    output wire        sts_viol,
    output wire        sts_lab
);
    localparam MASKED = (VARIANT >= 1) ? 1 : 0;
    localparam DUP    = (VARIANT == 2) ? 1 : 0;
    localparam LAB    = LAB_BUILD ? 1 : 0;
    localparam [1:0] VAR2 = (VARIANT == 2) ? 2'd2 : (VARIANT == 1) ? 2'd1 : 2'd0;
    localparam [0:0] LAB1 = LAB_BUILD ? 1'b1 : 1'b0;

    // --------------------------------------------------------- address map
    localparam [6:0] A_ID = 7'd0,  A_CTRL = 7'd1,  A_STATUS = 7'd2, A_BLK = 7'd3,
                     A_SEED = 7'd32, A_FCFG = 7'd33, A_FCNT = 7'd34, A_VCNT = 7'd35,
                     A_CYC  = 7'd36, A_LC   = 7'd37, A_OCNT = 7'd38, A_DLEN = 7'd39;
    // groups of 4 words: NONCE 4..7, DIN 8..11, DOUT 12..15, TAG_IN 16..19,
    // TAG_OUT 20..23, KEY_WR 24..27, KEY_RD 28..31 ; DBUF 64..127
    wire [4:0] grp  = avs_address[6:2];
    wire [1:0] widx = avs_address[1:0];
    localparam [4:0] G_NONCE = 5'd1, G_DIN = 5'd2, G_DOUT = 5'd3, G_TAGIN = 5'd4,
                     G_TAGOUT = 5'd5, G_KEYWR = 5'd6, G_KEYRD = 5'd7;
    wire is_dbuf = avs_address[6];

    localparam [31:0] LC_MAGIC = 32'h4C4F434B;   // "LOCK"

    // ---------------------------------------------------------------- state
    reg [127:0] nonce, din, tag_in, dout, tag_out;
    reg         busy, done, tag_ok, fault, viol, nonce_err, perr_f;
    reg         fault_lock, lc_locked;
    reg         op_dec, op_slot;
    reg  [7:0]  fault_cnt;
    reg  [15:0] viol_cnt;
    reg  [31:0] cyc_cnt, out_cnt;
    reg  [8:0]  dlen;
    reg  [4:0]  dbuf_n;
    reg [127:0] dbuf [0:DBUF_BLOCKS-1];
    reg         dbuf_clr;            // request: wipe the buffer next cycle

    // key manager: slot 0 = generated in hardware, slot 1 = written by host
    reg [127:0] ks0_0, ks1_0, ks0_1, ks1_1;   // slot n, share s
    reg         k0_valid;
    reg  [3:0]  k1_wmask;
    reg         k1_lock;
    reg [127:0] ln0, ln1;                     // last encrypt nonce per slot
    wire        k1_valid = &k1_wmask;

    // fault injector configuration
    reg         fi_en;
    reg  [7:0]  fi_round;
    reg  [2:0]  fi_word;
    reg  [5:0]  fi_bit;
    wire        fi_on = LAB & fi_en & ~lc_locked;

    // core control
    reg         core_start, core_clr, blk_go;
    reg         blk_is_ad, blk_last;
    reg  [4:0]  blk_nbytes;
    reg         c_dec, c_has_ad;

    // ------------------------------------------------------------------ PRNG
    reg         seed_we;
    reg  [31:0] seed;
    wire [319:0] rnd;
    sc_prng u_prng (.clk(clk), .rst_n(rst_n), .seed_we(seed_we), .seed(seed),
                    .ent_in(ent_in), .rnd(rnd));

    // ----------------------------------------------------------------- cores
    wire [127:0] key_s0 = op_slot ? ks0_1 : ks0_0;
    wire [127:0] key_s1 = op_slot ? ks1_1 : ks1_0;

    wire         a_rdy, a_perr, a_ov, a_tv, a_busy, a_comp;
    wire [127:0] a_od, a_tag;
    wire [4:0]   a_onb;
    wire [319:0] a_st0, a_st1;
    wire [15:0]  a_ctl;

    sc_ascon_core #(.MASKED(MASKED), .LAB(LAB)) u_core_a (
        .clk(clk), .rst_n(rst_n), .clr(core_clr),
        .start(core_start), .dec(c_dec), .has_ad(c_has_ad), .nonce(nonce),
        .key_s0(key_s0), .key_s1(key_s1), .rnd(rnd),
        .blk_valid(blk_go), .blk_is_ad(blk_is_ad), .blk_last(blk_last),
        .blk_nbytes(blk_nbytes), .blk_data(din), .blk_ready(a_rdy), .perr(a_perr),
        .out_valid(a_ov), .out_data(a_od), .out_nbytes(a_onb),
        .tag_valid(a_tv), .tag(a_tag), .busy(a_busy), .computing(a_comp),
        .fi_en(fi_on), .fi_round(fi_round), .fi_word(fi_word), .fi_bit(fi_bit),
        .st0(a_st0), .st1(a_st1), .ctl(a_ctl));

    wire mism;    // duplication mismatch (variant C), combinational
    generate
        if (DUP) begin : g_dup
            wire         b_rdy, b_perr, b_ov, b_tv, b_busy, b_comp;
            wire [127:0] b_od, b_tag;
            wire [4:0]   b_onb;
            wire [319:0] b_st0, b_st1;
            wire [15:0]  b_ctl;
            // Same inputs and the SAME randomness: both copies then hold
            // identical shares, so they can be compared share-by-share
            // without ever recombining a secret.
            sc_ascon_core #(.MASKED(MASKED), .LAB(0)) u_core_b (
                .clk(clk), .rst_n(rst_n), .clr(core_clr),
                .start(core_start), .dec(c_dec), .has_ad(c_has_ad), .nonce(nonce),
                .key_s0(key_s0), .key_s1(key_s1), .rnd(rnd),
                .blk_valid(blk_go), .blk_is_ad(blk_is_ad), .blk_last(blk_last),
                .blk_nbytes(blk_nbytes), .blk_data(din), .blk_ready(b_rdy), .perr(b_perr),
                .out_valid(b_ov), .out_data(b_od), .out_nbytes(b_onb),
                .tag_valid(b_tv), .tag(b_tag), .busy(b_busy), .computing(b_comp),
                .fi_en(1'b0), .fi_round(8'd0), .fi_word(3'd0), .fi_bit(6'd0),
                .st0(b_st0), .st1(b_st1), .ctl(b_ctl));
            assign mism = (|(a_st0 ^ b_st0)) | (|(a_st1 ^ b_st1))
                        | (a_ctl != b_ctl) | (a_rdy != b_rdy) | (a_perr != b_perr)
                        | (a_ov != b_ov) | (a_tv != b_tv) | (a_busy != b_busy)
                        | (a_ov & ((a_od != b_od) | (a_onb != b_onb)))
                        | (a_tv & (a_tag != b_tag));
        end else begin : g_nodup
            assign mism = 1'b0;
        end
    endgenerate

    // ------------------------------------------------------- helpers
    wire        slot_sel   = avs_writedata[3];
    wire        slot_ok    = slot_sel ? k1_valid : k0_valid;
    wire [127:0] ln_sel    = slot_sel ? ln1 : ln0;
    wire        nonce_gt   = (nonce > ln_sel);
    wire        mono_bad   = avs_writedata[4] & ~avs_writedata[1] & ~nonce_gt;

    integer j;

    // ------------------------------------------------- decrypt buffer
    // One write port and one clear path per flop. The clear is applied one
    // cycle after it is requested; that cycle is never observable because
    // every clear request also drops done/tag_ok, which gate DBUF reads.
    wire dbuf_we = busy & ~mism & a_ov & op_dec & (dbuf_n < DBUF_BLOCKS);
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (j = 0; j < DBUF_BLOCKS; j = j + 1) dbuf[j] <= 128'd0;
        end else if (dbuf_clr) begin
            for (j = 0; j < DBUF_BLOCKS; j = j + 1) dbuf[j] <= 128'd0;
        end else if (dbuf_we) begin
            dbuf[dbuf_n[3:0]] <= a_od;
        end
    end

    // ------------------------------------------------------------ main FSM
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            nonce <= 128'd0; din <= 128'd0; tag_in <= 128'd0;
            dout <= 128'd0; tag_out <= 128'd0;
            busy <= 1'b0; done <= 1'b0; tag_ok <= 1'b0; fault <= 1'b0;
            viol <= 1'b0; nonce_err <= 1'b0; perr_f <= 1'b0;
            fault_lock <= 1'b0; lc_locked <= 1'b0;
            op_dec <= 1'b0; op_slot <= 1'b0;
            fault_cnt <= 8'd0; viol_cnt <= 16'd0; cyc_cnt <= 32'd0; out_cnt <= 32'd0;
            dlen <= 9'd0; dbuf_n <= 5'd0;
            dbuf_clr <= 1'b0;
            ks0_0 <= 128'd0; ks1_0 <= 128'd0; ks0_1 <= 128'd0; ks1_1 <= 128'd0;
            k0_valid <= 1'b0; k1_wmask <= 4'd0; k1_lock <= 1'b0;
            ln0 <= 128'd0; ln1 <= 128'd0;
            fi_en <= 1'b0; fi_round <= 8'd0; fi_word <= 3'd0; fi_bit <= 6'd0;
            core_start <= 1'b0; core_clr <= 1'b0; blk_go <= 1'b0;
            blk_is_ad <= 1'b0; blk_last <= 1'b0; blk_nbytes <= 5'd0;
            c_dec <= 1'b0; c_has_ad <= 1'b0;
            seed_we <= 1'b0; seed <= 32'd0;
            avs_readdata <= 32'd0;
        end else begin
            core_start <= 1'b0;
            core_clr   <= 1'b0;
            blk_go     <= 1'b0;
            seed_we    <= 1'b0;
            dbuf_clr   <= 1'b0;

            if (busy && a_comp) cyc_cnt <= cyc_cnt + 32'd1;

            // ======================= core results / fault policy ==========
            if (busy && mism) begin
                // fault detected: abort, release NOTHING, wipe working data
                fault   <= 1'b1;
                done    <= 1'b1;
                busy    <= 1'b0;
                core_clr <= 1'b1;
                dout    <= 128'd0;
                tag_out <= 128'd0;
                tag_ok  <= 1'b0;
                dbuf_clr <= 1'b1;
                dbuf_n  <= 5'd0;
                dlen    <= 9'd0;
                if (fault_cnt != 8'hFF) fault_cnt <= fault_cnt + 8'd1;
                if (fault_cnt + 8'd1 >= FAULT_LIMIT) fault_lock <= 1'b1;
            end else if (busy) begin
                if (a_perr) begin
                    perr_f   <= 1'b1;
                    done     <= 1'b1;
                    busy     <= 1'b0;
                    core_clr <= 1'b1;
                    dout     <= 128'd0;
                    dbuf_clr <= 1'b1;
                end
                if (a_ov) begin
                    out_cnt <= out_cnt + 32'd1;
                    if (!op_dec) begin
                        dout <= a_od;
                    end else if (dbuf_n < DBUF_BLOCKS) begin
                        // block written by the dbuf process below
                        dbuf_n <= dbuf_n + 5'd1;
                        dlen   <= dlen + {4'd0, a_onb};
                    end else begin
                        // message longer than the decrypt buffer
                        perr_f   <= 1'b1;
                        done     <= 1'b1;
                        busy     <= 1'b0;
                        core_clr <= 1'b1;
                        dbuf_clr <= 1'b1;
                    end
                end
                if (a_tv) begin
                    done <= 1'b1;
                    busy <= 1'b0;
                    if (!op_dec) begin
                        tag_out <= a_tag;
                    end else if (a_tag == tag_in) begin
                        tag_ok <= 1'b1;
                    end else begin
                        tag_ok <= 1'b0;
                        dbuf_clr <= 1'b1;
                        dlen <= 9'd0;
                    end
                end
            end

            // ============================== bus writes ======================
            if (avs_write) begin
                if (is_dbuf) begin
                    // read-only window: ignore
                end else if (avs_address == A_CTRL) begin
                    if (avs_writedata[12]) begin
                        viol <= 1'b0; nonce_err <= 1'b0; perr_f <= 1'b0;
                    end
                    if (avs_writedata[8] || avs_writedata[9]) begin
                        // abort (and optionally zeroize keys)
                        busy <= 1'b0; done <= 1'b0; tag_ok <= 1'b0;
                        core_clr <= 1'b1;
                        dout <= 128'd0; tag_out <= 128'd0;
                        din  <= 128'd0; nonce <= 128'd0; tag_in <= 128'd0;
                        dbuf_clr <= 1'b1;
                        dbuf_n <= 5'd0; dlen <= 9'd0;
                        if (avs_writedata[9]) begin
                            ks0_0 <= 128'd0; ks1_0 <= 128'd0;
                            ks0_1 <= 128'd0; ks1_1 <= 128'd0;
                            k0_valid <= 1'b0; k1_wmask <= 4'd0; k1_lock <= 1'b0;
                            ln0 <= 128'd0; ln1 <= 128'd0;
                        end
                    end else if (!busy) begin
                        if (avs_writedata[10]) begin
                            // hardware key: two random shares, the key is their
                            // XOR and never exists in one register
                            ks0_0 <= MASKED ? rnd[127:0] : (rnd[127:0] ^ rnd[255:128]);
                            ks1_0 <= MASKED ? rnd[255:128] : 128'd0;
                            k0_valid <= 1'b1;
                            ln0 <= 128'd0;
                        end
                        if (avs_writedata[11]) k1_lock <= 1'b1;
                        if (avs_writedata[0]) begin
                            if (fault_lock || !slot_ok) begin
                                perr_f <= 1'b1;
                            end else if (mono_bad) begin
                                nonce_err <= 1'b1;
                            end else begin
                                core_start <= 1'b1;
                                c_dec      <= avs_writedata[1];
                                c_has_ad   <= avs_writedata[2];
                                op_dec     <= avs_writedata[1];
                                op_slot    <= slot_sel;
                                busy <= 1'b1; done <= 1'b0; tag_ok <= 1'b0;
                                fault <= 1'b0;
                                dout <= 128'd0; tag_out <= 128'd0;
                                dbuf_clr <= 1'b1;
                                dbuf_n <= 5'd0; dlen <= 9'd0;
                                cyc_cnt <= 32'd0; out_cnt <= 32'd0;
                                if (!avs_writedata[1]) begin
                                    if (slot_sel) ln1 <= nonce;
                                    else          ln0 <= nonce;
                                end
                            end
                        end
                    end
                end else if (avs_address == A_BLK) begin
                    if (busy && a_rdy && !blk_go) begin
                        blk_nbytes <= avs_writedata[4:0];
                        blk_is_ad  <= avs_writedata[8];
                        blk_last   <= avs_writedata[9];
                        blk_go     <= 1'b1;
                    end else begin
                        perr_f <= 1'b1;
                    end
                end else if (grp == G_NONCE) begin
                    if (!busy) nonce[widx*32 +: 32] <= avs_writedata;
                end else if (grp == G_DIN) begin
                    din[widx*32 +: 32] <= avs_writedata;
                end else if (grp == G_TAGIN) begin
                    if (!busy) tag_in[widx*32 +: 32] <= avs_writedata;
                end else if (grp == G_KEYWR) begin
                    if (k1_lock || busy) begin
                        viol <= 1'b1;
                        if (viol_cnt != 16'hFFFF) viol_cnt <= viol_cnt + 16'd1;
                    end else begin
                        // stored as (w ^ r, r) in the masked variants
                        ks0_1[widx*32 +: 32] <= MASKED ? (avs_writedata ^ rnd[31:0])
                                                       : avs_writedata;
                        ks1_1[widx*32 +: 32] <= MASKED ? rnd[31:0] : 32'd0;
                        k1_wmask[widx] <= 1'b1;
                        ln1 <= 128'd0;
                    end
                end else if (avs_address == A_SEED) begin
                    seed    <= avs_writedata;
                    seed_we <= 1'b1;
                end else if (avs_address == A_FCFG) begin
                    if (LAB && !lc_locked) begin
                        fi_en    <= avs_writedata[0];
                        fi_round <= avs_writedata[11:4];
                        fi_word  <= avs_writedata[14:12];
                        fi_bit   <= avs_writedata[21:16];
                    end else begin
                        viol <= 1'b1;
                        if (viol_cnt != 16'hFFFF) viol_cnt <= viol_cnt + 16'd1;
                    end
                end else if (avs_address == A_LC) begin
                    if (avs_writedata == LC_MAGIC) begin
                        lc_locked <= 1'b1;
                        fi_en     <= 1'b0;
                    end
                end
            end

            // =============================== bus reads ======================
            if (avs_read) begin
                avs_readdata <= 32'd0;
                if (is_dbuf) begin
                    if (done && op_dec && tag_ok && !fault &&
                        {1'b0, avs_address[5:2]} < DBUF_BLOCKS)
                        avs_readdata <= dbuf[avs_address[5:2]][widx*32 +: 32];
                end else if (grp == G_KEYRD) begin
                    // key window: never readable, every attempt is logged
                    viol <= 1'b1;
                    if (viol_cnt != 16'hFFFF) viol_cnt <= viol_cnt + 16'd1;
                end else if (grp == G_DOUT) begin
                    if (!op_dec) avs_readdata <= dout[widx*32 +: 32];
                end else if (grp == G_TAGOUT) begin
                    // never expose the computed tag of a decryption (forgery oracle)
                    if (!op_dec && done && !fault) avs_readdata <= tag_out[widx*32 +: 32];
                end else begin
                    case (avs_address)
                    A_ID:     avs_readdata <= 32'h53430100 | VARIANT;
                    A_STATUS: avs_readdata <= {14'd0, VAR2,
                                               1'b0, fi_on, k1_lock, k1_valid, k0_valid,
                                               LAB1, lc_locked, fault_lock,
                                               perr_f, nonce_err, viol, fault,
                                               tag_ok, done,
                                               busy & a_rdy & ~blk_go, busy};
                    A_FCNT:   avs_readdata <= {24'd0, fault_cnt};
                    A_VCNT:   avs_readdata <= {16'd0, viol_cnt};
                    A_CYC:    avs_readdata <= cyc_cnt;
                    A_LC:     avs_readdata <= {31'd0, lc_locked};
                    A_OCNT:   avs_readdata <= out_cnt;
                    A_DLEN:   avs_readdata <= (done && op_dec && tag_ok) ? {23'd0, dlen} : 32'd0;
                    default:  avs_readdata <= 32'd0;
                    endcase
                end
            end
        end
    end

    assign irq        = done;
    assign trig       = a_comp;
    assign sts_busy   = busy;
    assign sts_done   = done;
    assign sts_tag_ok = tag_ok;
    assign sts_fault  = fault;
    assign sts_viol   = viol;
    assign sts_lab    = LAB & ~lc_locked;
endmodule
