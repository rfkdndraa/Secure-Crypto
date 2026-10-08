// -----------------------------------------------------------------------------
// Testbench for the SecureCrypto Avalon-MM IP.
//   * all official Ascon-AEAD128 KAT vectors, encrypt AND decrypt, through the
//     same register interface the HPS driver will use
//   * tampered tags: decryption must fail and release no plaintext
//   * key-window reads, locked-slot writes, nonce policy, lifecycle lock
//   * fault injection: variant A/B release a wrong tag, variant C must detect
//     the fault and release nothing
// Run:  iverilog -g2005 -P tb_securecrypto.VARIANT=2 -o sim rtl/*.v tb/tb_securecrypto.v
//       vvp sim +VEC=tb/kat.hex
// -----------------------------------------------------------------------------
`timescale 1ns/1ps
module tb_securecrypto;
    parameter VARIANT = 2;
    parameter DBUF_BLOCKS = 16;

    // register map (word addresses)
    localparam A_ID = 0, A_CTRL = 1, A_STATUS = 2, A_BLK = 3, A_NONCE = 4,
               A_DIN = 8, A_DOUT = 12, A_TAGIN = 16, A_TAGOUT = 20, A_KEYWR = 24,
               A_KEYRD = 28, A_SEED = 32, A_FCFG = 33, A_FCNT = 34, A_VCNT = 35,
               A_CYC = 36, A_LC = 37, A_DLEN = 39, A_DBUF = 64;
    // STATUS bits
    localparam ST_BUSY = 0, ST_RDY = 1, ST_DONE = 2, ST_TAGOK = 3, ST_FAULT = 4,
               ST_VIOL = 5, ST_NERR = 6, ST_PERR = 7;

    reg clk = 0, rst_n = 0;
    always #10 clk = ~clk;                       // 50 MHz like FPGA_CLK1_50

    reg  [6:0]  address = 0;
    reg         read = 0, write = 0;
    reg  [31:0] writedata = 0;
    wire [31:0] readdata;

    securecrypto #(.VARIANT(VARIANT), .LAB_BUILD(1), .DBUF_BLOCKS(DBUF_BLOCKS)) dut (
        .clk(clk), .rst_n(rst_n),
        .avs_address(address), .avs_read(read), .avs_write(write),
        .avs_writedata(writedata), .avs_readdata(readdata),
        .ent_in(32'd0), .irq(), .trig(), .sts_busy(), .sts_done(),
        .sts_tag_ok(), .sts_fault(), .sts_viol(), .sts_lab());

    // ------------------------------------------------------------ bus tasks
    task wr(input [6:0] a, input [31:0] d);
        begin
            @(negedge clk); address = a; writedata = d; write = 1;
            @(negedge clk); write = 0;
        end
    endtask

    task rd(input [6:0] a, output [31:0] d);
        begin
            @(negedge clk); address = a; read = 1;
            @(negedge clk); read = 0; d = readdata;
        end
    endtask

    integer errors = 0;
    reg [31:0] st;

    task wait_bit(input integer b);
        integer t;
        begin
            t = 0;
            rd(A_STATUS, st);
            while (!st[b] && !st[ST_FAULT] && !st[ST_PERR] && t < 20000) begin
                rd(A_STATUS, st); t = t + 1;
            end
            if (!st[b] && !st[ST_FAULT] && !st[ST_PERR]) begin
                $display("TIMEOUT waiting for STATUS[%0d], STATUS=%h", b, st);
                errors = errors + 1;
            end
        end
    endtask

    task wait_done_or_fault;
        integer t;
        begin
            t = 0;
            rd(A_STATUS, st);
            while (!st[ST_DONE] && t < 20000) begin rd(A_STATUS, st); t = t + 1; end
        end
    endtask

    task check(input [31:0] got, input [31:0] exp, input [8*24-1:0] what, input integer idx);
        begin
            if (got !== exp) begin
                errors = errors + 1;
                if (errors < 20)
                    $display("MISMATCH %0s vec %0d: got %h exp %h", what, idx, got, exp);
            end
        end
    endtask

    // ------------------------------------------------------- vector memory
    reg [31:0] mem [0:200000];
    localparam CAP = 190000;                    // scratch area: captured ciphertext
    integer p, vec;

    // per-vector fields (indices into mem)
    integer adlen, ptlen, nad, npt, p_key, p_non, p_ad, p_pt, p_ct, p_tag;

    task parse_vec;
        begin
            adlen = mem[p][31:16]; ptlen = mem[p][15:0];
            nad   = (adlen > 0) ? adlen / 16 + 1 : 0;
            npt   = ptlen / 16 + 1;
            p_key = p + 1; p_non = p + 5; p_ad = p + 9;
            p_pt  = p_ad + 4 * nad; p_ct = p_pt + 4 * npt;
            p_tag = p_ct + 4 * npt;
        end
    endtask

    task load_key;      // slot 1 (host-provisioned)
        integer i;
        begin
            for (i = 0; i < 4; i = i + 1) wr(A_KEYWR + i, mem[p_key + i]);
        end
    endtask

    task send_blocks(input integer base, input integer nblk, input integer len,
                     input is_ad, input enc_out, input do_check, input integer cmpbase);
        integer b, i, nb;
        reg [31:0] w, m;
        begin
            for (b = 0; b < nblk; b = b + 1) begin
                wait_bit(ST_RDY);
                if (!st[ST_RDY]) b = nblk;          // aborted (fault) - stop
                else begin
                for (i = 0; i < 4; i = i + 1) wr(A_DIN + i, mem[base + 4*b + i]);
                nb = (b == nblk - 1) ? (len % 16) : 16;
                wr(A_BLK, {22'd0, (b == nblk - 1), is_ad, 3'd0, nb[4:0]});
                if (enc_out) begin
                    // wait until the core has consumed the block
                    @(negedge clk); @(negedge clk);
                    for (i = 0; i < 4; i = i + 1) begin
                        rd(A_DOUT + i, w);
                        mem[CAP + 4*b + i] = w;          // captured ciphertext
                        // expected bytes beyond nb are zero
                        if (nb >= 4*i + 4)      m = 32'hFFFFFFFF;
                        else if (nb <= 4*i)     m = 32'h0;
                        else                    m = 32'hFFFFFFFF >> (8 * (4*i + 4 - nb));
                        if (do_check) check(w, mem[cmpbase + 4*b + i] & m, "dout", vec);
                    end
                end
                end
            end
        end
    endtask

    task run_encrypt(input integer use_slot, input check_tag, output [127:0] tag_got);
        integer i;
        reg [31:0] w;
        begin
            for (i = 0; i < 4; i = i + 1) wr(A_NONCE + i, mem[p_non + i]);
            wr(A_CTRL, {28'd0, use_slot[0], (adlen > 0), 1'b0, 1'b1});
            if (nad) send_blocks(p_ad, nad, adlen, 1'b1, 1'b0, 1'b0, 0);
            send_blocks(p_pt, npt, ptlen, 1'b0, 1'b1, check_tag, p_ct);
            wait_done_or_fault;
            for (i = 0; i < 4; i = i + 1) begin
                rd(A_TAGOUT + i, w);
                tag_got[32*i +: 32] = w;
                if (check_tag) check(w, mem[p_tag + i], "tag", vec);
            end
        end
    endtask

    task run_decrypt(input integer use_slot, input integer ctbase,
                     input [127:0] tag_use, input expect_ok);
        integer i, b;
        reg [31:0] w, m;
        begin
            for (i = 0; i < 4; i = i + 1) wr(A_NONCE + i, mem[p_non + i]);
            for (i = 0; i < 4; i = i + 1) wr(A_TAGIN + i, tag_use[32*i +: 32]);
            wr(A_CTRL, {28'd0, use_slot[0], (adlen > 0), 1'b1, 1'b1});
            if (nad) send_blocks(p_ad, nad, adlen, 1'b1, 1'b0, 1'b0, 0);
            send_blocks(ctbase, npt, ptlen, 1'b0, 1'b0, 1'b0, 0);
            wait_bit(ST_DONE);
            check(st[ST_TAGOK], expect_ok, "tag_ok", vec);
            // DOUT must never show plaintext in decrypt mode
            for (i = 0; i < 4; i = i + 1) begin rd(A_DOUT + i, w); check(w, 0, "dout_dec", vec); end
            // TAG_OUT must never show the computed tag in decrypt mode
            for (i = 0; i < 4; i = i + 1) begin rd(A_TAGOUT + i, w); check(w, 0, "tagout_dec", vec); end
            rd(A_DLEN, w); check(w, expect_ok ? ptlen : 0, "dlen", vec);
            for (b = 0; b < npt; b = b + 1)
                for (i = 0; i < 4; i = i + 1) begin
                    rd(A_DBUF + 4*b + i, w);
                    if (!expect_ok)                  m = 32'h0;
                    else if (ptlen >= 16*b + 4*i + 4) m = 32'hFFFFFFFF;
                    else if (ptlen <= 16*b + 4*i)     m = 32'h0;
                    else m = 32'hFFFFFFFF >> (8 * (16*b + 4*i + 4 - ptlen));
                    check(w, mem[p_pt + 4*b + i] & m, "plaintext", vec);
                end
        end
    endtask

    // ------------------------------------------------------------- main
    reg [127:0] tag_ref, tag_got, tag2;
    reg [319:0] sh0_a, sh1_a, sh0_b, sh1_b;
    reg [31:0]  w;
    integer     i, nvec, cyc1, last_key_p;
    reg [8*64-1:0] vecfile;

    initial begin
        if (!$value$plusargs("VEC=%s", vecfile)) vecfile = "tb/kat.hex";
        $readmemh(vecfile, mem);
        repeat (5) @(negedge clk);
        rst_n = 1;

        rd(A_ID, w);
        $display("VARIANT %0d  ID=%h", VARIANT, w);
        wr(A_SEED, 32'hC0FFEE01);

        // ============ 1. official KAT, encrypt + decrypt =================
        p = 0; vec = 0; nvec = 0; last_key_p = -1;
        while (mem[p] !== 32'hFFFFFFFF) begin
            parse_vec;
            if (last_key_p < 0 || mem[p_key] !== mem[last_key_p]) begin
                load_key; last_key_p = p_key;
            end
            run_encrypt(1, 1'b1, tag_got);
            for (i = 0; i < 4; i = i + 1) tag_ref[32*i +: 32] = mem[p_tag + i];
            run_decrypt(1, p_ct, tag_ref, 1'b1);
            if (vec % 7 == 3) begin
                // tampered tag -> must fail, no plaintext released
                run_decrypt(1, p_ct, tag_ref ^ (128'd1 << (vec % 128)), 1'b0);
            end
            vec = vec + 1;
            p = p_tag + 4;
        end
        $display("KAT: %0d vectors encrypt+decrypt done, errors so far = %0d", vec, errors);

        // pick vector 'AD=5, PT=7' style: the first vector with adlen>0 and ptlen>0
        p = 0;
        parse_vec;
        while (!(adlen == 5 && ptlen == 7)) begin p = p_tag + 4; parse_vec; end
        for (i = 0; i < 4; i = i + 1) tag_ref[32*i +: 32] = mem[p_tag + i];

        // ============ 2. key isolation =================================
        for (i = 0; i < 4; i = i + 1) begin
            rd(A_KEYRD + i, w); check(w, 0, "keyrd", i);
        end
        rd(A_STATUS, st); check(st[ST_VIOL], 1, "viol_flag", 0);
        rd(A_VCNT, w);    check(w, 4, "viol_cnt", 0);
        wr(A_CTRL, 32'h1000);                 // clear flags
        wr(A_CTRL, 32'h0800);                 // lock slot 1
        wr(A_KEYWR, 32'hDEADBEEF);            // must be refused
        rd(A_VCNT, w);    check(w, 5, "viol_cnt_lock", 0);
        run_encrypt(1, 1'b1, tag_got);        // key unchanged -> still correct
        $display("key isolation: done, errors so far = %0d", errors);

        // ============ 3. hardware key (slot 0) round trip =============
        wr(A_CTRL, 32'h0400);                 // KEYGEN
        run_encrypt(0, 1'b0, tag2);
        check(tag2 != tag_ref, 1, "slot0_differs", 0);
        run_decrypt(0, CAP, tag2, 1'b1);      // plaintext must come back
        $display("slot0 round trip: done, errors so far = %0d", errors);

        // ============ 4. nonce policy ==================================
        wr(A_CTRL, 32'h1000);
        for (i = 0; i < 4; i = i + 1) wr(A_NONCE + i, mem[p_non + i]);
        wr(A_CTRL, {28'd0, 1'b1, 1'b1, 1'b0, 1'b1} | 32'h10);   // same nonce, mono
        rd(A_STATUS, st);
        check(st[ST_NERR], 1, "nonce_err", 0);
        check(st[ST_BUSY], 0, "nonce_refused", 0);
        wr(A_CTRL, 32'h1000);

        // ============ 5. latency of one 8-round block ==================
        rd(A_CYC, w); cyc1 = w;
        $display("cycles in last op (computing only) = %0d", cyc1);

        // ============ 6. fault injection ===============================
        // flip x2 bit 7 of share 0 after round 5 of the initialization
        wr(A_FCFG, (2 << 12) | (7 << 16) | (5 << 4) | 1);
        run_encrypt(1, 1'b0, tag_got);
        rd(A_STATUS, st);
        if (VARIANT == 2) begin
            check(st[ST_FAULT], 1, "fault_detected", 0);
            check(tag_got, 0, "no_tag_released", 0);
            rd(A_FCNT, w); check(w, 1, "fault_cnt", 0);
            $display("variant C: fault detected, tag withheld (TAG_OUT=%h)", tag_got);
        end else begin
            check(st[ST_FAULT], 0, "no_detector", 0);
            check(tag_got != tag_ref, 1, "faulty_tag_released", 0);
            $display("variant %s: fault NOT detected, faulty tag released: %h (correct %h)",
                     VARIANT == 0 ? "A" : "B", tag_got, tag_ref);
        end
        // fault in the very last finalization round
        wr(A_FCFG, ((12 + 8 + 12 - 1) << 4) | 1);   // 32 rounds total
        run_encrypt(1, 1'b0, tag_got);
        rd(A_STATUS, st);
        if (VARIANT == 2) begin
            check(st[ST_FAULT], 1, "fault_last_round", 0);
            check(tag_got, 0, "no_tag_last_round", 0);
        end
        wr(A_FCFG, 0);
        run_encrypt(1, 1'b1, tag_got);        // works again after a fault
        $display("fault tests: done, errors so far = %0d", errors);

        // ============ 7. lifecycle lock ================================
        wr(A_CTRL, 32'h1000);
        wr(A_LC, 32'h4C4F434B);
        rd(A_LC, w); check(w, 1, "lc_locked", 0);
        wr(A_FCFG, 1);                        // must be refused
        rd(A_STATUS, st); check(st[ST_VIOL], 1, "fcfg_refused", 0);
        check(st[14], 0, "injector_off", 0);
        run_encrypt(1, 1'b1, tag_got);

        // ============ 8. masking is really active (B, C) ===============
        // Two runs with identical inputs: the recombined state must be equal,
        // but share 1 must be non-zero and different between the runs.
        if (VARIANT != 0) begin
            wr(A_CTRL, 32'h1000);
            for (i = 0; i < 4; i = i + 1) wr(A_NONCE + i, mem[p_non + i]);
            wr(A_CTRL, 32'h0005);               // encrypt, has_ad, slot 0
            wait_bit(ST_RDY);
            sh1_a = dut.u_core_a.s1; sh0_a = dut.u_core_a.s0;
            wr(A_CTRL, 32'h0100);               // abort
            for (i = 0; i < 4; i = i + 1) wr(A_NONCE + i, mem[p_non + i]);
            wr(A_CTRL, 32'h0005);
            wait_bit(ST_RDY);
            sh1_b = dut.u_core_a.s1; sh0_b = dut.u_core_a.s0;
            wr(A_CTRL, 32'h0100);
            check(sh1_a != 0, 1, "share1_nonzero", 0);
            check(sh1_a != sh1_b, 1, "share1_fresh", 0);
            check((sh0_a ^ sh1_a) == (sh0_b ^ sh1_b), 1, "same_value", 0);
            $display("masking: share1 differs between identical runs, value identical");
        end

        // ============ 9. decrypt buffer overflow =======================
        // a message longer than the buffer must be refused, nothing released
        wr(A_CTRL, 32'h1000);
        wr(A_CTRL, 32'h0003);                 // decrypt, no AD, slot 0
        for (i = 0; i <= DBUF_BLOCKS; i = i + 1) begin
            wait_bit(ST_RDY);
            wr(A_BLK, (i == DBUF_BLOCKS) ? 32'h200 : 32'h0);
        end
        wait_bit(ST_DONE);
        check(st[ST_PERR], 1, "overflow_perr", 0);
        check(st[ST_TAGOK], 0, "overflow_no_tag", 0);
        rd(A_DBUF, w); check(w, 0, "overflow_no_pt", 0);
        $display("decrypt-buffer overflow refused");

        // ============ 10. zeroize ======================================
        wr(A_CTRL, 32'h0200);
        wr(A_CTRL, 32'h0009);                 // start on slot 1 (now empty)
        rd(A_STATUS, st);
        check(st[ST_BUSY], 0, "zeroized_refuse", 0);
        check(st[ST_PERR], 1, "zeroized_perr", 0);

        if (errors == 0) $display("RESULT VARIANT %0d: PASS", VARIANT);
        else             $display("RESULT VARIANT %0d: FAIL (%0d errors)", VARIANT, errors);
        $finish;
    end

    initial begin
        #2_000_000_000;
        $display("GLOBAL TIMEOUT");
        $finish;
    end
endmodule
