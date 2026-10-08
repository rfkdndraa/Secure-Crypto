`timescale 1ns/1ps
// -----------------------------------------------------------------------------
// SecureCrypto - on-board self-test sequencer (Avalon-MM master)
// Executes the program in sc_selftest_rom.v (generated from the official KAT)
// against the SecureCrypto registers. Lets the bitstream be validated on the
// DE10-Nano with only the push-buttons and LEDs, before the HPS is involved.
// -----------------------------------------------------------------------------
module sc_selftest (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        go,           // one-cycle start pulse
    input  wire        sw_fault,     // SW[0]: enable fault-injection step
    input  wire        sw_keyrd,     // SW[1]: enable key-read attempt

    output reg  [6:0]  m_address,
    output reg         m_read,
    output reg         m_write,
    output reg  [31:0] m_writedata,
    input  wire [31:0] m_readdata,   // valid one cycle after m_read

    output reg         running,
    output reg         finished,
    output reg         error
);
    localparam OP_END = 3'd0, OP_WR = 3'd1, OP_WAIT = 3'd2, OP_RDCMP = 3'd3,
               OP_WRSW0 = 3'd4, OP_RDSW1 = 3'd5;
    localparam S_IDLE = 2'd0, S_ISSUE = 2'd1, S_RESP = 2'd2;

    reg  [9:0]  pc;
    reg  [1:0]  st;
    reg  [21:0] tmo;                  // WAIT timeout (~84 ms at 50 MHz)
    wire [73:0] insn;
    wire [2:0]  i_op   = insn[73:71];
    wire [6:0]  i_addr = insn[70:64];
    wire [31:0] i_data = insn[63:32];
    wire [31:0] i_mask = insn[31:0];

    sc_selftest_rom u_rom (.pc(pc), .insn(insn));

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            pc <= 10'd0; st <= S_IDLE; tmo <= 22'd0;
            m_address <= 7'd0; m_read <= 1'b0; m_write <= 1'b0; m_writedata <= 32'd0;
            running <= 1'b0; finished <= 1'b0; error <= 1'b0;
        end else begin
            m_read  <= 1'b0;
            m_write <= 1'b0;
            case (st)
            S_IDLE: if (go) begin
                pc <= 10'd0; error <= 1'b0; finished <= 1'b0;
                running <= 1'b1; st <= S_ISSUE; tmo <= 22'd0;
            end
            S_ISSUE: begin
                m_address   <= i_addr;
                m_writedata <= i_data;
                case (i_op)
                OP_END:   begin running <= 1'b0; finished <= 1'b1; st <= S_IDLE; end
                OP_WR:    begin m_write <= 1'b1; pc <= pc + 10'd1; end
                OP_WRSW0: begin m_write <= sw_fault; pc <= pc + 10'd1; end
                OP_RDSW1: begin m_read  <= sw_keyrd; pc <= pc + 10'd1; end
                default:  begin m_read  <= 1'b1; st <= S_RESP; end  // WAIT, RDCMP
                endcase
            end
            S_RESP: if (!m_read) begin
                // m_read was high last cycle -> readdata valid now
                if (i_op == OP_WAIT) begin
                    if ((m_readdata & i_mask) != 32'd0) begin
                        pc <= pc + 10'd1; st <= S_ISSUE; tmo <= 22'd0;
                    end else if (&tmo) begin
                        error <= 1'b1; pc <= pc + 10'd1; st <= S_ISSUE; tmo <= 22'd0;
                    end else begin
                        tmo <= tmo + 22'd1; m_read <= 1'b1;      // poll again
                    end
                end else begin
                    if ((m_readdata & i_mask) != i_data) error <= 1'b1;
                    pc <= pc + 10'd1; st <= S_ISSUE;
                end
            end
            default: st <= S_IDLE;
            endcase
        end
    end
endmodule
