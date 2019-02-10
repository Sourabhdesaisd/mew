module btb #(
    parameter SETS = 8,
    parameter WAYS = 2,
    parameter TAGW = 27
)(
    input              clk,
    input              rst,

    // ================= FETCH =================
    input      [31:0]  pc,
    output reg         predict_valid,
    output reg         predict_taken,
    output reg [31:0]  predict_target,

    // ================= UPDATE =================
    input              update_en,
    input      [31:0]  update_pc,
    input              actual_taken,
    input      [31:0]  update_target
);

    // ============================================================
    // FETCH STAGE
    // ============================================================
    wire [2:0] fetch_set;
    wire [TAGW-1:0] fetch_tag;
    wire hit0, hit1;

    // Data returned from btb_file for fetch read
    wire rd_valid0, rd_valid1;
    wire [TAGW-1:0] rd_tag0, rd_tag1;
    wire [31:0] rd_target0, rd_target1;
    wire [1:0]  rd_state0, rd_state1;
    wire rd_lru;

    // ----------------- FETCH READ MODULE -----------------
    btb_read #(.TAGW(TAGW)) U_READ (
        .pc(pc),

        .rd_valid0(rd_valid0),
        .rd_tag0(rd_tag0),

        .rd_valid1(rd_valid1),
        .rd_tag1(rd_tag1),

        .set_index(fetch_set),
        .tag(fetch_tag),
        .hit0(hit0),
        .hit1(hit1)
    );

    // ----------------- FETCH OUTPUT LOGIC -----------------
    always @(*) begin
        predict_valid = hit0 | hit1;

        if (hit0) begin
            predict_taken  = rd_state0[1];
            predict_target = rd_target0;
        end
        else if (hit1) begin
            predict_taken  = rd_state1[1];
            predict_target = rd_target1;
        end
        else begin
            predict_taken  = 1'b0;
            predict_target = pc + 32'd4;
        end
    end

    // ============================================================
    // UPDATE STAGE (WRITE PATH)
    // ============================================================
    wire [2:0] upd_set = update_pc[4:2];
    wire [TAGW-1:0] upd_tag = update_pc[31:5];

    // Signals from BTB file for update side read
    wire upd_valid0 = rd_valid0;
    wire upd_valid1 = rd_valid1;
    wire [TAGW-1:0] upd_tag0 = rd_tag0;
    wire [TAGW-1:0] upd_tag1 = rd_tag1;

    // Predictor states for write logic
    wire [1:0] next_state0, next_state1;

    // ----------------- WRITE CONTROL -----------------
    wire         wr_en;
    wire [2:0]   wr_set;
    wire         wr_way;
    wire         wr_valid;
    wire [TAGW-1:0] wr_tag;
    wire [31:0] wr_target;
    wire [1:0]  wr_state;

    wire wr_lru_en;
    wire wr_lru_val;

    // ----------------- UPDATE MODULE -----------------
    btb_write #(.TAGW(TAGW)) U_WRITE (
        .clk(clk),
        .rst(rst),
        .update_en(update_en),
        .update_pc(update_pc),
        .actual_taken(actual_taken),
        .update_target(update_target),

        .rd_valid0_upd(upd_valid0),
        .rd_tag0_upd(upd_tag0),
        .rd_valid1_upd(upd_valid1),
        .rd_tag1_upd(upd_tag1),
        .rd_lru_upd(rd_lru),

        .wr_en(wr_en),
        .wr_set(wr_set),
        .wr_way(wr_way),
        .wr_valid(wr_valid),
        .wr_tag(wr_tag),
        .wr_target(wr_target),
        .wr_state(wr_state),

        .wr_lru_en(wr_lru_en),
        .wr_lru_val(wr_lru_val),

        .state0_in(rd_state0),
        .state1_in(rd_state1),
        .next_state0(next_state0),
        .next_state1(next_state1)
    );

    // ============================================================
    // BTB FILE (Storage Arrays)
    // ============================================================

    btb_file #(.SETS(SETS), .WAYS(WAYS), .TAGW(TAGW)) U_FILE (
        .clk(clk),
        .rst(rst),

        // READ side
        .rd_set(fetch_set),
        .rd_way0(1'b0),
        .rd_valid0(rd_valid0),
        .rd_tag0(rd_tag0),
        .rd_target0(rd_target0),
        .rd_state0(rd_state0),

        .rd_way1(1'b0),
        .rd_valid1(rd_valid1),
        .rd_tag1(rd_tag1),
        .rd_target1(rd_target1),
        .rd_state1(rd_state1),

        .rd_lru(rd_lru),

        // WRITE side
        .wr_en(wr_en),
        .wr_set(wr_set),
        .wr_way(wr_way),
        .wr_valid(wr_valid),
        .wr_tag(wr_tag),
        .wr_target(wr_target),
        .wr_state(wr_state),

        .wr_lru_en(wr_lru_en),
        .wr_lru_val(wr_lru_val)
    );

endmodule

