module btb_write #(
    parameter TAGW = 27
)(
    input  wire clk,
    input  wire rst,
    input  wire update_en,
    input  wire [31:0] update_pc,
    input  wire actual_taken,
    input  wire [31:0] update_target,

    // read info for hit detection
    input  wire rd_valid0_upd,
    input  wire [TAGW-1:0] rd_tag0_upd,
    input  wire rd_valid1_upd,
    input  wire [TAGW-1:0] rd_tag1_upd,
    input  wire rd_lru_upd,

    // write commands to btb_file
    output reg         wr_en,
    output reg  [2:0]  wr_set,
    output reg         wr_way,
    output reg         wr_valid,
    output reg  [TAGW-1:0] wr_tag,
    output reg  [31:0] wr_target,
    output reg  [1:0]  wr_state,

    // LRU
    output reg         wr_lru_en,
    output reg         wr_lru_val,

    // predictor input/output
    input  wire [1:0]  state0_in,
    input  wire [1:0]  state1_in,
    output wire [1:0]  next_state0,
    output wire [1:0]  next_state1
);

    wire [2:0] upd_set = update_pc[4:2];
    wire [TAGW-1:0] upd_tag = update_pc[31:5];

    // predictor logic
    dynamic_branch_predictor dp0(state0_in, actual_taken, next_state0);
    dynamic_branch_predictor dp1(state1_in, actual_taken, next_state1);

    wire hit0 = rd_valid0_upd && (rd_tag0_upd == upd_tag);
    wire hit1 = rd_valid1_upd && (rd_tag1_upd == upd_tag);

    always @(*) begin
        wr_en      = 0;
        wr_lru_en  = 0;

        if (!update_en) begin
            wr_valid = 0;
            wr_set   = 0;
            wr_way   = 0;
            wr_tag   = 0;
            wr_target= 0;
            wr_state = 0;
            wr_lru_val = 0;
        end
        else begin
            wr_set = upd_set;

            if (hit0) begin
                wr_way   = 0;
                wr_en    = 1;
                wr_valid = 1;
                wr_tag   = upd_tag;
                wr_state = next_state0;
                wr_target= actual_taken ? update_target : update_target;
                wr_lru_en = 1;
                wr_lru_val = 1;

            end else if (hit1) begin
                wr_way   = 1;
                wr_en    = 1;
                wr_valid = 1;
                wr_tag   = upd_tag;
                wr_state = next_state1;
                wr_target= actual_taken ? update_target : update_target;
                wr_lru_en = 1;
                wr_lru_val = 0;

            end else begin
                wr_en    = 1;
                wr_valid = 1;
                wr_tag   = upd_tag;
                wr_state = actual_taken ? 2'b10 : 2'b01;
                wr_target= update_target;
                wr_lru_en = 1;

                if (!rd_valid0_upd) begin
                    wr_way = 0;
                    wr_lru_val = 1;
                end else if (!rd_valid1_upd) begin
                    wr_way = 1;
                    wr_lru_val = 0;
                end else if (rd_lru_upd == 0) begin
                    wr_way = 0;
                    wr_lru_val = 1;
                end else begin
                    wr_way = 1;
                    wr_lru_val = 0;
                end
            end
        end
    end
endmodule

