module btb_file #(
    parameter SETS = 8,
    parameter WAYS = 2,
    parameter TAGW = 27
)(
    input  wire                  clk,
    input  wire                  rst,

    // -------- READ PORT --------
    input  wire [2:0]            rd_set,
    input  wire [0:0]            rd_way0,   // dummy, to align structure
    output wire                  rd_valid0,
    output wire [TAGW-1:0]       rd_tag0,
    output wire [31:0]           rd_target0,
    output wire [1:0]            rd_state0,

    input  wire [0:0]            rd_way1,
    output wire                  rd_valid1,
    output wire [TAGW-1:0]       rd_tag1,
    output wire [31:0]           rd_target1,
    output wire [1:0]            rd_state1,

    // -------- WRITE PORT --------
    input  wire                  wr_en,
    input  wire [2:0]            wr_set,
    input  wire                  wr_way,     // 0 or 1
    input  wire                  wr_valid,
    input  wire [TAGW-1:0]       wr_tag,
    input  wire [31:0]           wr_target,
    input  wire [1:0]            wr_state,

    // LRU
    output wire                  rd_lru,
    input  wire                  wr_lru_en,
    input  wire                  wr_lru_val
);

    // ================= Arrays =================
    reg                valid_arr  [0:SETS-1][0:WAYS-1];
    reg [TAGW-1:0]     tag_arr    [0:SETS-1][0:WAYS-1];
    reg [31:0]         target_arr [0:SETS-1][0:WAYS-1];
    reg [1:0]          state_arr  [0:SETS-1][0:WAYS-1];
    reg                lru        [0:SETS-1];

    // ============= READ ACCESS =============
    assign rd_valid0  = valid_arr[rd_set][0];
    assign rd_tag0    = tag_arr[rd_set][0];
    assign rd_target0 = target_arr[rd_set][0];
    assign rd_state0  = state_arr[rd_set][0];

    assign rd_valid1  = valid_arr[rd_set][1];
    assign rd_tag1    = tag_arr[rd_set][1];
    assign rd_target1 = target_arr[rd_set][1];
    assign rd_state1  = state_arr[rd_set][1];

    assign rd_lru     = lru[rd_set];

    // ============= WRITE ACCESS =============
    integer i,j;
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            for (i=0; i<SETS; i=i+1) begin
                lru[i] <= 0;
                for (j=0; j<WAYS; j=j+1) begin
                    valid_arr[i][j]  <= 0;
                    tag_arr[i][j]    <= 0;
                    target_arr[i][j] <= 0;
                    state_arr[i][j]  <= 2'b01;   // weakly not taken
                end
            end
        end
        else begin
            if (wr_en) begin
                valid_arr [wr_set][wr_way] <= wr_valid;
                tag_arr   [wr_set][wr_way] <= wr_tag;
                target_arr[wr_set][wr_way] <= wr_target;
                state_arr [wr_set][wr_way] <= wr_state;
            end

            if (wr_lru_en)
                lru[wr_set] <= wr_lru_val;
        end
    end

endmodule

