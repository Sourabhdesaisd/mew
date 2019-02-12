// mem_wb.v
// MEM -> WB pipeline register
// - captures ALU result and load result and forwards control to WB
// - provides a forwarding data output (data_forward_wb) for EX-stage forwarding
// - explicit flush-over-stall priority and deterministic hold behavior


module mem_wb (
    input  wire        clk,
    input  wire        rst,
    input  wire        en,        // enable (1 = advance, 0 = hold/stall)
    input  wire        flush,     // bubble insertion (1 = insert NOP/bubble)

    // Inputs from MEM stage (to be registered)
    input  wire [31:0] alu_result_in,
    input  wire [31:0] load_data_in,
    input  wire [4:0]  rd_in,
    input  wire        wb_reg_file_in,
    input  wire        memtoreg_in,

    // Optional: pass-through branch info for observation (not for redirect)
    input  wire        modify_pc_in,
    input  wire [31:0] update_pc_in,
    input  wire [31:0] jump_addr_in,
    input  wire        update_btb_in,

    // Outputs to WB stage
    output reg  [31:0] alu_result_out,
    output reg  [31:0] load_data_out,
    output reg  [4:0]  rd_out,
    output reg         wb_reg_file_out,
    output reg         memtoreg_out,

    // Forwarding / debug: data that forwarding unit should use from MEM/WB
    output wire [31:0] data_forward_wb, // typically selected as WB writeback data (mem or ALU)

    // Optional branch pass-through (for logging / performance counters)
    output reg         modify_pc_out,
    output reg [31:0]  update_pc_out,
    output reg [31:0]  jump_addr_out,
    output reg         update_btb_out
);

    // Internal: selected WB data (not registered here — outputs already register values)
    // Provide the forwarding value as the data that will be written back to the register file.
    // Forwarding unit expects the most-recent data available in WB stage:
    // If memtoreg_out==1 -> load data else -> alu result.
    assign data_forward_wb = (memtoreg_out) ? load_data_out : alu_result_out;

    // Safe NOP defaults
    localparam [31:0] ZERO32 = 32'h00000000;
    localparam [4:0]  ZERO5  = 5'd0;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            // reset outputs to safe defaults
            alu_result_out   <= ZERO32;
            load_data_out    <= ZERO32;
            rd_out           <= ZERO5;
            wb_reg_file_out  <= 1'b0;
            memtoreg_out     <= 1'b0;
            modify_pc_out    <= 1'b0;
            update_pc_out    <= ZERO32;
            jump_addr_out    <= ZERO32;
            update_btb_out   <= 1'b0;
        end
        // FLUSH should have priority over stall so bubble is inserted even if pipeline is stalled
        else if (flush) begin
            alu_result_out   <= ZERO32;
            load_data_out    <= ZERO32;
            rd_out           <= ZERO5;
            wb_reg_file_out  <= 1'b0;
            memtoreg_out     <= 1'b0;
            modify_pc_out    <= 1'b0;
            update_pc_out    <= ZERO32;
            jump_addr_out    <= ZERO32;
            update_btb_out   <= 1'b0;
        end
        else if (!en) begin
            // Hold: explicitly retain current values
            alu_result_out   <= alu_result_out;
            load_data_out    <= load_data_out;
            rd_out           <= rd_out;
            wb_reg_file_out  <= wb_reg_file_out;
            memtoreg_out     <= memtoreg_out;
            modify_pc_out    <= modify_pc_out;
            update_pc_out    <= update_pc_out;
            jump_addr_out    <= jump_addr_out;
            update_btb_out   <= update_btb_out;
        end
        else begin
            // Normal capture from MEM stage
            alu_result_out   <= alu_result_in;
            load_data_out    <= load_data_in;
            rd_out           <= rd_in;
            wb_reg_file_out  <= wb_reg_file_in;
            memtoreg_out     <= memtoreg_in;
            // Branch info forwarded for visibility only
            modify_pc_out    <= modify_pc_in;
            update_pc_out    <= update_pc_in;
            jump_addr_out    <= jump_addr_in;
            update_btb_out   <= update_btb_in;
        end
    end

endmodule

