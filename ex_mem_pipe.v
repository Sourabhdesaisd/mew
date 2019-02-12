// ex_mem_reg.v
// EX/MEM pipeline register — branch/jump control signals are NOT forwarded here.
// Branch/jump signals must be wired directly from EX -> IF / hazard / BTB.

module ex_mem_reg (
    input wire clk,
    input wire rst,
    input wire en,      // usually tied to 1 (no stall in MEM)
    input wire flush,   // usually 0 (no flush needed here)

    input wire [31:0] alu_result_ex,
    input wire [31:0] rs2_data_ex,
    input wire [4:0]  rd_ex,
    input wire        mem_write_ex,
    input wire        mem_read_ex,
    input wire [2:0]  mem_load_type_ex,
    input wire [1:0]  mem_store_type_ex,
    input wire        wb_reg_file_ex,
    input wire        memtoreg_ex,

    // NOTE: branch/jump signals intentionally NOT included here.
    // EX-stage must drive IF/hazard/BTB directly for immediate redirect.

    output reg [31:0] alu_result_mem,
    output reg [31:0] rs2_data_mem,
    output reg [4:0]  rd_mem,
    output reg        mem_write_mem,
    output reg        mem_read_mem,
    output reg [2:0]  mem_load_type_mem,
    output reg [1:0]  mem_store_type_mem,
    output reg        wb_reg_file_mem,
    output reg        memtoreg_mem
);

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            // Reset all pipeline outputs to safe defaults
            alu_result_mem    <= 32'h0;
            rs2_data_mem      <= 32'h0;
            rd_mem            <= 5'd0;
            mem_write_mem     <= 1'b0;
            mem_read_mem      <= 1'b0;
            mem_load_type_mem <= 3'b111;
            mem_store_type_mem<= 2'b11;
            wb_reg_file_mem   <= 1'b0;
            memtoreg_mem      <= 1'b0;
        end
        // FLUSH (bubble) has priority over stall
        else if (flush) begin
            alu_result_mem    <= 32'h0;
            rs2_data_mem      <= 32'h0;
            rd_mem            <= 5'd0;
            mem_write_mem     <= 1'b0;
            mem_read_mem      <= 1'b0;
            mem_load_type_mem <= 3'b111;
            mem_store_type_mem<= 2'b11;
            wb_reg_file_mem   <= 1'b0;
            memtoreg_mem      <= 1'b0;
        end
        else if (!en) begin
            // Stall/hold: explicitly retain current values
            alu_result_mem    <= alu_result_mem;
            rs2_data_mem      <= rs2_data_mem;
            rd_mem            <= rd_mem;
            mem_write_mem     <= mem_write_mem;
            mem_read_mem      <= mem_read_mem;
            mem_load_type_mem <= mem_load_type_mem;
            mem_store_type_mem<= mem_store_type_mem;
            wb_reg_file_mem   <= wb_reg_file_mem;
            memtoreg_mem      <= memtoreg_mem;
        end
        else begin
            // Normal advance: capture EX outputs (memory / WB path)
            alu_result_mem    <= alu_result_ex;
            rs2_data_mem      <= rs2_data_ex;
            rd_mem            <= rd_ex;
            mem_write_mem     <= mem_write_ex;
            mem_read_mem      <= mem_read_ex;
            mem_load_type_mem <= mem_load_type_ex;
            mem_store_type_mem<= mem_store_type_ex;
            wb_reg_file_mem   <= wb_reg_file_ex;
            memtoreg_mem      <= memtoreg_ex;
        end
    end
endmodule

