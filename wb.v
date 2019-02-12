// wb_stage.v
// Writeback stage: select ALU or load data and present write port to register file.

module wb_stage (
    input  wire        clk,
    input  wire        rst,

    // ---------------- Inputs from MEM/WB Pipeline Register ----------------
    input  wire [31:0] alu_result_wb,
    input  wire [31:0] load_data_wb,
    input  wire [4:0]  rd_wb,
    input  wire        wb_reg_file_wb,     // RegWrite enable
    input  wire        memtoreg_wb,        // Selects between ALU and memory data

    // ---------------- Register File Connection ----------------
    output wire [31:0] wb_write_data,      // data written into regfile
    output wire [4:0]  wb_write_addr,      // write register number
    output wire        wb_write_en         // regfile write enable
);

    // Select writeback data: memory takes priority when memtoreg asserted.
    assign wb_write_data = memtoreg_wb ? load_data_wb : alu_result_wb;

    // Pass-through destination register number
    assign wb_write_addr = rd_wb;

    // Write enable: only if RegWrite asserted and rd != x0 (avoid writing x0)
    assign wb_write_en = (wb_reg_file_wb && (rd_wb != 5'd0));

endmodule

