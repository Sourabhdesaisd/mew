module mem_stage (
    input  wire        clk,
    input  wire        rst,
    input  wire        en,              // pipeline stall control (not used inside but left for uniform API)
    input  wire        flush,           // bubble insertion

    // ---------------- EX/MEM REGISTER INPUTS ----------------
    input  wire [31:0] alu_result_mem,       // address or ALU value
    input  wire [31:0] rs2_data_mem,         // store-data
    input  wire [4:0]  rd_mem,               // rd

    input  wire        mem_write_mem,
    input  wire        mem_read_mem,
    input  wire [2:0]  mem_load_type_mem,
    input  wire [1:0]  mem_store_type_mem,
    input  wire        wb_reg_file_mem,
    input  wire        memtoreg_mem,

    // branch/jump results from EX stage (should be connected directly EX->MEM input ports in top if used)
    input  wire        modify_pc_mem,   // NOTE: expected source = EX stage (direct connect), not EX/MEM reg
    input  wire [31:0] update_pc_mem,
    input  wire [31:0] jump_addr_mem,
    input  wire        update_btb_mem,

    // ---------------- OUTPUTS -> MEM/WB REGISTER ----------------
    output wire [31:0] alu_result_for_wb,
    output wire [31:0] load_wb_data,
    output wire [4:0]  rd_for_wb,
    output wire        wb_reg_file_out,
    output wire        memtoreg_out,

    // pass-through branch results to WB stage (if you need them there)
    output wire        modify_pc_out,
    output wire [31:0] update_pc_out,
    output wire [31:0] jump_addr_out,
    output wire        update_btb_out
);
    wire [31:0] mem_read_data;

    data_mem_top u_datamem (
        .clk(clk),
        .mem_read(mem_read_mem),
        .mem_write(mem_write_mem),
        .load_type(mem_load_type_mem),
        .store_type(mem_store_type_mem),
        .addr(alu_result_mem),
        .rs2_data(rs2_data_mem),
        .read_data(mem_read_data)
    );

    // OUTPUT ASSIGNMENTS (to MEM/WB)
    assign alu_result_for_wb = alu_result_mem;
    assign load_wb_data      = mem_read_data;
    assign rd_for_wb         = rd_mem;
    assign wb_reg_file_out   = wb_reg_file_mem;
    assign memtoreg_out      = memtoreg_mem;

    // Pass-through control flow results (if you want to carry them through MEM stage)
    assign modify_pc_out = modify_pc_mem;
    assign update_pc_out = update_pc_mem;
    assign jump_addr_out = jump_addr_mem;
    assign update_btb_out= update_btb_mem;
endmodule


