



// top_decode: connects decode_unit, control_unit and register file
module top_decode (
    input  wire        clk,
    input  wire        rst,

    // Instruction fetch / ID inputs
    input  wire [31:0] instruction_in,
    input  wire        id_flush,

    // Writeback port (from WB stage)
    input  wire        wb_wr_en,
    input  wire [4:0]  wb_wr_addr,
    input  wire [31:0] wb_wr_data,

    // Instruction fields (outputs)
    output wire [6:0]  opcode,
    output wire [2:0]  func3,
    output wire [6:0]  func7,
    output wire [4:0]  rd,
    output wire [4:0]  rs1,
    output wire [4:0]  rs2,
    output wire [31:0] imm_out,

    // Register file outputs
    output wire [31:0] rs1_data,
    output wire [31:0] rs2_data,

    // Control signals
    output wire        ex_alu_src,
    output wire        mem_write,
    output wire        mem_read,
    output wire [2:0]  mem_load_type,
    output wire [1:0]  mem_store_type,
    output wire        wb_reg_file,
    output wire        memtoreg,
    output wire        branch,
    output wire        jal,
    output wire        jalr,
    output wire        auipc,
    output wire        lui,
    output wire [3:0]  alu_ctrl
);
    // Internal wires
    wire [6:0] opcode_w; wire [2:0] func3_w; wire [6:0] func7_w;
    wire [4:0] rd_w; wire [4:0] rs1_w; wire [4:0] rs2_w; wire [31:0] imm_w;
    wire ex_alu_src_w; wire mem_write_w; wire mem_read_w; wire [2:0] mem_load_type_w; wire [1:0] mem_store_type_w;
    wire wb_reg_file_w; wire memtoreg_w; wire branch_w; wire jal_w; wire jalr_w; wire auipc_w; wire lui_w; wire [3:0] alu_ctrl_w;

    // Decode unit
    decode_unit u_decode_unit (
        .instruction_in(instruction_in),
        .id_flush(id_flush),
        .opcode(opcode_w),
        .func3(func3_w),
        .func7(func7_w),
        .rd(rd_w),
        .rs1(rs1_w),
        .rs2(rs2_w),
        .imm_out(imm_w)
    );

    // Control unit
    control_unit u_ctrl (
        .opcode(opcode_w), .func3(func3_w), .func7(func7_w),
        .ex_alu_src(ex_alu_src_w), .mem_write(mem_write_w), .mem_read(mem_read_w),
        .mem_load_type(mem_load_type_w), .mem_store_type(mem_store_type_w),
        .wb_reg_file(wb_reg_file_w), .memtoreg(memtoreg_w),
        .branch(branch_w), .jal(jal_w), .jalr(jalr_w), .auipc(auipc_w), .lui(lui_w),
        .alu_ctrl(alu_ctrl_w)
    );

    // Register file (external file regfile.v)
    register_file u_regfile (
        .clk(clk),
        .wr_en(wb_wr_en), .wr_addr(wb_wr_addr), .wr_data(wb_wr_data),
        .rs1_addr(rs1_w), .rs2_addr(rs2_w),
        .rs1_data(rs1_data), .rs2_data(rs2_data)
    );

    // expose outputs
    assign opcode = opcode_w;
    assign func3 = func3_w;
    assign func7 = func7_w;
    assign rd = rd_w;
    assign rs1 = rs1_w;
    assign rs2 = rs2_w;
    assign imm_out = imm_w;

    assign ex_alu_src = ex_alu_src_w;
    assign mem_write = mem_write_w;
    assign mem_read = mem_read_w;
    assign mem_load_type = mem_load_type_w;
    assign mem_store_type = mem_store_type_w;
    assign wb_reg_file = wb_reg_file_w;
    assign memtoreg = memtoreg_w;
    assign branch = branch_w;
    assign jal = jal_w;
    assign jalr = jalr_w;
    assign auipc = auipc_w;
    assign lui = lui_w;
    assign alu_ctrl = alu_ctrl_w;
endmodule







