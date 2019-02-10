module execute_stage (
    // ---------- Inputs (from ID/EX) ----------
    input wire [31:0] pc_ex, // instruction PC (passed through, not used here)
    input wire [31:0] rs1_data_ex,
    input wire [31:0] rs2_data_ex,
    input wire [31:0] imm_ex,
    input wire [4:0] rs1_ex,
    input wire [4:0] rs2_ex,
    input wire [4:0] rd_ex,
    // Control signals (latched)
    input wire ex_alu_src_ex,
    input wire mem_write_ex,
    input wire mem_read_ex,
    input wire [2:0] mem_load_type_ex,
    input wire [2:0] mem_store_type_ex,
    input wire wb_reg_file_ex,
    input wire memtoreg_ex,
    input wire [3:0] alu_ctrl_ex,
    // ---------- Forwarding inputs ----------
    input wire [1:0] operand_a_forward_cntl, // 00=rs1_ex, 01=EX/MEM, 10=MEM/WB
    input wire [1:0] operand_b_forward_cntl,
    input wire [31:0] data_forward_mem,
    input wire [31:0] data_forward_wb,
    // ---------- Outputs (to EX/MEM) ----------
    output wire [31:0] alu_result_ex,
    output wire zero_flag_ex,
    output wire negative_flag_ex,
    output wire carry_flag_ex,
    output wire overflow_flag_ex,
    output wire [31:0] rs2_data_for_mem_ex,
    output wire [4:0] rd_ex_out,
    output wire mem_write_ex_out,
    output wire mem_read_ex_out,
    output wire [2:0] mem_load_type_ex_out,
    output wire [2:0] mem_store_type_ex_out,
    output wire wb_reg_file_ex_out,
    output wire memtoreg_ex_out,
    // ---------- Debug outputs ----------
    output wire [31:0] op1_selected_ex,
    output wire [31:0] op2_selected_ex,
    output wire [31:0] op2_after_alu_src_ex
);
    // --------------------------
    // Forwarding muxes (combinational)
    // --------------------------
    reg [31:0] op1_sel;
    reg [31:0] op2_sel;
    always @(*) begin
        // default
        op1_sel = rs1_data_ex;
        op2_sel = rs2_data_ex;

        // op1 selection (rs1 forwarding) - EX/MEM takes priority over MEM/WB
        case (operand_a_forward_cntl)
            2'b01: op1_sel = data_forward_mem;
            2'b10: op1_sel = data_forward_wb;
            default: op1_sel = rs1_data_ex;
        endcase

        // op2 selection (rs2 forwarding)
        case (operand_b_forward_cntl)
            2'b01: op2_sel = data_forward_mem;
            2'b10: op2_sel = data_forward_wb;
            default: op2_sel = rs2_data_ex;
        endcase
    end

    assign op1_selected_ex = op1_sel;
    assign op2_selected_ex = op2_sel;

    // ALU-src mux (choose immediate or forwarded rs2)
    reg [31:0] op2_final;
    always @(*) begin
        if (ex_alu_src_ex) op2_final = imm_ex;
        else op2_final = op2_sel;
    end
    assign op2_after_alu_src_ex = op2_final;

    // --------------------------
    // ALU invocation (arithmetic/logic/shift/cmp)
    // --------------------------
    wire [31:0] alu_result_w;
    wire zf_w, nf_w, cf_w, of_w;
    alu_top32 u_alu_top (
        .rs1(op1_sel),
        .rs2(op2_final),
        .alu_ctrl(alu_ctrl_ex),
        .alu_result(alu_result_w),
        .zero_flag(zf_w),
        .negative_flag(nf_w),
        .carry_flag(cf_w),
        .overflow_flag(of_w)
    );

    // Outputs
    assign alu_result_ex = alu_result_w;
    assign zero_flag_ex = zf_w;
    assign negative_flag_ex = nf_w;
    assign carry_flag_ex = cf_w;
    assign overflow_flag_ex = of_w;

    // Store data (forwarded rs2)
    assign rs2_data_for_mem_ex = op2_sel;

    // Control pass-through (to EX/MEM)
    assign rd_ex_out = rd_ex;
    assign mem_write_ex_out = mem_write_ex;
    assign mem_read_ex_out = mem_read_ex;
    assign mem_load_type_ex_out = mem_load_type_ex;
    assign mem_store_type_ex_out = mem_store_type_ex[1:0];
    assign wb_reg_file_ex_out = wb_reg_file_ex;
    assign memtoreg_ex_out = memtoreg_ex;
endmodule






