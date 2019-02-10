// -------------------------------
// forwarding_unit
// -------------------------------
module forwarding_unit (
    input  wire [4:0] rs1_ex,
    input  wire [4:0] rs2_ex,
    input  wire       exmem_regwrite,
    input  wire [4:0] exmem_rd,
    input  wire       memwb_regwrite,
    input  wire [4:0] memwb_rd,
    output reg  [1:0] operand_a_forward_cntl,
    output reg  [1:0] operand_b_forward_cntl
);
    always @(*) begin
        operand_a_forward_cntl = 2'b00;
        operand_b_forward_cntl = 2'b00;

        // Operand A (rs1) - EX/MEM priority
        if (exmem_regwrite && (exmem_rd != 5'd0) && (exmem_rd == rs1_ex)) begin
            operand_a_forward_cntl = 2'b01;
        end else if (memwb_regwrite && (memwb_rd != 5'd0) && (memwb_rd == rs1_ex)) begin
            operand_a_forward_cntl = 2'b10;
        end

        // Operand B (rs2)
        if (exmem_regwrite && (exmem_rd != 5'd0) && (exmem_rd == rs2_ex)) begin
            operand_b_forward_cntl = 2'b01;
        end else if (memwb_regwrite && (memwb_rd != 5'd0) && (memwb_rd == rs2_ex)) begin
            operand_b_forward_cntl = 2'b10;
        end
    end
endmodule

