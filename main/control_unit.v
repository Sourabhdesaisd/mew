// Small control unit (decoding high-level control signals)
module control_unit(
    input wire [6:0] opcode,
    input wire [2:0] func3,
    input wire [6:0] func7,

    output reg ex_alu_src,
    output reg mem_write,
    output reg mem_read,
    output reg [2:0] mem_load_type,
    output reg [1:0] mem_store_type,
    output reg wb_reg_file,
    output reg memtoreg,
    output reg branch,
    output reg jal,
    output reg jalr,
    output reg auipc,
    output reg lui,
    output reg [3:0] alu_ctrl
);
    always @(*) begin
        // defaults
        ex_alu_src = 1'b0; mem_write = 1'b0; mem_read = 1'b0; mem_load_type = 3'b010; mem_store_type = 2'b10;
        wb_reg_file = 1'b0; memtoreg = 1'b0; branch = 1'b0; jal = 1'b0; jalr = 1'b0; auipc = 1'b0; lui = 1'b0;
        alu_ctrl = 4'b0000; // ADD default

        case (opcode)
            7'b0110011: begin // R-type
                wb_reg_file = 1'b1;
                case (func3)
                    3'b000: alu_ctrl = func7[5] ? 4'b0001 : 4'b0000; // SUB/ADD
                    3'b111: alu_ctrl = 4'b0010; // AND
                    3'b110: alu_ctrl = 4'b0011; // OR
                    3'b100: alu_ctrl = 4'b0100; // XOR
                    3'b001: alu_ctrl = 4'b0101; // SLL
                    3'b101: alu_ctrl = func7[5] ? 4'b0111 : 4'b0110; // SRA/SRL
                    3'b010: alu_ctrl = 4'b1000; // SLT
                    3'b011: alu_ctrl = 4'b1001; // SLTU
                    default: alu_ctrl = 4'b0000;
                endcase
            end
            7'b0010011: begin // I-type ALU
                ex_alu_src = 1'b1; wb_reg_file = 1'b1;
                case (func3)
                    3'b000: alu_ctrl = 4'b0000; // ADDI
                    3'b111: alu_ctrl = 4'b0010; // ANDI
                    3'b110: alu_ctrl = 4'b0011; // ORI
                    3'b100: alu_ctrl = 4'b0100; // XORI
                    3'b001: alu_ctrl = 4'b0101; // SLLI
                    3'b101: alu_ctrl = func7[5] ? 4'b0111 : 4'b0110; // SRAI/SRLI
                    3'b010: alu_ctrl = 4'b1000; // SLTI
                    3'b011: alu_ctrl = 4'b1001; // SLTIU
                    default: alu_ctrl = 4'b0000;
                endcase
            end
            7'b0000011: begin // LOAD
                ex_alu_src = 1'b1; mem_read = 1'b1; wb_reg_file = 1'b1; memtoreg = 1'b1;
                case (func3)
                    3'b000: mem_load_type = 3'b000; // LB
                    3'b001: mem_load_type = 3'b001; // LH
                    3'b010: mem_load_type = 3'b010; // LW
                    3'b100: mem_load_type = 3'b011; // LBU
                    3'b101: mem_load_type = 3'b100; // LHU
                    default: mem_load_type = 3'b010;
                endcase
            end
            7'b0100011: begin // STORE
                ex_alu_src = 1'b1; mem_write = 1'b1;
                case (func3)
                    3'b000: mem_store_type = 2'b00; // SB
                    3'b001: mem_store_type = 2'b01; // SH
                    3'b010: mem_store_type = 2'b10; // SW
                    default: mem_store_type = 2'b10;
                endcase
            end
            7'b1100011: begin // BRANCH
                branch = 1'b1; alu_ctrl = 4'b0001; // SUB for compare
            end
            7'b1101111: begin // JAL
                jal = 1'b1; wb_reg_file = 1'b1;
            end
            7'b1100111: begin // JALR
                jalr = 1'b1; ex_alu_src = 1'b1; wb_reg_file = 1'b1;
            end
            7'b0110111: begin // LUI
                wb_reg_file = 1'b1; alu_ctrl = 4'b1010;
            end
            7'b0010111: begin // AUIPC
                wb_reg_file = 1'b1; alu_ctrl = 4'b1011;
            end
            default: begin end
        endcase
    end
endmodule
