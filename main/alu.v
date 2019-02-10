// -------------------------------
// ALU Top and subunits
// -------------------------------
module alu_top32 (
    input  [31:0] rs1,
    input  [31:0] rs2,
    input  [3:0]  alu_ctrl,
    output [31:0] alu_result,
    output        zero_flag,
    output        negative_flag,
    output        carry_flag,
    output        overflow_flag
);
    wire [31:0] result_arith;
    wire [31:0] result_logic;
    wire [31:0] result_shift;
    wire [31:0] result_cmp;
    wire zf, nf, cf, of;

    arithmetic_unit32 u_arith (
        .rs1(rs1), .rs2(rs2), .alu_ctrl(alu_ctrl),
        .result_alu(result_arith), .zero_flag(zf),
        .carry_flag(cf), .negative_flag(nf), .overflow_flag(of)
    );

    logical_unit32 u_logic (
        .rs1(rs1), .rs2(rs2), .alu_ctrl(alu_ctrl),
        .result_alu(result_logic)
    );

    shift_unit32 u_shift (
        .rs1(rs1), .rs2(rs2), .alu_ctrl(alu_ctrl),
        .result_shift(result_shift)
    );

    compare_unit32 u_cmp (
        .rs_1(rs1), .rs_2(rs2), .alu_ctrl(alu_ctrl),
        .result_cmp(result_cmp)
    );

    reg [31:0] result_final;
    always @(*) begin
        case (alu_ctrl)
            4'b0000, 4'b0001, 4'b1010, 4'b1011: result_final = result_arith;
            4'b0010, 4'b0011, 4'b0100:          result_final = result_logic;
            4'b0101, 4'b0110, 4'b0111:          result_final = result_shift;
            4'b1000, 4'b1001:                   result_final = result_cmp;
            default: result_final = 32'b0;
        endcase
    end

    assign alu_result = result_final;
    assign zero_flag = zf;
    assign carry_flag = cf;
    assign negative_flag = nf;
    assign overflow_flag = of;
endmodule


module logical_unit32 (
    input  [31:0] rs1,
    input  [31:0] rs2,
    input  [3:0]  alu_ctrl,
    output reg [31:0] result_alu
);
    always @(*) begin
        case (alu_ctrl)
            4'b0010: result_alu = rs1 & rs2;
            4'b0011: result_alu = rs1 | rs2;
            4'b0100: result_alu = rs1 ^ rs2;
            default: result_alu = 32'b0;
        endcase
    end
endmodule


module shift_unit32 (
    input  [31:0] rs1,
    input  [31:0] rs2,
    input  [3:0]  alu_ctrl,
    output reg [31:0] result_shift
);
    wire [4:0] shamt = rs2[4:0];
    always @(*) begin
        case (alu_ctrl)
            4'b0101: result_shift = rs1 << shamt;
            4'b0110: result_shift = rs1 >> shamt;
            4'b0111: result_shift = $signed(rs1) >>> shamt;
            default: result_shift = 32'b0;
        endcase
    end
endmodule


module arithmetic_unit32 (
    input  [31:0] rs1,
    input  [31:0] rs2,
    input  [3:0]  alu_ctrl,
    output reg [31:0] result_alu,
    output       zero_flag,
    output reg   carry_flag,
    output reg   negative_flag,
    output reg   overflow_flag
);
    wire [32:0] add_ext = {1'b0, rs1} + {1'b0, rs2};
    wire [32:0] sub_ext = {1'b0, rs1} - {1'b0, rs2};

    always @(*) begin
        result_alu = 32'b0;
        carry_flag = 1'b0;
        negative_flag = 1'b0;
        overflow_flag = 1'b0;

        case (alu_ctrl)
            4'b0000: begin
                result_alu = add_ext[31:0];
                carry_flag = add_ext[32];
            end
            4'b0001: begin
                result_alu = sub_ext[31:0];
                carry_flag = sub_ext[32]; // borrow indicator style
            end
            4'b1010: begin
                result_alu = rs2; // LUI expects prepared imm
                carry_flag = 1'b0;
            end
            4'b1011: begin
                result_alu = add_ext[31:0]; // AUIPC: PC+imm expected as inputs
                carry_flag = add_ext[32];
            end
            default: begin
                result_alu = 32'b0;
                carry_flag = 1'b0;
            end
        endcase

        negative_flag = result_alu[31];

        case (alu_ctrl)
            4'b0000: begin
                overflow_flag = (~rs1[31] & ~rs2[31] & result_alu[31]) |
                                ( rs1[31] & rs2[31] & ~result_alu[31]);
            end
            4'b0001: begin
                overflow_flag = ( rs1[31] & ~rs2[31] & ~result_alu[31]) |
                                (~rs1[31] &  rs2[31] &  result_alu[31]);
            end
            default: overflow_flag = 1'b0;
        endcase
    end

    assign zero_flag = (result_alu == 32'b0);
endmodule


module compare_unit32 (
    input  [31:0] rs_1,
    input  [31:0] rs_2,
    input  [3:0]  alu_ctrl,
    output reg [31:0] result_cmp
);
    always @(*) begin
        case (alu_ctrl)
            4'b1000: result_cmp = ($signed(rs_1) < $signed(rs_2)) ? 32'b1 : 32'b0;
            4'b1001: result_cmp = (rs_1 < rs_2) ? 32'b1 : 32'b0;
            default: result_cmp = 32'b0;
        endcase
    end
endmodule



