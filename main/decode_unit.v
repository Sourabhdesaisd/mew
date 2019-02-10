module decode_unit (
    input  wire [31:0] instruction_in,
    input  wire        id_flush,        // when asserted, treat instruction as NOP (all zeros)
    output wire [6:0]  opcode,
    output wire [2:0]  func3,
    output wire [6:0]  func7,
    output wire [4:0]  rd,
    output wire [4:0]  rs1,
    output wire [4:0]  rs2,
    output reg  [31:0] imm_out
);
    // Select either real instruction or zero when flushed
    wire [31:0] instr = id_flush ? 32'h00000000 : instruction_in;

    // Field extraction (combinational)
    assign opcode = instr[6:0];
    assign rd     = instr[11:7];
    assign func3  = instr[14:12];
    assign rs1    = instr[19:15];
    assign rs2    = instr[24:20];
    assign func7  = instr[31:25];

    // Immediate generation
    always @(*) begin
        case (opcode)
            // I-type (includes arithmetic immediates) and loads (I-format) and JALR
            7'b0010011, 7'b0000011, 7'b1100111: begin
                imm_out = {{20{instr[31]}}, instr[31:20]};
            end

            // S-type (store): imm[11:5]=instr[31:25], imm[4:0]=instr[11:7]
            7'b0100011: begin
                imm_out = {{20{instr[31]}}, instr[31:25], instr[11:7]};
            end

            // B-type (branch): imm = {instr[31], instr[7], instr[30:25], instr[11:8], 1'b0}
            7'b1100011: begin
                imm_out = {{19{instr[31]}}, instr[31], instr[7], instr[30:25], instr[11:8], 1'b0};
            end

            // J-type (JAL): imm = {instr[31], instr[19:12], instr[20], instr[30:21], 1'b0}
            7'b1101111: begin
                imm_out = {{11{instr[31]}}, instr[31], instr[19:12], instr[20], instr[30:21], 1'b0};
            end

            // U-type (LUI/AUIPC): imm = instr[31:12] << 12
            7'b0110111, 7'b0010111: begin
                imm_out = {instr[31:12], 12'b0};
            end

            // Default (R-type or unknown)
            default: begin
                imm_out = 32'h00000000;
            end
        endcase
    end
endmodule


