// -------------------------------
// branch_jump_unit
// -------------------------------
// branch_jump_unit.v
// Evaluates branch/jump conditions in EX stage and produces control-flow outputs
// - Corrected unsigned compare semantics for BLTU / BGEU (borrow interpretation)
// - JAL/JALR target calculation included (JALR result aligned by clearing LSB)

module branch_jump_unit (
    // ---------- Inputs (from ID/EX controls) ----------
    input  wire branch_ex,           // branch instruction?
    input  wire jal_ex,              // JAL?
    input  wire jalr_ex,             // JALR?
    input  wire [2:0] func3_ex,      // branch type (BEQ/BNE/BLT/...)
    input  wire [31:0] pc_ex,        // PC of this instr
    input  wire [31:0] imm_ex,       // branch/jump offset
    input  wire predictedTaken_ex,   // BTB prediction forwarded to EX
    // ---------- From ALU (flags for condition) ----------
    input  wire zero_flag,           // result == 0 (EQ)
    input  wire negative_flag,       // sign bit of result (N)
    input  wire carry_flag,          // carry-out = 1 -> NO borrow for subtraction
    input  wire overflow_flag,       // signed overflow (V)
    input  wire [31:0] op1_forwarded,// forwarded rs1 (for JALR target)
    // ---------- Outputs (to hazard/IF/BTB) ----------
    output wire ex_branch_resolved,  // 1 if branch/jal/jalr in EX
    output wire ex_branch_taken,     // actual outcome (taken = 1)
    output wire ex_predicted_taken,  // forwarded prediction
    output wire modify_pc_ex,        // 1 if mispredict (flush needed)
    output wire [31:0] update_pc_ex, // next PC: target or pc+4
    output wire [31:0] jump_addr_ex, // computed target (for BTB)
    output wire update_btb_ex        // 1 for every resolved control-flow (train)
);

    // Any control-flow instruction resolved in EX
    wire is_branch = branch_ex;
    wire is_jal    = jal_ex;
    wire is_jalr   = jalr_ex;
    wire any_ctrl  = is_branch | is_jal | is_jalr;
    assign ex_branch_resolved = any_ctrl;
    assign ex_predicted_taken = predictedTaken_ex;

    // ----------------------------------------
    // Branch condition evaluation (from ALU flags)
    // For branches we assume ALU performed (rs1 - rs2)
    // ----------------------------------------
    reg branch_cond;
    always @(*) begin
        branch_cond = 1'b0;
        if (is_branch) begin
            case (func3_ex)
                3'b000: branch_cond = zero_flag;                          // BEQ
                3'b001: branch_cond = ~zero_flag;                         // BNE

                // Signed comparisons use N XOR V (standard two's complement)
                3'b100: branch_cond = (negative_flag ^ overflow_flag);    // BLT  (signed <)
                3'b101: branch_cond = ~(negative_flag ^ overflow_flag);   // BGE  (signed >=)

                // Unsigned comparisons: derive from borrow of subtraction rs1 - rs2
                // Note: carry_flag here is the carry-out from (rs1 - rs2) when implemented
                // as an extended subtraction. In that representation:
                //   carry_flag == 1 -> NO borrow (rs1 >= rs2)
                //   carry_flag == 0 -> BORROW occurred (rs1 < rs2)
                // Therefore:
                3'b110: branch_cond = ~carry_flag;                        // BLTU -> taken when borrow (rs1 < rs2)
                3'b111: branch_cond = carry_flag;                         // BGEU -> taken when no borrow (rs1 >= rs2)

                default: branch_cond = 1'b0;
            endcase
        end
    end

    // JAL/JALR are always taken control-flow transfers
    wire jump_taken = is_jal | is_jalr;
    wire actual_taken = is_branch ? branch_cond : (jump_taken ? 1'b1 : 1'b0);
    assign ex_branch_taken = actual_taken;

    // ----------------------------------------
    // Target calculation
    // - Branch/JAL: pc + imm
    // - JALR: (rs1 + imm) with LSB cleared (RISC-V spec)
    // Use forwarded rs1 for JALR target calculation.
    // ----------------------------------------
    wire [31:0] target_branch_jal = pc_ex + imm_ex;
    wire [31:0] target_jalr       = (op1_forwarded + imm_ex) & 32'hFFFFFFFE; // align LSB = 0
    wire [31:0] computed_target = is_jalr ? target_jalr :
                                  is_jal  ? target_branch_jal :
                                            target_branch_jal;
    assign jump_addr_ex = computed_target;

    // ----------------------------------------
    // Mispredict detection and next-PC selection
    // - Mispredict if actual outcome != prediction
    // - When mispredict: next PC = computed target (if actually taken) else pc+4
    // - When no mispredict: next PC defaults to pc+4 (IF can use BTB/prediction otherwise)
    // ----------------------------------------
    wire [31:0] pc_plus_4 = pc_ex + 32'd4;
    wire mispredict = (actual_taken ^ predictedTaken_ex);
    assign modify_pc_ex = mispredict;
    assign update_pc_ex = mispredict ? (actual_taken ? computed_target : pc_plus_4) : pc_plus_4;

    // Train BTB/predictor on every resolved control-flow (branch/jal/jalr)
    assign update_btb_ex = any_ctrl;

endmodule
