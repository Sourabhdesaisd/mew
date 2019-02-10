
`ifndef STRONG_NOT_TAKEN
`define STRONG_NOT_TAKEN 2'b00
`define WEAK_NOT_TAKEN   2'b01
`define WEAK_TAKEN       2'b10
`define STRONG_TAKEN     2'b11
`endif
/*
// -----------------------------------------------------------------------------
// pc - simple PC register (async reset)
// -----------------------------------------------------------------------------
module pc (
    input  wire        clk,
    input  wire        rst,      // active-high asynchronous reset
    input  wire [31:0] next_pc,
    input  wire        pc_en,    // enable update (for stalls)
    output reg  [31:0] pc
);
    always @(posedge clk or posedge rst) begin
        if (rst) pc <= 32'h00000000;
        else if (pc_en) pc <= next_pc;
        // else hold (stall)
    end
endmodule

// -----------------------------------------------------------------------------
// pc_update - choose next PC from EX override, BTB prediction, or pc+4
// -----------------------------------------------------------------------------
module pc_update(
    input wire [31:0] pc,
    input wire [31:0] pc_jump_addr, // jump target computed in EX (override)
    input wire [31:0] btb_target_pc, // BTB predicted target
    input wire btb_pc_valid, // BTB has a valid entry for this PC
    input wire btb_pc_predictTaken, // BTB prediction: taken?
    input wire jump_en, // EX indicates an immediate override (e.g., resolved taken)
    output reg [31:0] next_pc
);
    // Selection priority:
    // 1) EX override (jump_en) -> pc_jump_addr
    // 2) BTB predicted taken -> btb_target_pc
    // 3) Default sequential PC+4
    wire [31:0] pc_plus_4 = pc + 32'h4;
    always @(*) begin
        if (jump_en) next_pc = pc_jump_addr;
        else if (btb_pc_valid && btb_pc_predictTaken) next_pc = btb_target_pc;
        else next_pc = pc_plus_4;
    end
endmodule
// -----------------------------------------------------------------------------
// if_stage_complex_btb - IF stage with BTB lookup + next PC selection
// -----------------------------------------------------------------------------
module if_stage_complex_btb (
    input wire clk,
    input wire rst,
    // Hazard unit control
    input wire pc_en, // allow updating PC
    input wire if_id_en, // allow IF/ID latch (unused inside IF stage, forwarded by top)
    input wire if_id_flush, // flush IF/ID pipeline reg (unused inside IF stage, forwarded by top)
    // From EX stage for immediate resolution / updates
    input wire modify_pc_ex, // EX indicates an immediate override (e.g., branch taken/mispredict)
    input wire [31:0] update_pc_ex, // corrected PC from EX (override next PC)
    input wire [31:0] pc_ex, // branch PC from EX (for BTB update index/tag)
    input wire [31:0] jump_addr_ex, // computed target from EX (for BTB update_target)
    input wire update_btb_ex, // update BTB on resolved control-flow
    // IF outputs
    output [31:0] pc_if,
    output wire [31:0] instr_if,
    output wire predictedTaken_if,
    output wire [31:0] predictedTarget_if
);
    // -------------------------------------------------------------
    // 1) PC REGISTER
    // -------------------------------------------------------------
    wire [31:0] pc_next;
    reg [31:0] pc_reg;
    always @(posedge clk or posedge rst) begin
        if (rst)
            pc_reg <= 32'h0000_0000;
        else if (pc_en)
            pc_reg <= pc_next;
        // else hold
    end
    assign pc_if = pc_reg;

    // -------------------------------------------------------------
    // 2) COMPLEX BTB LOOKUP (read-only from IF)
    // -------------------------------------------------------------
    wire [31:0] btb_target;
    wire btb_valid;
    wire btb_predictedTaken;

    // The btb module performs read using pc_reg and may accept update inputs from EX stage.
    btb u_btb (
        .clk(clk),
        .rst(rst),
        .pc(pc_reg),
        .update_pc(pc_ex),         // branch PC (for update index/tag)
        .update(update_btb_ex),    // update request from EX
        .update_target(jump_addr_ex),
        .mispredicted(1'b0),       // pass-through placeholder; BTB internal FSM uses provided signals during update path
        .target_pc(btb_target),
        .valid(btb_valid),
        .predictedTaken(btb_predictedTaken)
    );

    assign predictedTaken_if = btb_predictedTaken & btb_valid;
    assign predictedTarget_if = (predictedTaken_if ? btb_target : pc_reg + 32'd4);

    // -------------------------------------------------------------
    // 3) Next-PC selection using pc_update module
    //    - If EX requests immediate override (modify_pc_ex) -> use update_pc_ex
    //    - Else if BTB predicts taken -> use btb_target
    //    - Else -> pc+4
    // -------------------------------------------------------------
    wire [31:0] pc_jump_addr = update_pc_ex;
    wire jump_en = modify_pc_ex;
    pc_update u_pcupdate (
        .pc(pc_reg),
        .pc_jump_addr(pc_jump_addr),
        .btb_target_pc(btb_target),
        .btb_pc_valid(btb_valid),
        .btb_pc_predictTaken(btb_predictedTaken),
        .jump_en(jump_en),
        .next_pc(pc_next)
    );

    // -------------------------------------------------------------
    // 4) Instruction Memory
    // -------------------------------------------------------------
    inst_mem u_imem (
        .pc(pc_reg),
        .read_en(1'b1),
        .instruction(instr_if)
    );
endmodule

*/

// -----------------------------------------------------------------------------
// inst_mem// -----------------------------------------------------------------------------
module inst_mem (
    input  wire [31:0] pc,       // byte address
    input  wire        read_en,  // ignored (always read in IF-stage), kept for API consistency
    output wire [31:0] instruction
);
    // Simple small instruction memory (256 x 32-bit words)
    reg [31:0] mem [0:255];

    initial begin
        
        $readmemh("instructions.hex", mem);
    end

    
    assign instruction = mem[pc[11:2]];
endmodule


module pc (
    input  wire        clk,
    input  wire        rst,      // active-high async reset
    input  wire [31:0] next_pc,
    input  wire        pc_en,    // enable update (for stall)
    output reg  [31:0] pc
);
    always @(posedge clk or posedge rst) begin
        if (rst)
            pc <= 32'h0000_0000;
        else if (pc_en)
            pc <= next_pc;
        // else hold (stall)
    end
endmodule

module pc_update(
    input wire [31:0] pc,
    input wire [31:0] pc_jump_addr,      // EX override target
    input wire [31:0] btb_target_pc,     // BTB predicted target
    input wire        btb_pc_valid,      // BTB hit
    input wire        btb_pc_predictTaken, // BTB predicted taken
    input wire        jump_en,           // EX override enable (actual_taken)
    output reg [31:0] next_pc
);

    wire [31:0] pc_plus_4 = pc + 32'h4;

    always @(*) begin
        // Priority:
        // 1) EX override (resolved taken or mispredict correction)
        if (jump_en)
            next_pc = pc_jump_addr;

        // 2) BTB predicted taken
        else if (btb_pc_valid && btb_pc_predictTaken)
            next_pc = btb_target_pc;

        // 3) default sequential
        else
            next_pc = pc_plus_4;
    end
endmodule

// -----------------------------------------------------------------------------
// IF stage with integrated BTB prediction + EX override support
// -----------------------------------------------------------------------------
module if_stage_complex_btb (
    input wire clk,
    input wire rst,

    // Hazard controls
    input wire pc_en,
    input wire if_id_en,       // (unused here, forwarded to pipeline)
    input wire if_id_flush,    // (unused here, forwarded to pipeline)

    // EX stage update / override signals
    input wire        modify_pc_ex,    // actual_taken (branch/jump resolved taken)
    input wire [31:0] update_pc_ex,    // corrected PC from EX
    input wire [31:0] pc_ex,           // original PC of branch (for BTB update)
    input wire [31:0] jump_addr_ex,    // resolved branch/jump target
    input wire        update_btb_ex,   // BTB update enable (branch resolved)

    // IF outputs
    output      [31:0] pc_if,
    output wire [31:0] instr_if,
    output wire        predictedTaken_if,
    output wire [31:0] predictedTarget_if
);

    // ============================================================
    // 1) PC REGISTER
    // ============================================================
    reg  [31:0] pc_reg;
    wire [31:0] pc_next;

    always @(posedge clk or posedge rst) begin
        if (rst)
            pc_reg <= 32'h00000000;
        else if (pc_en)
            pc_reg <= pc_next;
        // else hold for stall
    end

    assign pc_if = pc_reg;

    // ============================================================
    // 2) BTB READ + UPDATE
    // ============================================================
    wire [31:0] btb_target;
    wire        btb_valid;
    wire        btb_predictedTaken;

    btb u_btb (
        .clk(clk),
        .rst(rst),

        // ----- READ -----
        .pc(pc_reg),

        // ----- UPDATE -----
        .update_pc(pc_ex),           // PC of resolved branch
        .update(update_btb_ex),      // update enable
        .update_taken(modify_pc_ex), // ACTUAL branch outcome (correct)
        .update_target(jump_addr_ex),

        // ----- OUTPUT -----
        .target_pc(btb_target),
        .valid(btb_valid),
        .predictedTaken(btb_predictedTaken)
    );

    assign predictedTaken_if  = btb_valid && btb_predictedTaken;
    assign predictedTarget_if = predictedTaken_if ? btb_target : pc_reg + 32'd4;

    // ============================================================
    // 3) NEXT PC SELECTION (PC UPDATE LOGIC)
    // ============================================================
    pc_update u_pcupdate (
        .pc(pc_reg),
        .pc_jump_addr(update_pc_ex),     // EX override target
        .btb_target_pc(btb_target),
        .btb_pc_valid(btb_valid),
        .btb_pc_predictTaken(btb_predictedTaken),
        .jump_en(modify_pc_ex),          // EX override enable
        .next_pc(pc_next)
    );

    // ============================================================
    // 4) INSTRUCTION MEMORY
    // ============================================================
    inst_mem u_imem (
        .pc(pc_reg),
        .read_en(1'b1),
        .instruction(instr_if)
    );

endmodule


// -----------------------------------------------------------------------------
// dynamic_branch_predictor - 2-bit saturating counter update
// -----------------------------------------------------------------------------
module dynamic_branch_predictor(
    input  [1:0] current_state,
    input        actual_taken,     // corrected input name
    output reg [1:0] next_state
);

    always @(*) begin
        if (actual_taken) begin
            case (current_state)
                2'b00: next_state = 2'b01; // SN -> WN
                2'b01: next_state = 2'b10; // WN -> WT
                2'b10: next_state = 2'b11; // WT -> ST
                2'b11: next_state = 2'b11; // ST -> ST
                default: next_state = 2'b01;
            endcase
        end else begin
            case (current_state)
                2'b00: next_state = 2'b00; // SN -> SN
                2'b01: next_state = 2'b00; // WN -> SN
                2'b10: next_state = 2'b01; // WT -> WN
                2'b11: next_state = 2'b10; // ST -> WT
                default: next_state = 2'b01;
            endcase
        end
    end

endmodule
module btb_write(
    input  [127:0] update_set,
    input  [7:0]   LRU,
    input  [26:0]  update_tag,
    input  [2:0]   update_index,
    input  [31:0]  update_target,
    input          update_taken,        // corrected signal name
    output [127:0] write_set,
    output         next_LRU_write
);

    // Extract ways
    wire [63:0] way0 = update_set[127:64];
    wire [63:0] way1 = update_set[63:0];

    wire valid0 = way0[63];
    wire valid1 = way1[63];

    wire [26:0] tag0 = way0[62:36];
    wire [26:0] tag1 = way1[62:36];

    wire [31:0] tgt0 = way0[35:4];
    wire [31:0] tgt1 = way1[35:4];

    wire [1:0] state0 = way0[3:2];
    wire [1:0] state1 = way1[3:2];

    wire hit0 = valid0 && (tag0 == update_tag);
    wire hit1 = valid1 && (tag1 == update_tag);
    wire entry_exists = hit0 || hit1;

    // LRU selection
    wire lru_bit = LRU[update_index];     // 0 = way0 LRU, 1 = way1 LRU

    wire insert0 = entry_exists ? hit0 : (lru_bit == 1'b0);
    wire insert1 = entry_exists ? hit1 : (lru_bit == 1'b1);

    // Predictor FSMs
    wire [1:0] next_state0, next_state1;

    dynamic_branch_predictor p0(
        .current_state(entry_exists ? state0 : 2'b01),   // init = weakly not taken
        .actual_taken(update_taken),
        .next_state(next_state0)
    );

    dynamic_branch_predictor p1(
        .current_state(entry_exists ? state1 : 2'b01),
        .actual_taken(update_taken),
        .next_state(next_state1)
    );

    // Select write state
    wire [1:0] write_state0 = insert0 ? next_state0 : state0;
    wire [1:0] write_state1 = insert1 ? next_state1 : state1;

    // Correct target update rule (match Code-B)
    wire [31:0] write_tgt0 = insert0 ?
                                (update_taken ? update_target : (update_index * 4)) :
                                tgt0;

    wire [31:0] write_tgt1 = insert1 ?
                                (update_taken ? update_target : (update_index * 4)) :
                                tgt1;

    // Form 64-bit entries (removed padding bits!)
    wire [63:0] new_way0 =
        { (valid0 | insert0),
          update_tag,
          write_tgt0,
          write_state0 };

    wire [63:0] new_way1 =
        { (valid1 | insert1),
          update_tag,
          write_tgt1,
          write_state1 };

    assign write_set = { new_way0, new_way1 };

    // Replacement policy
    assign next_LRU_write = entry_exists ? lru_bit : insert1;

endmodule
module btb_file (
    input  wire        clk,
    input  wire        rst,
    input  wire [2:0]  read_index,
    input  wire [2:0]  update_index,
    input  wire [2:0]  write_index,
    input  wire [127:0] write_set,
    input  wire        write_en,

    output wire [127:0] read_set,
    output wire [127:0] update_set
);

    // 8 sets × 128-bit entries
    reg [127:0] file [0:7];
    integer i;

    // Synchronous write + synchronous reset
    always @(posedge clk) begin
        if (rst) begin
            // NOTE: pure Verilog increment: i = i + 1
            for (i = 0; i < 8; i = i + 1)
                file[i] <= 128'h0;
        end 
        else if (write_en) begin
            file[write_index] <= write_set;
        end
    end

    // Read operations (combinational)
    assign update_set = file[update_index];

    // Read-forwarding to prevent hazards
    assign read_set = (write_en && (write_index == read_index)) ?
                        write_set :
                        file[read_index];

endmodule
module btb_read(
    input  [127:0] read_set,
    input  [7:0]   LRU,
    input  [26:0]  read_tag,
    input  [2:0]   read_index,

    output         next_LRU_read,
    output         valid,
    output         predictedTaken,
    output [31:0]  target
);

    wire [63:0] way0 = read_set[127:64];
    wire [63:0] way1 = read_set[63:0];

    wire valid0 = way0[63];
    wire valid1 = way1[63];

    wire [26:0] tag0 = way0[62:36];
    wire [26:0] tag1 = way1[62:36];

    wire [31:0] tgt0 = way0[35:4];
    wire [31:0] tgt1 = way1[35:4];

    wire [1:0] state0 = way0[3:2];
    wire [1:0] state1 = way1[3:2];

    wire hit0 = valid0 && (tag0 == read_tag);
    wire hit1 = valid1 && (tag1 == read_tag);

    assign valid = hit0 || hit1;
    assign target = hit0 ? tgt0 : tgt1;
    assign predictedTaken = hit0 ? state0[1] :
                            hit1 ? state1[1] : 1'b0;

    // LRU update on read hit
    wire curr_lru = LRU[read_index];
    assign next_LRU_read = valid ? hit1 : curr_lru;

endmodule
module btb(
    input clk,
    input rst,
    input [31:0] pc,
    input [31:0] update_pc,
    input        update,
    input        update_taken,
    input [31:0] update_target,

    output [31:0] target_pc,
    output        valid,
    output        predictedTaken
);

    wire [2:0] read_index = pc[4:2];
    wire [26:0] read_tag = pc[31:5];

    wire [2:0] update_index = update_pc[4:2];
    wire [26:0] update_tag  = update_pc[31:5];

    wire [127:0] read_set, update_set, write_set;

    // LRU
    wire [7:0] LRU, next_LRU;
    wire next_lru_read, next_lru_write;

    // LRU register
    lru_reg lru_reg_inst(
        .clk(clk),
        .rst(rst),
        .LRU_updated(next_LRU),
        .LRU(LRU)
    );

    // BTB file
    btb_file btb_file_inst(
        .clk(clk),
        .rst(rst),
        .read_index(read_index),
        .update_index(update_index),
        .write_index(update_index),
        .write_set(write_set),
        .write_en(update),
        .read_set(read_set),
        .update_set(update_set)
    );

    // READ
    btb_read btb_read_inst(
        .read_set(read_set),
        .LRU(LRU),
        .read_tag(read_tag),
        .read_index(read_index),
        .next_LRU_read(next_lru_read),
        .valid(valid),
        .predictedTaken(predictedTaken),
        .target(target_pc)
    );

    // WRITE
    btb_write btb_write_inst(
        .update_set(update_set),
        .LRU(LRU),
        .update_tag(update_tag),
        .update_index(update_index),
        .update_target(update_target),
        .update_taken(update_taken),
        .write_set(write_set),
        .next_LRU_write(next_lru_write)
    );

    // LRU update
    lru_next lru_next_inst(
        .index(read_index),
        .update_index(update_index),
        .update_lru_read(next_lru_read),
        .update_lru_write(next_lru_write),
        .valid(valid),
        .update(update),
        .LRU(LRU),
        .next_LRU(next_LRU)
    );

endmodule




/*
// -----------------------------------------------------------------------------
// btb_file - memory array for BTB sets (synchronous write, combinational read)
// -----------------------------------------------------------------------------
module btb_file (
    input clk,
    input rst,                 // new reset input
    input [2:0] read_index,    // 2^3 = 8 sets
    input [2:0] update_index,
    input [2:0] write_index,
    input [127:0] write_set,
    input write_en,

    output wire [127:0] read_set,
    output wire [127:0] update_set
);
    reg [127:0] file [7:0];
    integer i;

    // synchronous reset + write
    always @(posedge clk) begin
        if (rst) begin
            for (i = 0; i < 8; i = i + 1)
                file[i] <= 128'h0;
        end else begin
            if (write_en) begin
                file[write_index] <= write_set;
            end
        end
    end

    // Read operation (combinational read)
    assign update_set = file[update_index];

    // Forwarding: if reading the same index being written this cycle, forward write_set
    assign read_set = ((read_index == write_index) && write_en) ? write_set : file[read_index];

endmodule

// -----------------------------------------------------------------------------
// btb_write - prepare a 128-bit set to write into BTB file (EX stage helper)
// -----------------------------------------------------------------------------
module btb_write(
    input [127:0] update_set,
    input [7:0] LRU,
    input [26:0] update_tag,
    input [2:0] update_index,
    input [31:0] update_target,
    input mispredicted,
    output [127:0] write_set,
    output next_LRU_write
);
    // EX Stage operations
    wire current_LRU_write;
    // Extract Signals from Set
    wire [63:0] branch1, branch2;
    wire valid1, valid2;
    wire [26:0] tag1, tag2;
    wire [31:0] target1, target2;
    wire [1:0] state1, state2;
    // Final write signals to put into BTB
    wire write_valid1, write_valid2;
    wire [26:0] write_tag1, write_tag2;
    wire [31:0] write_target1, write_target2;
    // Check for each branch in set
    wire check_branch1, check_branch2;
    wire entry_exists;
    // Insert data branches
    wire insert_branch1, insert_branch2;
    // Current state of branches to consider
    wire [1:0] current_state_branch1, current_state_branch2;
    // Next state of branches
    wire [1:0] next_state_branch1, next_state_branch2;
    wire [1:0] write_state1, write_state2;

    assign branch1 = update_set[127:64];
    assign branch2 = update_set[63:0];

    assign valid1 = branch1[63];
    assign valid2 = branch2[63];

    assign tag1 = branch1[62:36];
    assign tag2 = branch2[62:36];

    assign target1 = branch1[35:4];
    assign target2 = branch2[35:4];

    assign state1 = branch1[3:2];
    assign state2 = branch2[3:2];

    assign check_branch1 = valid1 && (update_tag == tag1);
    assign check_branch2 = valid2 && (update_tag == tag2);

    assign entry_exists = check_branch1 || check_branch2;

    // Read the LRU bit for this set
    assign current_LRU_write = LRU[update_index];

    // Decide which slot to insert/update
    assign insert_branch1 = entry_exists ? check_branch1 : current_LRU_write;
    assign insert_branch2 = entry_exists ? check_branch2 : !current_LRU_write;

    assign write_valid1 = valid1 || insert_branch1;
    assign write_valid2 = valid2 || insert_branch2;

    assign write_tag1 = insert_branch1 ? update_tag : tag1;
    assign write_tag2 = insert_branch2 ? update_tag : tag2;

    assign write_target1 = insert_branch1 ? update_target : target1;
    assign write_target2 = insert_branch2 ? update_target : target2;

    // If entry new -> initialize with not-taken strong; otherwise use existing state
    assign current_state_branch1 = entry_exists ? state1 : `STRONG_NOT_TAKEN;
    assign current_state_branch2 = entry_exists ? state2 : `STRONG_NOT_TAKEN;

    // Use dynamic predictor FSM - NOTE: port 'mispredicted' is used here as the
    // source of actual outcome (1 = taken, 0 = not taken). Upstream must supply
    // actual outcome for correct updates (see changelog).
    dynamic_branch_predictor fsm_branch1(
        .current_state(current_state_branch1),
        .mispredicted(mispredicted),
        .next_state(next_state_branch1)
    );
    dynamic_branch_predictor fsm_branch2(
        .current_state(current_state_branch2),
        .mispredicted(mispredicted),
        .next_state(next_state_branch2)
    );

    assign write_state1 = insert_branch1 ? next_state_branch1 : state1;
    assign write_state2 = insert_branch2 ? next_state_branch2 : state2;

    // Form the 128-bit set to write back
    assign write_set = { write_valid1, write_tag1, write_target1, write_state1, 2'b00,
                         write_valid2, write_tag2, write_target2, write_state2, 2'b00};

    // Next LRU: if entry exists keep same LRU, else mark the other way
    assign next_LRU_write = entry_exists ? current_LRU_write : insert_branch2;
endmodule
/*
  // -----------------------------------------------------------------------------
// btb_write - prepare a 128-bit set to write into BTB file (EX stage helper)
// -----------------------------------------------------------------------------
module btb_write(
    input [127:0] update_set,
    input [7:0] LRU,
    input [26:0] update_tag,
    input [2:0] update_index,
    input [31:0] update_target,
    input actual_taken,  // Renamed from 'mispredicted' for clarity: 1=taken, 0=not-taken (actual outcome)
    output [127:0] write_set,
    output next_LRU_write
);
    // EX Stage operations
    wire current_LRU_write;
    // Extract Signals from Set
    wire [63:0] branch1, branch2;
    wire valid1, valid2;
    wire [26:0] tag1, tag2;
    wire [31:0] target1, target2;
    wire [1:0] state1, state2;
    // Final write signals to put into BTB
    wire write_valid1, write_valid2;
    wire [26:0] write_tag1, write_tag2;
    wire [31:0] write_target1, write_target2;
    // Check for each branch in set
    wire check_branch1, check_branch2;
    wire entry_exists;
    // Insert data branches
    wire insert_branch1, insert_branch2;
    // Current state of branches to consider
    wire [1:0] current_state_branch1, current_state_branch2;
    // Next state of branches
    wire [1:0] next_state_branch1, next_state_branch2;
    wire [1:0] write_state1, write_state2;

    assign branch1 = update_set[127:64];
    assign branch2 = update_set[63:0];

    assign valid1 = branch1[63];
    assign valid2 = branch2[63];

    assign tag1 = branch1[62:36];
    assign tag2 = branch2[62:36];

    assign target1 = branch1[35:4];
    assign target2 = branch2[35:4];

    assign state1 = branch1[3:2];
    assign state2 = branch2[3:2];

    assign check_branch1 = valid1 && (update_tag == tag1);
    assign check_branch2 = valid2 && (update_tag == tag2);

    assign entry_exists = check_branch1 || check_branch2;

    // Read the LRU bit for this set
    assign current_LRU_write = LRU[update_index];

    // Decide which slot to insert/update
    assign insert_branch1 = entry_exists ? check_branch1 : current_LRU_write;
    assign insert_branch2 = entry_exists ? check_branch2 : !current_LRU_write;

    assign write_valid1 = valid1 || insert_branch1;
    assign write_valid2 = valid2 || insert_branch2;

    assign write_tag1 = insert_branch1 ? update_tag : tag1;
    assign write_tag2 = insert_branch2 ? update_tag : tag2;

    assign write_target1 = insert_branch1 ? update_target : target1;
    assign write_target2 = insert_branch2 ? update_target : target2;

    // If entry new -> initialize with not-taken strong; otherwise use existing state
    assign current_state_branch1 = entry_exists ? state1 : `STRONG_NOT_TAKEN;
    assign current_state_branch2 = entry_exists ? state2 : `STRONG_NOT_TAKEN;

    // Use dynamic predictor FSM - NOTE: input 'actual_taken' is the actual branch outcome (1 = taken, 0 = not taken).
    // Upstream must supply actual outcome for correct updates.
    dynamic_branch_predictor fsm_branch1(
        .current_state(current_state_branch1),
        .actual_taken(actual_taken),  // Renamed input for clarity
        .next_state(next_state_branch1)
    );
    dynamic_branch_predictor fsm_branch2(
        .current_state(current_state_branch2),
        .actual_taken(actual_taken),
        .next_state(next_state_branch2)
    );

    assign write_state1 = insert_branch1 ? next_state_branch1 : state1;
    assign write_state2 = insert_branch2 ? next_state_branch2 : state2;

    // Form the 128-bit set to write back
    assign write_set = { write_valid1, write_tag1, write_target1, write_state1, 2'b00,
                         write_valid2, write_tag2, write_target2, write_state2, 2'b00};

    // Next LRU: Mark the other way as LRU (promotes accessed/inserted slot to MRU)
    // Works for both hit (insert_branch2 = check_branch2) and miss (!current_LRU_write)
    assign next_LRU_write = insert_branch2;
endmodule //
// -----------------------------------------------------------------------------
// btb_read - decode a 128-bit set into outputs for IF stage
// -----------------------------------------------------------------------------
module btb_read(
    input [127:0] read_set,
    input [7:0] LRU,
    input [26:0] read_tag,
    input [2:0] read_index,
    output next_LRU_read,
    output valid,
    output predictedTaken,
    output [31:0] target
);
    wire current_LRU_read;

    wire [63:0] branch1, branch2;
    wire valid1, valid2;
    wire [26:0] tag1, tag2;
    wire [31:0] target1, target2;
    wire [1:0] state1, state2;

    wire check_branch1, check_branch2;
    wire [1:0] current_state;

    assign branch1 = read_set[127:64];
    assign branch2 = read_set[63:0];

    assign valid1 = branch1[63];
    assign valid2 = branch2[63];

    assign tag1 = branch1[62:36];
    assign tag2 = branch2[62:36];

    assign target1 = branch1[35:4];
    assign target2 = branch2[35:4];

    assign state1 = branch1[3:2];
    assign state2 = branch2[3:2];

    assign check_branch1 = valid1 && (read_tag == tag1);
    assign check_branch2 = valid2 && (read_tag == tag2);

    assign valid = check_branch1 || check_branch2;

    assign target = check_branch1 ? target1 : target2;

    assign current_state = check_branch1 ? state1 : (
                           check_branch2 ? state2 : `STRONG_NOT_TAKEN);

    assign predictedTaken = current_state[0];

    assign current_LRU_read = LRU[read_index];
    assign next_LRU_read = valid ? check_branch2 : current_LRU_read;
    
endmodule

// -----------------------------------------------------------------------------
// lru_reg - hold LRU byte vector across cycles
// -----------------------------------------------------------------------------
module lru_reg(
    input clk,
    input rst,
    input [7:0] LRU_updated,

    output reg [7:0] LRU
);

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            LRU <= 8'h00; // Reset LRU to 0
        end else begin
            LRU <= LRU_updated;
        end
    end

endmodule

// -----------------------------------------------------------------------------
// lru_next - compute next LRU vector when a read/write occurs
// -----------------------------------------------------------------------------
module lru_next(
    input [2:0] index,
    input [2:0] update_index,
    input update_lru_read,
    input update_lru_write,
    input valid,
    input update,
    input [7:0] LRU,
    output reg [7:0] next_LRU
);
    reg [7:0] read_mask;
    reg [7:0] write_mask;
    reg [7:0] update_mask;
    reg [7:0] update_bits;

    always @* begin
        read_mask   = (8'b00000001 << index);
        write_mask  = (8'b00000001 << update_index);

        update_mask = read_mask | write_mask;

        update_bits = (update_lru_read  && valid  ? read_mask  : 8'b00000000)
                    | (update_lru_write && update ? write_mask : 8'b00000000);

        next_LRU = (LRU & ~update_mask) | update_bits;
    end

endmodule 

// -----------------------------------------------------------------------------
// lru_next - compute next LRU vector when a read/write occurs
// -----------------------------------------------------------------------------
module lru_next(
    input [2:0] index,
    input [2:0] update_index,
    input update_lru_read,
    input update_lru_write,
    input valid,
    input update,
    input [7:0] LRU,
    output reg [7:0] next_LRU
);
    reg [7:0] read_mask;
    reg [7:0] write_mask;
    reg [7:0] update_mask;
    reg [7:0] update_bits;

    always @* begin
        read_mask   = (8'b00000001 << index);
        write_mask  = (8'b00000001 << update_index);

        update_mask = read_mask | write_mask;

        // Prioritize write over read: if write update applies, use write_mask value;
        // else use read_mask if applicable. Avoids OR conflict on same index.
        update_bits = 8'b00000000;
        if (update_lru_write && update) begin
            update_bits = write_mask;
        end else if (update_lru_read && valid) begin
            update_bits = read_mask;
        end

        next_LRU = (LRU & ~update_mask) | update_bits;
    end

endmodule

// -----------------------------------------------------------------------------
// dynamic_branch_predictor - 2-bit saturating counter update (safe/fixed)
// -----------------------------------------------------------------------------
module dynamic_branch_predictor(
    input [1:0] current_state,
    // NOTE: upstream modules currently connect `mispredicted` to this port.
    // For correct predictor behavior this port MUST be the actual branch outcome:
    //   1 = actual TAKEN, 0 = actual NOT TAKEN
    input mispredicted,
    output reg [1:0] next_state
);
    wire actual_taken = mispredicted; // interpret input as actual outcome
    always @(*) begin
        if (actual_taken) begin
            // increment towards taken with saturation
            case (current_state)
                2'b00: next_state = 2'b01;
                2'b01: next_state = 2'b10;
                2'b10: next_state = 2'b11;
                2'b11: next_state = 2'b11;
                default: next_state = current_state;
            endcase
        end else begin
            // decrement towards not-taken with saturation
            case (current_state)
                2'b00: next_state = 2'b00;
                2'b01: next_state = 2'b00;
                2'b10: next_state = 2'b01;
                2'b11: next_state = 2'b10;
                default: next_state = current_state;
            endcase
        end
    end
endmodule

// -----------------------------------------------------------------------------
// btb - top-level BTB wrapper (read + delayed write)
// -----------------------------------------------------------------------------
module btb(
    input clk,
    input rst,
    input [31:0] pc,
    input [31:0] update_pc,
    input update,
    
    input [31:0] update_target,
    input mispredicted,

    output [31:0] target_pc,
    output valid,
    output predictedTaken
);

    // Read Signals
    wire [2:0] read_index;
    wire [26:0] read_tag;
    wire [127:0] read_set;

    // Update Signals
    wire [2:0] update_index;
    wire [26:0] update_tag;
    wire [127:0] update_set;  
    wire [127:0] write_set;

    // LRU Signals
    wire [7:0] LRU, next_LRU;
    wire next_LRU_read;
    wire next_LRU_write;

    // Added a cycle delay in update signal
    reg reg_file_write;
    reg [127:0] reg_write_set;
    reg [2:0] reg_write_index;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            reg_file_write <= 0;
            reg_write_set <= 0;
            reg_write_index <= 0;
        end else begin
            reg_file_write <= update;  // delayed by 1 cycle
            reg_write_set <= write_set;
            reg_write_index <= update_index;
        end
    end

    // PC (32 bits) = Tag (27 bits) + Index (3 bits) + Byte offset (2 bits)
    assign read_index = pc[4:2];
    assign read_tag = pc[31:5];

    assign update_index = update_pc[4:2];
    assign update_tag = update_pc[31:5];

    lru_reg lru_reg_inst(
        .clk(clk),
        .rst(rst),
        .LRU_updated(next_LRU),
        .LRU(LRU)
    );

    btb_file btb_file_inst(
        .clk(clk),
        .rst(rst),
        .read_index(read_index),
        .update_index(update_index),
        .write_index(reg_write_index),
        .write_set(reg_write_set),
        .write_en(reg_file_write),
        .read_set(read_set),
        .update_set(update_set)
    );

    btb_read btb_read_inst(
        .read_set(read_set),
        .LRU(LRU),
        .read_tag(read_tag),
        .read_index(read_index),
        .next_LRU_read(next_LRU_read),
        .valid(valid),
        .predictedTaken(predictedTaken),
        .target(target_pc)
    );

    btb_write btb_write_inst(
        .update_set(update_set),
        .LRU(LRU),
        .update_tag(update_tag),
        .update_index(update_index),
        .update_target(update_target),
        .mispredicted(mispredicted),
        .write_set(write_set),
        .next_LRU_write(next_LRU_write)
    );

    lru_next lru_next_inst(
        .index(read_index),
        .update_index(update_index),
        .update_lru_read(next_LRU_read),
        .update_lru_write(next_LRU_write),
        .valid(valid),
        .update(update),
        .LRU(LRU),
        .next_LRU(next_LRU)
    );

endmodule
*/

/*


// Testbench for pc module
// Tests: Reset, PC update on enable, hold on stall

module tb_pc;
    reg clk;
    reg rst;
    reg [31:0] next_pc;
    reg pc_en;
    wire [31:0] pc;

    // Instantiate DUT
    pc dut (
        .clk(clk),
        .rst(rst),
        .next_pc(next_pc),
        .pc_en(pc_en),
        .pc(pc)
    );

    // Clock generation
    always #5 clk = ~clk; // 10ns period

    initial begin
        // Initialize
        clk = 0;
        rst = 1;
        next_pc = 32'h00000000;
        pc_en = 0;

        // Reset
        #10;
        rst = 0;
        #10;

        // Test hold (stall)
        next_pc = 32'h00001000;
        pc_en = 0;
        #10;
        $display("At t=%0t: pc=%h (should hold 0)", $time, pc);

        // Test update
        pc_en = 1;
        #10;
        $display("At t=%0t: pc=%h (should be 1000)", $time, pc);

        // Another update
        next_pc = 32'h00002000;
        #10;
        $display("At t=%0t: pc=%h (should be 2000)", $time, pc);

        // Stall again
        pc_en = 0;
        next_pc = 32'hDEADBEEF;
        #10;
        $display("At t=%0t: pc=%h (should hold 2000)", $time, pc);

        #10 $finish;
    end
endmodule
// Testbench for pc_update module
// Tests: Priority selection - jump_en > BTB taken > pc+4


module tb_pc_update;
    reg [31:0] pc;
    reg [31:0] pc_jump_addr;
    reg [31:0] btb_target_pc;
    reg btb_pc_valid;
    reg btb_pc_predictTaken;
    reg jump_en;
    wire [31:0] next_pc;

    // Instantiate DUT
    pc_update dut (
        .pc(pc),
        .pc_jump_addr(pc_jump_addr),
        .btb_target_pc(btb_target_pc),
        .btb_pc_valid(btb_pc_valid),
        .btb_pc_predictTaken(btb_pc_predictTaken),
        .jump_en(jump_en),
        .next_pc(next_pc)
    );

    initial begin
        // Test case 1: jump_en high -> pc_jump_addr
        pc = 32'h00001000;
        pc_jump_addr = 32'hDEADBEEF;
        btb_target_pc = 32'hCAFEBABE;
        btb_pc_valid = 1;
        btb_pc_predictTaken = 1;
        jump_en = 1;
        #1;
        $display("Test 1: next_pc=%h (should be DEADBEEF)", next_pc);

        // Test case 2: jump_en low, BTB valid+taken -> btb_target_pc
        jump_en = 0;
        #1;
        $display("Test 2: next_pc=%h (should be CAFEBABE)", next_pc);

        // Test case 3: BTB not taken -> pc+4
        btb_pc_predictTaken = 0;
        #1;
        $display("Test 3: next_pc=%h (should be 1004)", next_pc);

        // Test case 4: BTB invalid -> pc+4
        btb_pc_predictTaken = 1;
        btb_pc_valid = 0;
        #1;
        $display("Test 4: next_pc=%h (should be 1004)", next_pc);

        #1 $finish;
    end
endmodule
// Testbench for inst_mem module
// Note: For simulation, manually initialize mem since $readmemh requires file.
// Tests: Read from specific addresses.

module tb_inst_mem;
    reg [31:0] pc;
    reg read_en;
    wire [31:0] instruction;

    // Instantiate DUT (override initial block in testbench)
    inst_mem dut (
        .pc(pc),
        .read_en(read_en),
        .instruction(instruction)
    );

    // Manually initialize mem (override the $readmemh)
    initial begin
        dut.mem[0] = 32'h00500093; // Example instr at addr 0
        dut.mem[1] = 32'h00600093; // Example at addr 4
        dut.mem[2] = 32'h00700093; // Example at addr 8
    end

    initial begin
        read_en = 1;

        // Test addr 0 (word addr 0)
        pc = 32'h00000000;
        #1;
        $display("Addr 0: instr=%h (should be 00500093)", instruction);

        // Test addr 4 (word addr 1)
        pc = 32'h00000004;
        #1;
        $display("Addr 4: instr=%h (should be 00600093)", instruction);

        // Test addr 8 (word addr 2)
        pc = 32'h00000008;
        #1;
        $display("Addr 8: instr=%h (should be 00700093)", instruction);

        // Test unaligned (but discards low bits)
        pc = 32'h00000002;
        #1;
        $display("Addr 2: instr=%h (should be 00500093)", instruction);

        #1 $finish;
    end
endmodule
// Testbench for if_stage_complex_btb module
// This is complex; tests basic PC update, BTB lookup (assuming btb works), flush/en not directly used in IF.
// Note: Requires btb module to be functional; simulates simple sequence.


module tb_if_stage_complex_btb;
    reg clk;
    reg rst;
    reg pc_en;
    reg if_id_en;
    reg if_id_flush;
    reg modify_pc_ex;
    reg [31:0] update_pc_ex;
    reg [31:0] pc_ex;
    reg [31:0] jump_addr_ex;
    reg update_btb_ex;
    wire [31:0] pc_if;
    wire [31:0] instr_if;
    wire predictedTaken_if;
    wire [31:0] predictedTarget_if;

    // Instantiate DUT
    if_stage_complex_btb dut (
        .clk(clk),
        .rst(rst),
        .pc_en(pc_en),
        .if_id_en(if_id_en),
        .if_id_flush(if_id_flush),
        .modify_pc_ex(modify_pc_ex),
        .update_pc_ex(update_pc_ex),
        .pc_ex(pc_ex),
        .jump_addr_ex(jump_addr_ex),
        .update_btb_ex(update_btb_ex),
        .pc_if(pc_if),
        .instr_if(instr_if),
        .predictedTaken_if(predictedTaken_if),
        .predictedTarget_if(predictedTarget_if)
    );

    // Clock
    always #5 clk = ~clk;

    initial begin
        clk = 0; rst = 1; pc_en = 0; if_id_en = 1; if_id_flush = 0;
        modify_pc_ex = 0; update_pc_ex = 0; pc_ex = 0; jump_addr_ex = 0; update_btb_ex = 0;

        #10; rst = 0; pc_en = 1;
        #10; // PC should be 0, instr from mem[0], no predict

        // Simulate EX override
        modify_pc_ex = 1; update_pc_ex = 32'h00002000;
        #10; // Next PC should jump to 2000

        // Reset override, simulate BTB hit/taken (but BTB needs update first)
        modify_pc_ex = 0;
        // Assume prior update made BTB predict taken to 32'hDEAD, valid=1
        // This test assumes BTB is pre-loaded or updated; for full test, need prior cycles
        update_btb_ex = 1; pc_ex = 32'h00001000; jump_addr_ex = 32'hDEADBEEF; // Update BTB for pc=1000
        #10; update_btb_ex = 0;
        // Now fetch at 1000, should predict taken to DEAD
        #10;

        $display("At t=%0t: pc_if=%h, instr=%h, taken=%b, target=%h", $time, pc_if, instr_if, predictedTaken_if, predictedTarget_if);

        #50 $finish;
    end
endmodule
// Testbench for btb_file module
// Tests: Reset, write, read, forwarding.

module tb_btb_file;
    reg clk;
    reg rst;
    reg [2:0] read_index;
    reg [2:0] update_index;
    reg [2:0] write_index;
    reg [127:0] write_set;
    reg write_en;
    wire [127:0] read_set;
    wire [127:0] update_set;

    // Instantiate DUT
    btb_file dut (
        .clk(clk),
        .rst(rst),
        .read_index(read_index),
        .update_index(update_index),
        .write_index(write_index),
        .write_set(write_set),
        .write_en(write_en),
        .read_set(read_set),
        .update_set(update_set)
    );

    always #5 clk = ~clk;

    initial begin
        clk = 0; rst = 1; read_index = 0; update_index = 0; write_index = 0; write_set = 128'h0; write_en = 0;

        #10; rst = 0;
        #10;

        // Test read before write (should be 0)
        read_index = 3'd1;
        #1;
        $display("Read set 1 before write: %h (should be 0)", read_set);

        // Write to index 1
        write_en = 1; write_index = 3'd1; write_set = 128'hDEADBEEFDEADBEEF;
        #10; write_en = 0;
        #1;

        // Read same index (no forward needed post-write)
        read_index = 3'd1;
        #1;
        $display("Read set 1 after write: %h (should be DEAD...)", read_set);

        // Test forwarding: write and read same cycle
        // (In sim, since sync write, test by asserting in same cycle)
        write_en = 1; write_index = 3'd2; write_set = 128'hCAFEBABECAFEBABE; read_index = 3'd2;
        #1; // Forward should apply
        $display("Forward read set 2: %h (should be CAFE...)", read_set);

        // Update set (combinational)
        update_index = 3'd0;
        #1;
        $display("Update set 0: %h (should be 0)", update_set);

        #10 $finish;
    end
endmodule
// Testbench for btb_write module
// Tests: Update existing entry, insert new, state update with predictor.


module tb_btb_write;
    reg [127:0] update_set;
    reg [7:0] LRU;
    reg [26:0] update_tag;
    reg [2:0] update_index;
    reg [31:0] update_target;
    reg mispredicted;
    wire [127:0] write_set;
    wire next_LRU_write;

    // Instantiate DUT
    btb_write dut (
        .update_set(update_set),
        .LRU(LRU),
        .update_tag(update_tag),
        .update_index(update_index),
        .update_target(update_target),
        .mispredicted(mispredicted),
        .write_set(write_set),
        .next_LRU_write(next_LRU_write)
    );

    initial begin
        // Setup: Empty set, LRU=0 (use slot1), new insert, mispredicted=0 (not taken)
        update_set = 128'h0;
        LRU = 8'h00;
        update_tag = 27'h1234567;
        update_index = 3'd0;
        update_target = 32'hDEADBEEF;
        mispredicted = 0; // actual not taken

        #1;
        $display("New insert, not taken: write_set[127:0]=%h, next_LRU=%b", write_set, next_LRU_write);
        // Expect: insert to slot1 (LRU=0), state=00 (strong not), next_LRU=0 (since new, insert_branch2=0?)

        // Test update existing: Assume slot1 has tag match, state=00, mispredicted=1 (taken)
        update_set = {1'b1, 27'h1234567, 32'h00000000, 2'b00, 30'b0,  // slot1: valid, matching tag, target0, state00
                      1'b0, 27'h0, 32'h0, 2'b0, 30'b0}; // slot2 invalid
        mispredicted = 1;

        #1;
        $display("Update existing slot1 to taken: write_set=%h", write_set);
        // Expect: state to 01, same slot

        // Test insert to slot2 (LRU=1), taken
        LRU = 8'h01; // bit0=1, use slot2 (!LRU)
        update_set = 128'h0;
        update_tag = 27'h7654321;
        mispredicted = 1;

        #1;
        $display("New insert slot2, taken: write_set=%h, next_LRU=%b", write_set, next_LRU_write);
        // Expect: insert slot2, state=01

        #1 $finish;
    end
endmodule
// Testbench for btb_read module
// Tests: Hit on slot1/slot2, predict taken/not, LRU update.


module tb_btb_read;
    reg [127:0] read_set;
    reg [7:0] LRU;
    reg [26:0] read_tag;
    reg [2:0] read_index;
    wire next_LRU_read;
    wire valid;
    wire predictedTaken;
    wire [31:0] target;

    // Instantiate DUT
    btb_read dut (
        .read_set(read_set),
        .LRU(LRU),
        .read_tag(read_tag),
        .read_index(read_index),
        .next_LRU_read(next_LRU_read),
        .valid(valid),
        .predictedTaken(predictedTaken),
        .target(target)
    );

    initial begin
        read_index = 3'd0;
        LRU = 8'h00;

        // Test miss: empty set
        read_set = 128'h0;
        read_tag = 27'h1234567;
        #1;
        $display("Miss: valid=%b, taken=%b, target=%h, next_LRU=%b", valid, predictedTaken, target, next_LRU_read);

        // Test hit slot1, taken (state=11)
        read_set = {1'b1, 27'h1234567, 32'hDEADBEEF, 2'b11, 30'b0,  // slot1: match, taken
                    1'b0, 27'h0, 32'h0, 2'b0, 30'b0}; // slot2 invalid
        #1;
        $display("Hit slot1 taken: valid=%b, taken=%b, target=%h, next_LRU=%b (should flip to 1)", valid, predictedTaken, target, next_LRU_read);

        // Test hit slot2, not taken (state=00)
        read_set = {1'b0, 27'h0, 32'h0, 2'b00, 30'b0,  // slot1 invalid
                    1'b1, 27'h1234567, 32'hCAFEBABE, 2'b00, 30'b0}; // slot2: match, not taken
        LRU = 8'h01; // Assume LRU=1, hit slot2 -> next_LRU=0? (check_branch2=1, next= check_branch2 ? 0 : LRU[0]=1 ->0)
        #1;
        $display("Hit slot2 not taken: valid=%b, taken=%b, target=%h, next_LRU=%b", valid, predictedTaken, target, next_LRU_read);

        #1 $finish;
    end
endmodule
// Testbench for lru_reg module
// Tests: Reset, update.

module tb_lru_reg;
    reg clk;
    reg rst;
    reg [7:0] LRU_updated;
    wire [7:0] LRU;

    // Instantiate DUT
    lru_reg dut (
        .clk(clk),
        .rst(rst),
        .LRU_updated(LRU_updated),
        .LRU(LRU)
    );

    always #5 clk = ~clk;

    initial begin
        clk = 0; rst = 1; LRU_updated = 8'hFF;

        #10; rst = 0;
        #5; // After reset, LRU=00

        $display("After reset: LRU=%h", LRU);

        LRU_updated = 8'hA5;
        #10;
        $display("After update: LRU=%h", LRU);

        #10 $finish;
    end
endmodule
// Testbench for lru_next module
// Tests: LRU update on read hit, write.

module tb_lru_next;
    reg [2:0] index;
    reg [2:0] update_index;
    reg update_lru_read;
    reg update_lru_write;
    reg valid;
    reg update;
    reg [7:0] LRU;
    wire [7:0] next_LRU;

    // Instantiate DUT
    lru_next dut (
        .index(index),
        .update_index(update_index),
        .update_lru_read(update_lru_read),
        .update_lru_write(update_lru_write),
        .valid(valid),
        .update(update),
        .LRU(LRU),
        .next_LRU(next_LRU)
    );

    initial begin
        LRU = 8'h00;
        index = 3'd0;
        update_index = 3'd1;

        // No update
        update_lru_read = 0; update_lru_write = 0; valid = 0; update = 0;
        #1;
        $display("No update: next=%h (same as LRU=00)", next_LRU);

        // Read hit update (index=0, valid=1)
        update_lru_read = 1; valid = 1;
        #1;
        $display("Read hit index0: next=%h (set bit0=1)", next_LRU); // 01

        // Write update (update_index=1, update=1)
        LRU = 8'h00; update_lru_read = 0; update_lru_write = 1; update = 1;
        #1;
        $display("Write index1: next=%h (set bit1=1)", next_LRU); // 02

        // Combined, same index
        index = 3'd2; update_index = 3'd2; LRU = 8'h00;
        update_lru_read = 1; valid = 1; update_lru_write = 1; update = 1;
        #1;
        $display("Read+write same index2: next=%h (set bit2=1)", next_LRU); // 04

        #1 $finish;
    end
endmodule
// Testbench for lru_next module
// Tests: LRU update on read hit, write.

module tb_lru_next;
    reg [2:0] index;
    reg [2:0] update_index;
    reg update_lru_read;
    reg update_lru_write;
    reg valid;
    reg update;
    reg [7:0] LRU;
    wire [7:0] next_LRU;

    // Instantiate DUT
    lru_next dut (
        .index(index),
        .update_index(update_index),
        .update_lru_read(update_lru_read),
        .update_lru_write(update_lru_write),
        .valid(valid),
        .update(update),
        .LRU(LRU),
        .next_LRU(next_LRU)
    );

    initial begin
        LRU = 8'h00;
        index = 3'd0;
        update_index = 3'd1;

        // No update
        update_lru_read = 0; update_lru_write = 0; valid = 0; update = 0;
        #1;
        $display("No update: next=%h (same as LRU=00)", next_LRU);

        // Read hit update (index=0, valid=1)
        update_lru_read = 1; valid = 1;
        #1;
        $display("Read hit index0: next=%h (set bit0=1)", next_LRU); // 01

        // Write update (update_index=1, update=1)
        LRU = 8'h00; update_lru_read = 0; update_lru_write = 1; update = 1;
        #1;
        $display("Write index1: next=%h (set bit1=1)", next_LRU); // 02

        // Combined, same index
        index = 3'd2; update_index = 3'd2; LRU = 8'h00;
        update_lru_read = 1; valid = 1; update_lru_write = 1; update = 1;
        #1;
        $display("Read+write same index2: next=%h (set bit2=1)", next_LRU); // 04

        #1 $finish;
    end
endmodule
// Testbench for btb module
// Tests: Read miss/hit, update with delay, predict.
// Note: Complex; simulates sequence of reads/updates.


module tb_btb;
    reg clk;
    reg rst;
    reg [31:0] pc;
    reg [31:0] update_pc;
    reg update;
    reg [31:0] update_target;
    reg mispredicted;
    wire [31:0] target_pc;
    wire valid;
    wire predictedTaken;

    // Instantiate DUT
    btb dut (
        .clk(clk),
        .rst(rst),
        .pc(pc),
        .update_pc(update_pc),
        .update(update),
        .update_target(update_target),
        .mispredicted(mispredicted),
        .target_pc(target_pc),
        .valid(valid),
        .predictedTaken(predictedTaken)
    );

    always #5 clk = ~clk;

    initial begin
        clk = 0; rst = 1; pc = 32'h00001000; // index= pc[4:2]= (1000>>2)=100 ->4? Wait, 0x1000=4096, [4:2]=512? Assume low addrs.
        // Use low PC for index 0: pc=32'h00000008 (index= pc[4:2]=2)
        pc = 32'h00000008; update_pc = 32'h00000008; update = 0; update_target = 0; mispredicted = 0;

        #10; rst = 0;
        #10; // Read: miss, valid=0

        $display("t=%0t: pc=%h valid=%b taken=%b target=%h", $time, pc, valid, predictedTaken, target_pc);

        // Update BTB: taken branch at pc=8 to target=0x100
        update = 1; update_target = 32'h00000100; mispredicted = 1; // actual taken
        #10; update = 0;
        #10; // Delay: write happens next cycle

        // Re-read same pc: now hit, taken=1 (state updated to 01 or more)
        $display("After update t=%0t: valid=%b taken=%b target=%h", $time, valid, predictedTaken, target_pc);

        // Mispredict update: not taken
        update = 1; update_target = 32'h00000100; mispredicted = 0; // actual not
        #10; update = 0;
        #30; // Read again: state decrement

        $display("After mispredict update: valid=%b taken=%b", valid, predictedTaken);

        #20 $finish;
    end
endmodule

*/


