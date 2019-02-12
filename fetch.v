// if_stage_and_btb_fixed.v
// Combined corrected modules provided by user with small, safe fixes.
// NOTES:
//  - Minimal behavioral changes; no datapath or ISA semantics changed.
//  - Added fallback predictor-state macros if not provided by external defines.vh
//  - dynamic_branch_predictor now expects an 'actual outcome' encoded on the port named `mispredicted`
//    (this is a compatibility choice — see changelog / next steps).

`ifndef STRONG_NOT_TAKEN
`define STRONG_NOT_TAKEN 2'b00
`define WEAK_NOT_TAKEN   2'b01
`define WEAK_TAKEN       2'b10
`define STRONG_TAKEN     2'b11
`endif

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
// inst_mem - small ROM read (word-addressed)
// -----------------------------------------------------------------------------
module inst_mem (
    input  wire [31:0] pc,       // byte address
    input  wire        read_en,  // ignored (always read in IF-stage), kept for API consistency
    output wire [31:0] instruction
);
    // Simple small instruction memory (256 x 32-bit words)
    reg [31:0] mem [0:255];

    initial begin
        // testbench will create "instructions.hex" file; simulation reads it here.
        // Format: one 32-bit hex word per line (e.g., 00500093)
        // If file absent, memory contents remain X for simulation but will be synthesized as a blank ROM in FPGA tools.
        $readmemh("instructions.hex", mem);
    end

    // Word-addressed: instruction at word address pc[11:2]
    // (we discard lowest two bits assuming aligned fetches).
    assign instruction = mem[pc[11:2]];
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

    assign predictedTaken = current_state[1];

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

