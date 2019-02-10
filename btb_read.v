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
