`timescale 1ns/1ps

module btb_read_tb;
    reg  [127:0] read_set;
    reg  [7:0]   LRU;
    reg  [26:0]  read_tag;
    reg  [2:0]   read_index;

    wire next_LRU_read;
    wire valid;
    wire predictedTaken;
    wire [31:0] target;

    // DUT
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

    // helper: build a 64-bit entry:
    // [63] valid, [62:36] tag (27bit), [35:4] target (32bit), [3:2] state, [1:0] reserved
    function [63:0] make_entry;
        input        v;
        input [26:0] tag;
        input [31:0] trg;
        input [1:0]  st;
        begin
            make_entry = { v, tag, trg, st, 2'b00 };
        end
    endfunction

    integer errors;
    initial begin
        errors = 0;

        // default: all zeros
        read_set = 128'h0;
        LRU = 8'h00;
        read_tag = 27'h0;
        read_index = 3'd2;

        #1;
        // Case 1: no entries valid -> miss
        #1;
        if (valid !== 1'b0) begin $display("FAIL case1: valid expected 0, got %b", valid); errors = errors + 1; end
        if (predictedTaken !== 1'b0) begin $display("FAIL case1: predictedTaken expected 0, got %b", predictedTaken); errors = errors + 1; end
        if (target !== 32'h0) begin $display("FAIL case1: target expected 0, got %h", target); errors = errors + 1; end

        // Case 2: way1 hit
        // put an entry in way1 with tag = 0x1A5 and target = 0xCAFEBABE, state = 2'b10 (predict taken)
        read_tag = 27'h1A5;
        read_set = { make_entry(1'b1, 27'h1A5, 32'hCAFEBABE, 2'b10), 64'h0 }; // branch1, branch2
        LRU = 8'b0000_0001; // some LRU that will be replaced if code sets it
        #1;
        if (valid !== 1'b1) begin $display("FAIL case2: valid expected 1"); errors = errors + 1; end
        if (predictedTaken !== 1'b1) begin $display("FAIL case2: predictedTaken expected 1"); errors = errors + 1; end
        if (target !== 32'hCAFEBABE) begin $display("FAIL case2: target mismatch %h", target); errors = errors + 1; end
        if (next_LRU_read !== 1'b0) begin $display("FAIL case2: next_LRU_read expected 0 (way1 hit), got %b", next_LRU_read); errors = errors + 1; end

        // Case 3: way2 hit (only lower 64 bits)
        read_tag = 27'h2B7;
        read_set = { 64'h0, make_entry(1'b1, 27'h2B7, 32'h12345678, 2'b11) }; // way2 has taken state
        LRU = 8'b1111_1110;
        #1;
        if (valid !== 1'b1) begin $display("FAIL case3: valid expected 1"); errors = errors + 1; end
        if (predictedTaken !== 1'b1) begin $display("FAIL case3: predictedTaken expected 1"); errors = errors + 1; end
        if (target !== 32'h12345678) begin $display("FAIL case3: target mismatch %h", target); errors = errors + 1; end
        if (next_LRU_read !== 1'b1) begin $display("FAIL case3: next_LRU_read expected 1 (way2 hit), got %b", next_LRU_read); errors = errors + 1; end

        // Case 4: both ways valid and both tags equal -> way1 priority expected
        read_tag = 27'h0AA;
        read_set = { make_entry(1'b1, 27'h0AA, 32'hAAAA_AAAA, 2'b10), make_entry(1'b1, 27'h0AA, 32'hBBBB_BBBB, 2'b11) };
        LRU = 8'b0000_0000;
        #1;
        if (valid !== 1'b1) begin $display("FAIL case4: valid expected 1"); errors = errors + 1; end
        if (target !== 32'hAAAA_AAAA) begin $display("FAIL case4: both-hit priority mismatch, got %h", target); errors = errors + 1; end
        if (next_LRU_read !== 1'b0) begin $display("FAIL case4: next_LRU_read expected 0 (way1 priority), got %b", next_LRU_read); errors = errors + 1; end

        #1;
        if (errors == 0) $display("btb_read_tb: ALL PASSED");
        else $display("btb_read_tb: %0d ERRORS", errors);

        $finish;
    end
endmodule

