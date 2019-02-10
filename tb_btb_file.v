
module btb_file_tb;

    // Ports
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

    // Clock generation: 10ns period
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Simple test variables
    integer errors;
    initial begin
        errors = 0;
        // waveform
        $dumpfile("btb_file_tb.vcd");
        $dumpvars(0, btb_file_tb);

        // --- Test 1: reset clears memory ---
        rst = 1;
        write_en = 0;
        write_index = 3;
        write_set = 128'h0;
        read_index = 3;
        update_index = 3;
        #12; // wait some time (more than one posedge)
        if (read_set !== 128'h0) begin
            $display("FAIL: after reset, read_set not zero: %h", read_set);
            errors = errors + 1;
        end else $display("PASS: reset cleared read_set");

        if (update_set !== 128'h0) begin
            $display("FAIL: after reset, update_set not zero: %h", update_set);
            errors = errors + 1;
        end else $display("PASS: reset cleared update_set");

        // release reset
        @(negedge clk);
        rst = 0;
        #2;

        // --- Test 2: forwarding when writing and reading same index in same cycle ---
        write_index = 3;
        read_index  = 3;
        update_index = 4; // check update_set separate
        write_set = 128'hDEAD_BEEF_0123_4567_89AB_CDEF_0000_1111;
        write_en = 1;

        // Immediately check read_set combinational forwarding (no need to wait posedge)
        #1;
        if (read_set !== write_set) begin
            $display("FAIL: forwarding read_set != write_set when write_en asserted and indices match");
            $display("  read_set  = %h", read_set);
            $display("  write_set = %h", write_set);
            errors = errors + 1;
        end else $display("PASS: forwarding read_set equals write_set when reading same index being written");

        // But update_set is a direct file read (it reads memory contents). Since write is synchronous,
        // before the posedge the memory hasn't been updated yet, update_set should not equal write_set.
        if (update_set === write_set) begin
            $display("WARN: update_set equals write_set before posedge (unexpected) -> %h", update_set);
        end else $display("INFO: update_set did not yet reflect write (expected before posedge)");

        // Now tick clock so write is committed into memory
        @(posedge clk);
        #1; // let combinational settle
        write_en = 0; // deassert write_en

        // After commit, update_set should now show the written value if update_index matched the write_index
        // currently update_index == 4, so update_set should not equal write_set
        if (update_set === write_set) begin
            $display("FAIL: update_set equals write_set although update_index != write_index after write commit");
            errors = errors + 1;
        end else $display("PASS: commit didn't corrupt other index");

        // Read from the committed index (read_index already 3). With write_en=0, read_set should be from memory.
        #2;
        if (read_set !== write_set) begin
            $display("FAIL: after commit, read_set should reflect memory and equal write_set. got %h", read_set);
            errors = errors + 1;
        end else $display("PASS: after commit, read_set matches stored memory");

        // --- Test 3: write to another index and check no forwarding when indices differ ---
        write_index = 1;
        read_index  = 3; // different
        write_set = 128'h1111_2222_3333_4444_5555_6666_7777_8888;
        write_en = 1;
        #1;
        if (read_set === write_set) begin
            $display("FAIL: Unexpected forwarding when read_index != write_index");
            errors = errors + 1;
        end else $display("PASS: no forwarding when indices differ");

        // Commit write
        @(posedge clk);
        #1;
        write_en = 0;

        // Read index 1 now should reflect newly written value
        read_index = 1;
        #2;
        if (read_set !== 128'h1111_2222_3333_4444_5555_6666_7777_8888) begin
            $display("FAIL: read_set for index 1 did not equal expected memory value: %h", read_set);
            errors = errors + 1;
        end else $display("PASS: read back written value at index 1");

        // --- Test 4: multiple writes and check all indices ---
        // Write to index 0
        write_index = 0;
        read_index = 0;
        write_set = 128'h0000_0000_0000_0000_0000_0000_0000_ABCD;
        write_en = 1;
        #1;
        // Forwarding should apply
        if (read_set !== write_set) begin
            $display("FAIL: forwarding failed for index 0");
            errors = errors + 1;
        end else $display("PASS: forwarding for index 0 ok");
        @(posedge clk);
        #1;
        write_en = 0;

        // check memory contents for indexes 0,1,3 (previous writes)
        read_index = 0; #1;
        if (read_set !== 128'h0000_0000_0000_0000_0000_0000_0000_ABCD) begin
            $display("FAIL: index0 mismatch: %h", read_set);
            errors = errors + 1;
        end

        read_index = 1; #1;
        if (read_set !== 128'h1111_2222_3333_4444_5555_6666_7777_8888) begin
            $display("FAIL: index1 mismatch: %h", read_set);
            errors = errors + 1;
        end

        read_index = 3; #1;
        if (read_set !== 128'hDEAD_BEEF_0123_4567_89AB_CDEF_0000_1111) begin
            $display("FAIL: index3 mismatch: %h", read_set);
            errors = errors + 1;
        end

        // Final result
        #5;
        if (errors == 0) begin
            $display("ALL TESTS PASSED");
        end else begin
            $display("TESTS FAILED: %0d errors", errors);
        end

        $finish;
    end

endmodule

