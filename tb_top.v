// main_tb.v

module main_tb;
    // Clock / reset
    reg clk;
    reg rst;
    // ---------------------------------------------------------
    // Instantiate DUT (change module name if your top uses a different name)
    // ---------------------------------------------------------
    // If your top module is named differently, replace rv32i_core with your module name.
    wire [31:0] tb_pc;
    wire [31:0] tb_next_pc;
    wire        tb_pc_en;
    wire [31:0] tb_if_id_instr;
    wire [31:0] tb_id_ex_instr;
    wire        tb_branch_ex;
    wire        tb_branch_taken_ex;
    wire [31:0] tb_branch_target;
    wire        tb_if_id_en;
    wire        tb_if_id_flush;
    wire        tb_id_ex_en;
    wire        tb_id_ex_flush;
    wire        tb_load_stall;

    rv32i_core dut (
        .clk(clk),
        .rst(rst),
        .pc(tb_pc),
        .next_pc(tb_next_pc),
        .pc_en(tb_pc_en),
        .if_id_instr(tb_if_id_instr),
        .id_ex_instr(tb_id_ex_instr),
        .ex_mem_instr(),             // left unconnected (optional)
        .branch_ex(tb_branch_ex),
        .branch_taken_ex(tb_branch_taken_ex),
        .branch_target(tb_branch_target),
        .if_id_en_out(tb_if_id_en),
        .if_id_flush_out(tb_if_id_flush),
        .id_ex_en_out(tb_id_ex_en),
        .id_ex_flush_out(tb_id_ex_flush),
        .load_stall_out(tb_load_stall)
    );

    // ---------------------------------------------------------
    // Waveform & SHM probe (your original style)
    // ---------------------------------------------------------
    initial begin
        

        // Your provided SHM probe calls — keep if your simulator supports them
        // (ModelSim/Questa/Verdi may support $shm_* or use other mechanisms)
        // If your simulator doesn't support SHM, these system tasks will be ignored or cause warnings.
        $shm_open("wave.shm");
        $shm_probe("ACTMF");
    end

    

    initial begin
        clk = 1;
        forever #5 clk = ~clk;
    end

    // Test stimulus
    initial begin
        // Apply reset
        rst = 1;
        #20;       // Hold reset for 20ns
        rst = 0;

        // Run simulation for N ns then finish (adjust as needed)
        #1000;
        $display("SIMULATION DONE");
        $finish;
    end

endmodule

