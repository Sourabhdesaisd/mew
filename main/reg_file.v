module register_file (
    input  wire        clk,

    // write port (from WB stage)
    input  wire        wr_en,
    input  wire [4:0]  wr_addr,
    input  wire [31:0] wr_data,

    // read addresses (from ID stage)
    input  wire [4:0]  rs1_addr,
    input  wire [4:0]  rs2_addr,

    // read data outputs
    output wire [31:0] rs1_data,
    output wire [31:0] rs2_data
);
    reg [31:0] reg_file [0:31];
      //  integer i;
    
    initial begin
        // Optional: initialize registers from a file if present
        $readmemh("reg_mem.hex", reg_file);
       // for (i = 0; i < 32; i = i + 1) reg_file[i] = 32'h00000000;
    end

    // Forwarding behavior: if a write happens to the same reg in the same cycle,
    // provide the write data to reads (combinational forwarding).
    // This simple scheme assumes write happens on posedge and reads are combinational.
    wire [31:0] rs1_comb = reg_file[rs1_addr];
    wire [31:0] rs2_comb = reg_file[rs2_addr];

    assign rs1_data = (rs1_addr == 5'd0) ? 32'h0 :
                      ((wr_en && (wr_addr == rs1_addr)) ? wr_data : rs1_comb);

    assign rs2_data = (rs2_addr == 5'd0) ? 32'h0 :
                      ((wr_en && (wr_addr == rs2_addr)) ? wr_data : rs2_comb);

    // Write operation (synchronous)
    always @(posedge clk) begin
        if (wr_en && (wr_addr != 5'd0)) begin
            reg_file[wr_addr] <= wr_data;
        end
    end

endmodule
