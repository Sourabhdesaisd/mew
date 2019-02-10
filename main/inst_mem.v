module inst_mem (
    input  wire [31:0] pc, 
	input  rst,clk,flush,read_en,     // byte address
    output reg [31:0] instruction
);
    reg [31:0] mem [0:255];

    initial begin
        $readmemh("instructions.hex", mem);  // optional
    end


always @(posedge clk) 
begin

        if (rst) 

            instruction <= 32'h00000000; // Reset instruction to NOP

        
	 else if (flush) 

            instruction <= 32'h00000000; // Flush instruction to NOP

         
	else if (read_en) 

            instruction <= mem[pc[11:2]]; // Fetch instruction based on PC

        

    end

endmodule
