




// pc_reg.v
module pc_reg (
    input  wire clk,
    input  wire rst,
    input  wire pc_en,
    input  wire [31:0] next_pc,
    output reg  [31:0] pc
);
    always @(posedge clk or posedge rst) begin
        if (rst)
            pc <= 32'h0000_0000;
        else if (pc_en)
            pc <= next_pc;
    end
endmodule





