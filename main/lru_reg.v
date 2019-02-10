module lru_reg(
    input  wire clk,
    input  wire rst,
    input  wire en,
    input  wire next_lru,
    output reg  lru_out
);
    always @(posedge clk or posedge rst) begin
        if (rst)
            lru_out <= 1'b0;
        else if (en)
            lru_out <= next_lru;
    end
endmodule
