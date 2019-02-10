module dynamic_branch_predictor(
    input  wire [1:0] curr_state,
    input  wire       actual_taken,
    output reg  [1:0] next_state
);
    always @(*) begin
        if (actual_taken) begin
            case (curr_state)
                2'b00: next_state = 2'b01;
                2'b01: next_state = 2'b10;
                2'b10: next_state = 2'b11;
                2'b11: next_state = 2'b11;
            endcase
        end
        else begin
            case (curr_state)
                2'b00: next_state = 2'b00;
                2'b01: next_state = 2'b00;
                2'b10: next_state = 2'b01;
                2'b11: next_state = 2'b10;
            endcase
        end
    end
endmodule

