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
