module data_memory (
    input  wire        clk,
    input  wire        mem_read,
    input  wire        mem_write,
    input  wire [31:0] addr,          // byte address
    input  wire [31:0] write_data,    // from store datapath
    input  wire [3:0]  byte_enable,   // from store datapath
    output reg  [31:0] mem_data_out   // to load datapath
);
    reg [7:0] mem [0:1023]; // 1KB byte-addressable

    integer i;
    initial begin
        for(i=0;i<1024;i=i+1)
            mem[i] = 8'b0; // avoid X in simulation
    end

    // WRITE — Byte controlled
    always @(posedge clk) begin
        if (mem_write) begin
            if (byte_enable[0]) mem[addr]     <= write_data[7:0];
            if (byte_enable[1]) mem[addr+1]   <= write_data[15:8];
            if (byte_enable[2]) mem[addr+2]   <= write_data[23:16];
            if (byte_enable[3]) mem[addr+3]   <= write_data[31:24];
        end
    end

    // READ — Form 32-bit word from 4 bytes (combinational)
    always @(*) begin
        if (mem_read) begin
            mem_data_out = { mem[addr+3], mem[addr+2], mem[addr+1], mem[addr] };
        end else begin
            mem_data_out = 32'b0;
        end
    end
endmodule
