// mem_stage_and_data_path_fixed.v
// Corrected load/store datapath + data memory + mem_stage wiring.
// Small, safe fix: correct halfword extraction for little-endian layout.


module load_datapath (
    input  wire [2:0]  load_type,
    input  wire [31:0] mem_data_in,
    input  wire [31:0] addr,
    output reg  [31:0] read_data
);
    // byte lanes (little-endian)
    wire [7:0]  byte0 = mem_data_in[7:0];
    wire [7:0]  byte1 = mem_data_in[15:8];
    wire [7:0]  byte2 = mem_data_in[23:16];
    wire [7:0]  byte3 = mem_data_in[31:24];

    // halfwords for little-endian: low half (bytes[1:0]), high half (bytes[3:2])
    wire [15:0] half0 = {byte1, byte0}; // addr[1] == 0 -> bytes [1:0]
    wire [15:0] half1 = {byte3, byte2}; // addr[1] == 1 -> bytes [3:2]

    // selected byte depending on addr[1:0]
    wire [7:0] selected_byte = (addr[1:0] == 2'b00) ? byte0 :
                               (addr[1:0] == 2'b01) ? byte1 :
                               (addr[1:0] == 2'b10) ? byte2 :
                                                      byte3;

    // select halfword by addr[1]
    wire [15:0] selected_half = (addr[1] == 1'b0) ? half0 : half1;

    always @(*) begin
        case (load_type)
            3'b000: begin // LB - sign-extend byte
                read_data = {{24{selected_byte[7]}}, selected_byte};
            end
            3'b011: begin // LBU - zero-extend byte
                read_data = {24'b0, selected_byte};
            end
            3'b001: begin // LH - sign-extend halfword
                read_data = {{16{selected_half[15]}}, selected_half};
            end
            3'b100: begin // LHU - zero-extend halfword
                read_data = {16'b0, selected_half};
            end
            3'b010: begin // LW - full word
                read_data = mem_data_in;
            end
            default: begin
                read_data = 32'h00000000;
            end
        endcase
    end
endmodule


module store_datapath (
    input  wire [1:0]  store_type, // 00=SB, 01=SH, 10=SW
    input  wire [31:0] write_data, // rs2 data
    input  wire [31:0] addr,       // ALU result (byte address)
    output reg  [31:0] mem_write_data,
    output reg  [3:0]  byte_enable
);
    always @(*) begin
        mem_write_data = 32'b0;
        byte_enable    = 4'b0000;

        case(store_type)
            2'b00: begin // SB
                mem_write_data = {4{write_data[7:0]}}; // replicate byte across word
                case(addr[1:0])
                    2'b00: byte_enable = 4'b0001;
                    2'b01: byte_enable = 4'b0010;
                    2'b10: byte_enable = 4'b0100;
                    2'b11: byte_enable = 4'b1000;
                endcase
            end
            2'b01: begin // SH
                mem_write_data = {2{write_data[15:0]}};
                byte_enable = addr[1] ? 4'b1100 : 4'b0011;
            end
            2'b10: begin // SW
                mem_write_data = write_data;
                byte_enable    = 4'b1111;
            end
            default: begin
                mem_write_data = 32'b0;
                byte_enable = 4'b0000;
            end
        endcase
    end
endmodule





