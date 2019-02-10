module lru_next(
    input  wire hit_way,     // 0 or 1
    output wire next_lru     // 0 => way0 LRU, 1 => way1 LRU
);
    assign next_lru = hit_way ? 1'b0 : 1'b1;
endmodule

