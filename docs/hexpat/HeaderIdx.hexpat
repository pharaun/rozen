import type.leb128;

struct HeaderIdx {
    char typ[4];
    u8 hash[32];
    type::uLEB128 start_idx;
    type::uLEB128 length;
};

HeaderIdx entries[while(!std::mem::eof())] @ 0x00;
