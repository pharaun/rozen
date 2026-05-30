#include <std/mem.pat>

struct LtvcBlock {
    u32 data_length;
    char typ[4];
    u16 header_hash;
    u8 data[data_length];
    u32 data_hash;
};

LtvcBlock entries[while(!std::mem::eof())] @ 0x00;
