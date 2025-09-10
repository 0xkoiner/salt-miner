/*
   CREATE2 vanity address search using GPU compute shader

   Adapted from the kale-miner keccak implementation found in:
   https://github.com/FredericRezeau/kale-miner/blob/4d5be16d326584b422240ee01a381d1bfb016aae/utils/keccak.wgsl
*/

struct uint64 {
    low: u32,
    high: u32
};

fn uint64FromBytes(bytes: ptr<function, array<u32, 200>>, offset: u32) -> uint64 {
    return uint64(
        (*bytes)[offset] |
        ((*bytes)[offset + 1u] << 8u) |
        ((*bytes)[offset + 2u] << 16u) |
        ((*bytes)[offset + 3u] << 24u),
        (*bytes)[offset + 4u] |
        ((*bytes)[offset + 5u] << 8u) |
        ((*bytes)[offset + 6u] << 16u) |
        ((*bytes)[offset + 7u] << 24u));
}

fn uint64ToBytes(val: uint64, bytes: ptr<function, array<u32, 200>>, offset: u32) {
    (*bytes)[offset] = val.low & 0xFFu;
    (*bytes)[offset + 1u] = (val.low >> 8u) & 0xFFu;
    (*bytes)[offset + 2u] = (val.low >> 16u) & 0xFFu;
    (*bytes)[offset + 3u] = (val.low >> 24u) & 0xFFu;
    (*bytes)[offset + 4u] = val.high & 0xFFu;
    (*bytes)[offset + 5u] = (val.high >> 8u) & 0xFFu;
    (*bytes)[offset + 6u] = (val.high >> 16u) & 0xFFu;
    (*bytes)[offset + 7u] = (val.high >> 24u) & 0xFFu;
}

fn uint64Xor(a: uint64, b: uint64) -> uint64 {
    return uint64(a.low ^ b.low, a.high ^ b.high);
}

fn uint64And(a: uint64, b: uint64) -> uint64 {
    return uint64(a.low & b.low, a.high & b.high);
}

fn uint64Not(a: uint64) -> uint64 {
    return uint64(~a.low, ~a.high);
}

fn uint64Rotl(a: uint64, n: u32) -> uint64 {
    let nmod: u32 = n % 64u;
    if (nmod == 0u) {
        return a;
    } else if (nmod < 32u) {
        return uint64((a.low << nmod) | (a.high >> (32u - nmod)),
            (a.high << nmod) | (a.low >> (32u - nmod)));
    } else if (nmod == 32u) {
        return uint64(a.high, a.low);
    } else {
        let shift: u32 = nmod - 32u;
        return uint64((a.high << shift) | (a.low >> (32u - shift)),
            (a.low << shift) | (a.high >> (32u - shift)));
    }
}

fn xorState(state: ptr<function, array<u32, 200>>, index: u32, x: u32) {
    (*state)[index] ^= x;
}

fn keccakF1600(state: ptr<function, array<u32, 200>>) {
    var s0: uint64 = uint64FromBytes(state, 0u * 8u);
    var s1: uint64 = uint64FromBytes(state, 1u * 8u);
    var s2: uint64 = uint64FromBytes(state, 2u * 8u);
    var s3: uint64 = uint64FromBytes(state, 3u * 8u);
    var s4: uint64 = uint64FromBytes(state, 4u * 8u);
    var s5: uint64 = uint64FromBytes(state, 5u * 8u);
    var s6: uint64 = uint64FromBytes(state, 6u * 8u);
    var s7: uint64 = uint64FromBytes(state, 7u * 8u);
    var s8: uint64 = uint64FromBytes(state, 8u * 8u);
    var s9: uint64 = uint64FromBytes(state, 9u * 8u);
    var s10: uint64 = uint64FromBytes(state, 10u * 8u);
    var s11: uint64 = uint64FromBytes(state, 11u * 8u);
    var s12: uint64 = uint64FromBytes(state, 12u * 8u);
    var s13: uint64 = uint64FromBytes(state, 13u * 8u);
    var s14: uint64 = uint64FromBytes(state, 14u * 8u);
    var s15: uint64 = uint64FromBytes(state, 15u * 8u);
    var s16: uint64 = uint64FromBytes(state, 16u * 8u);
    var s17: uint64 = uint64FromBytes(state, 17u * 8u);
    var s18: uint64 = uint64FromBytes(state, 18u * 8u);
    var s19: uint64 = uint64FromBytes(state, 19u * 8u);
    var s20: uint64 = uint64FromBytes(state, 20u * 8u);
    var s21: uint64 = uint64FromBytes(state, 21u * 8u);
    var s22: uint64 = uint64FromBytes(state, 22u * 8u);
    var s23: uint64 = uint64FromBytes(state, 23u * 8u);
    var s24: uint64 = uint64FromBytes(state, 24u * 8u);

    var C0: uint64; var C1: uint64; var C2: uint64; var C3: uint64; var C4: uint64;
    var D0: uint64; var D1: uint64; var D2: uint64; var D3: uint64; var D4: uint64;
    var B0: uint64; var B1: uint64; var B2: uint64; var B3: uint64; var B4: uint64;
    var B5: uint64; var B6: uint64; var B7: uint64; var B8: uint64; var B9: uint64;
    var B10: uint64; var B11: uint64; var B12: uint64; var B13: uint64; var B14: uint64;
    var B15: uint64; var B16: uint64; var B17: uint64; var B18: uint64; var B19: uint64;
    var B20: uint64; var B21: uint64; var B22: uint64; var B23: uint64; var B24: uint64;

    for (var round: u32 = 0u; round < 24u; round = round + 1u) {
        // θ step
        C0 = uint64Xor(uint64Xor(uint64Xor(uint64Xor(s0, s5), s10), s15), s20);
        C1 = uint64Xor(uint64Xor(uint64Xor(uint64Xor(s1, s6), s11), s16), s21);
        C2 = uint64Xor(uint64Xor(uint64Xor(uint64Xor(s2, s7), s12), s17), s22);
        C3 = uint64Xor(uint64Xor(uint64Xor(uint64Xor(s3, s8), s13), s18), s23);
        C4 = uint64Xor(uint64Xor(uint64Xor(uint64Xor(s4, s9), s14), s19), s24);

        D0 = uint64Xor(C4, uint64Rotl(C1, 1u));
        D1 = uint64Xor(C0, uint64Rotl(C2, 1u));
        D2 = uint64Xor(C1, uint64Rotl(C3, 1u));
        D3 = uint64Xor(C2, uint64Rotl(C4, 1u));
        D4 = uint64Xor(C3, uint64Rotl(C0, 1u));

        s0 = uint64Xor(s0, D0);
        s5 = uint64Xor(s5, D0);
        s10 = uint64Xor(s10, D0);
        s15 = uint64Xor(s15, D0);
        s20 = uint64Xor(s20, D0);

        s1 = uint64Xor(s1, D1);
        s6 = uint64Xor(s6, D1);
        s11 = uint64Xor(s11, D1);
        s16 = uint64Xor(s16, D1);
        s21 = uint64Xor(s21, D1);

        s2 = uint64Xor(s2, D2);
        s7 = uint64Xor(s7, D2);
        s12 = uint64Xor(s12, D2);
        s17 = uint64Xor(s17, D2);
        s22 = uint64Xor(s22, D2);

        s3 = uint64Xor(s3, D3);
        s8 = uint64Xor(s8, D3);
        s13 = uint64Xor(s13, D3);
        s18 = uint64Xor(s18, D3);
        s23 = uint64Xor(s23, D3);

        s4 = uint64Xor(s4, D4);
        s9 = uint64Xor(s9, D4);
        s14 = uint64Xor(s14, D4);
        s19 = uint64Xor(s19, D4);
        s24 = uint64Xor(s24, D4);

        // ρ and π steps
        B0 = s0;
        B1 = uint64Rotl(s6, 44u);
        B2 = uint64Rotl(s12, 43u);
        B3 = uint64Rotl(s18, 21u);
        B4 = uint64Rotl(s24, 14u);
        B5 = uint64Rotl(s3, 28u);
        B6 = uint64Rotl(s9, 20u);
        B7 = uint64Rotl(s10, 3u);
        B8 = uint64Rotl(s16, 45u);
        B9 = uint64Rotl(s22, 61u);
        B10 = uint64Rotl(s1, 1u);
        B11 = uint64Rotl(s7, 6u);
        B12 = uint64Rotl(s13, 25u);
        B13 = uint64Rotl(s19, 8u);
        B14 = uint64Rotl(s20, 18u);
        B15 = uint64Rotl(s4, 27u);
        B16 = uint64Rotl(s5, 36u);
        B17 = uint64Rotl(s11, 10u);
        B18 = uint64Rotl(s17, 15u);
        B19 = uint64Rotl(s23, 56u);
        B20 = uint64Rotl(s2, 62u);
        B21 = uint64Rotl(s8, 55u);
        B22 = uint64Rotl(s14, 39u);
        B23 = uint64Rotl(s15, 41u);
        B24 = uint64Rotl(s21, 2u);

        // χ step
        var t0: uint64;
        var t1: uint64;
        var t2: uint64;
        var t3: uint64;
        var t4: uint64;
        t0 = B0; t1 = B1; t2 = B2; t3 = B3; t4 = B4;
        s0 = uint64Xor(t0, uint64And(uint64Not(t1), t2));
        s1 = uint64Xor(t1, uint64And(uint64Not(t2), t3));
        s2 = uint64Xor(t2, uint64And(uint64Not(t3), t4));
        s3 = uint64Xor(t3, uint64And(uint64Not(t4), t0));
        s4 = uint64Xor(t4, uint64And(uint64Not(t0), t1));
        t0 = B5; t1 = B6; t2 = B7; t3 = B8; t4 = B9;
        s5 = uint64Xor(t0, uint64And(uint64Not(t1), t2));
        s6 = uint64Xor(t1, uint64And(uint64Not(t2), t3));
        s7 = uint64Xor(t2, uint64And(uint64Not(t3), t4));
        s8 = uint64Xor(t3, uint64And(uint64Not(t4), t0));
        s9 = uint64Xor(t4, uint64And(uint64Not(t0), t1));
        t0 = B10; t1 = B11; t2 = B12; t3 = B13; t4 = B14;
        s10 = uint64Xor(t0, uint64And(uint64Not(t1), t2));
        s11 = uint64Xor(t1, uint64And(uint64Not(t2), t3));
        s12 = uint64Xor(t2, uint64And(uint64Not(t3), t4));
        s13 = uint64Xor(t3, uint64And(uint64Not(t4), t0));
        s14 = uint64Xor(t4, uint64And(uint64Not(t0), t1));
        t0 = B15; t1 = B16; t2 = B17; t3 = B18; t4 = B19;
        s15 = uint64Xor(t0, uint64And(uint64Not(t1), t2));
        s16 = uint64Xor(t1, uint64And(uint64Not(t2), t3));
        s17 = uint64Xor(t2, uint64And(uint64Not(t3), t4));
        s18 = uint64Xor(t3, uint64And(uint64Not(t4), t0));
        s19 = uint64Xor(t4, uint64And(uint64Not(t0), t1));
        t0 = B20; t1 = B21; t2 = B22; t3 = B23; t4 = B24;
        s20 = uint64Xor(t0, uint64And(uint64Not(t1), t2));
        s21 = uint64Xor(t1, uint64And(uint64Not(t2), t3));
        s22 = uint64Xor(t2, uint64And(uint64Not(t3), t4));
        s23 = uint64Xor(t3, uint64And(uint64Not(t4), t0));
        s24 = uint64Xor(t4, uint64And(uint64Not(t0), t1));

        // ι step
        var roundConstant: uint64;
        switch (round) {
            case 0u: { roundConstant = uint64(0x00000001u, 0x00000000u); }
            case 1u: { roundConstant = uint64(0x00008082u, 0x00000000u); }
            case 2u: { roundConstant = uint64(0x0000808au, 0x80000000u); }
            case 3u: { roundConstant = uint64(0x80008000u, 0x80000000u); }
            case 4u: { roundConstant = uint64(0x0000808bu, 0x00000000u); }
            case 5u: { roundConstant = uint64(0x80000001u, 0x00000000u); }
            case 6u: { roundConstant = uint64(0x80008081u, 0x80000000u); }
            case 7u: { roundConstant = uint64(0x00008009u, 0x80000000u); }
            case 8u: { roundConstant = uint64(0x0000008au, 0x00000000u); }
            case 9u: { roundConstant = uint64(0x00000088u, 0x00000000u); }
            case 10u: { roundConstant = uint64(0x80008009u, 0x00000000u); }
            case 11u: { roundConstant = uint64(0x8000000au, 0x00000000u); }
            case 12u: { roundConstant = uint64(0x8000808bu, 0x00000000u); }
            case 13u: { roundConstant = uint64(0x0000008bu, 0x80000000u); }
            case 14u: { roundConstant = uint64(0x00008089u, 0x80000000u); }
            case 15u: { roundConstant = uint64(0x00008003u, 0x80000000u); }
            case 16u: { roundConstant = uint64(0x00008002u, 0x80000000u); }
            case 17u: { roundConstant = uint64(0x00000080u, 0x80000000u); }
            case 18u: { roundConstant = uint64(0x0000800au, 0x00000000u); }
            case 19u: { roundConstant = uint64(0x8000000au, 0x80000000u); }
            case 20u: { roundConstant = uint64(0x80008081u, 0x80000000u); }
            case 21u: { roundConstant = uint64(0x00008080u, 0x80000000u); }
            case 22u: { roundConstant = uint64(0x80000001u, 0x00000000u); }
            case 23u: { roundConstant = uint64(0x80008008u, 0x80000000u); }
            default: { roundConstant = uint64(0u, 0u); }
        }
        s0 = uint64Xor(s0, roundConstant);
    }

    uint64ToBytes(s0, state, 0u * 8u);
    uint64ToBytes(s1, state, 1u * 8u);
    uint64ToBytes(s2, state, 2u * 8u);
    uint64ToBytes(s3, state, 3u * 8u);
    uint64ToBytes(s4, state, 4u * 8u);
    uint64ToBytes(s5, state, 5u * 8u);
    uint64ToBytes(s6, state, 6u * 8u);
    uint64ToBytes(s7, state, 7u * 8u);
    uint64ToBytes(s8, state, 8u * 8u);
    uint64ToBytes(s9, state, 9u * 8u);
    uint64ToBytes(s10, state, 10u * 8u);
    uint64ToBytes(s11, state, 11u * 8u);
    uint64ToBytes(s12, state, 12u * 8u);
    uint64ToBytes(s13, state, 13u * 8u);
    uint64ToBytes(s14, state, 14u * 8u);
    uint64ToBytes(s15, state, 15u * 8u);
    uint64ToBytes(s16, state, 16u * 8u);
    uint64ToBytes(s17, state, 17u * 8u);
    uint64ToBytes(s18, state, 18u * 8u);
    uint64ToBytes(s19, state, 19u * 8u);
    uint64ToBytes(s20, state, 20u * 8u);
    uint64ToBytes(s21, state, 21u * 8u);
    uint64ToBytes(s22, state, 22u * 8u);
    uint64ToBytes(s23, state, 23u * 8u);
    uint64ToBytes(s24, state, 24u * 8u);
}

fn keccak256(data: ptr<function, array<u32, 200>>, length: u32) -> array<u32, 32u> {
    var state: array<u32, 200>;

    let rate: u32 = 136u;
    var len: u32 = length;
    var doff: u32 = 0u;
    var offset: u32 = 0u;

    while (len > 0u) {
        var chunk: u32 = len;
        if (len > (rate - offset)) {
            chunk = rate - offset;
        }
        let t: u32 = offset;
        for (var i: u32 = 0u; i < chunk; i = i + 1u) {
            xorState(&state, t + i, (*data)[doff + i]);
        }
        offset += chunk;
        doff += chunk;
        len -= chunk;
        if (offset == rate) {
            keccakF1600(&state);
            offset = 0u;
        }
    }

    xorState(&state, offset, 0x01u);
    xorState(&state, 135u, 0x80u);
    keccakF1600(&state);

    var output: array<u32, 32u>;
    for (var i: u32 = 0u; i < 32u; i = i + 1u) {
        output[i] = state[i];
    }
    return output;
}

fn add128_le(a0: u32, a1: u32, a2: u32, a3: u32, add: u32) -> vec4<u32> {
    // 128-bit little-endian add of (a3 a2 a1 a0) + add, returns new limbs
    var r0 = a0 + add;
    var c = select(0u, 1u, r0 < a0);
    var r1 = a1 + c;
    c = select(0u, 1u, r1 < a1 || (c == 1u && r1 == a1));
    var r2 = a2 + c;
    c = select(0u, 1u, r2 < a2 || (c == 1u && r2 == a2));
    var r3 = a3 + c;
    return vec4<u32>(r0, r1, r2, r3);
}

// Input and Output buffers
struct Inputs {
    // salt base (128-bit; little-endian limbs)
    base_salt: vec4<u32>, // [s0, s1, s2, s3]

    // pattern controls
    pattern_len: u32,     // number of nibbles to match (0..40)
    match_mode: u32,      // 0=Prefix,1=Suffix,2=Contains,3=Mask,4=Exact
    salts_per_invocation: u32, // number of salts each thread should test
    stride: u32,          // salt delta between loop iterations (usually total_invocations)
    work_items: u32,      // total number of work items (threads) that should run

    // 20-byte deployer as 5 u32 words; bytes are stored little-endian within each word
    deployer_words: array<u32, 5>,

    // 32-byte init_code_hash as 8 u32 words; bytes stored little-endian within each word
    init_hash_words: array<u32, 8>,

    // Pattern nibbles: 40 entries, each lower 4 bits used (0..15).
    pattern_nibbles: array<u32, 40>,

    // Mask flags for Mask mode: 40 entries, 1=wildcard ('.'), 0=must match nibble.
    pattern_mask: array<u32, 40>,
};

struct Output {
    found: atomic<u32>,         // 0 = no, 1 = yes
    // winning salt (128-bit little-endian limbs)
    salt_le: vec4<u32>,
    // address (20 bytes) packed into 5 u32 little-endian words
    addr_words: array<u32, 5>,
    _pad: array<u32, 2>,
};

@group(0) @binding(0) var<storage, read> in_buf: Inputs;
@group(0) @binding(1) var<storage, read_write> out_buf: Output;

fn get_deployer_byte(i: u32) -> u32 {
    // i in [0..19]
    let w = in_buf.deployer_words[i / 4u];
    let b = i % 4u;
    return (w >> (b * 8u)) & 0xffu;
}

fn get_init_hash_byte(i: u32) -> u32 {
    // i in [0..31]
    let w = in_buf.init_hash_words[i / 4u];
    let b = i % 4u;
    return (w >> (b * 8u)) & 0xffu;
}

fn get_salt_be_byte_32(i: u32, salt_le: vec4<u32>) -> u32 {
    // Return the i-th byte (0..31) of the 32-byte salt, in big-endian.
    // Upper 16 bytes are zero; lower 16 bytes are from salt_le (128-bit).
    if (i < 16u) { return 0u; }
    let pos = i - 16u;         // 0..15 within the lower 16 bytes
    let limb_index = 3u - (pos / 4u);   // 3,2,1,0 descending for big-endian ordering
    let be_in_word = pos % 4u;          // 0..3 within the word (MSB..LSB)
    let word = select(
        select(salt_le.x, salt_le.y, limb_index == 1u),
        select(salt_le.z, salt_le.w, limb_index == 3u),
        limb_index >= 2u
    );
    let shift = (3u - be_in_word) * 8u;
    return (word >> shift) & 0xffu;
}

// Address nibble helpers and matchers
const MODE_PREFIX: u32 = 0u;
const MODE_SUFFIX: u32 = 1u;
const MODE_CONTAINS: u32 = 2u;
const MODE_MASK: u32 = 3u;
const MODE_EXACT: u32 = 4u;

fn addr_nibble(addr: ptr<function, array<u32, 20>>, idx: u32) -> u32 {
    // Nibble index 0..39: 0=high nibble of first byte, 1=low nibble of first byte, etc.
    let byte_index = idx / 2u;
    let is_high = (idx & 1u) == 0u;
    let b = (*addr)[byte_index];
    return select(b & 0x0fu, (b >> 4u) & 0x0fu, is_high);
}

fn prefix_match(addr: ptr<function, array<u32, 20>>, nib_count: u32) -> bool {
    for (var n: u32 = 0u; n < nib_count; n = n + 1u) {
        let nib = addr_nibble(addr, n);
        let want = in_buf.pattern_nibbles[n] & 0x0fu;
        if (nib != want) { return false; }
    }
    return true;
}

fn suffix_match(addr: ptr<function, array<u32, 20>>, nib_count: u32) -> bool {
    if (nib_count == 0u) { return true; }
    if (nib_count > 40u) { return false; }
    let start = 40u - nib_count;
    for (var n: u32 = 0u; n < nib_count; n = n + 1u) {
        let nib = addr_nibble(addr, start + n);
        let want = in_buf.pattern_nibbles[n] & 0x0fu;
        if (nib != want) { return false; }
    }
    return true;
}

fn contains_match(addr: ptr<function, array<u32, 20>>, nib_count: u32) -> bool {
    if (nib_count == 0u) { return true; }
    if (nib_count > 40u) { return false; }
    let last_start = 40u - nib_count;
    for (var s: u32 = 0u; s <= last_start; s = s + 1u) {
        var ok = true;
        for (var n: u32 = 0u; n < nib_count; n = n + 1u) {
            let nib = addr_nibble(addr, s + n);
            let want = in_buf.pattern_nibbles[n] & 0x0fu;
            if (nib != want) {
                ok = false;
                break;
            }
        }
        if (ok) { return true; }
    }
    return false;
}

fn exact_match(addr: ptr<function, array<u32, 20>>) -> bool {
    // Expect exactly 40 nibbles
    for (var n: u32 = 0u; n < 40u; n = n + 1u) {
        let nib = addr_nibble(addr, n);
        let want = in_buf.pattern_nibbles[n] & 0x0fu;
        if (nib != want) { return false; }
    }
    return true;
}

fn mask_match(addr: ptr<function, array<u32, 20>>) -> bool {
    // pattern_mask[n] == 1 => wildcard ('.'), skip compare
    for (var n: u32 = 0u; n < 40u; n = n + 1u) {
        if (in_buf.pattern_mask[n] != 0u) {
            continue;
        }
        let nib = addr_nibble(addr, n);
        let want = in_buf.pattern_nibbles[n] & 0x0fu;
        if (nib != want) { return false; }
    }
    return true;
}

fn pack_addr_words_le(addr: ptr<function, array<u32, 20>>, out_words: ptr<function, array<u32, 5>>) {
    // Pack 20 bytes as 5 u32 words, little-endian within each word
    for (var i: u32 = 0u; i < 5u; i = i + 1u) {
        (*out_words)[i] = 0u;
    }
    for (var i2: u32 = 0u; i2 < 20u; i2 = i2 + 1u) {
        let w = i2 / 4u;
        let shift = (i2 % 4u) * 8u;
        let v = (*addr)[i2] << shift;
        (*out_words)[w] = (*out_words)[w] | v;
    }
}

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    // Early exit if this thread is beyond the requested work items
    if (gid.x >= in_buf.work_items) {
        return;
    }

    // Compute base salt for this thread: base + gid.x (128-bit little-endian)
    var salt_le = add128_le(in_buf.base_salt.x, in_buf.base_salt.y, in_buf.base_salt.z, in_buf.base_salt.w, gid.x);
    let stride = in_buf.stride;
    let repeats = in_buf.salts_per_invocation;

    // Iterate multiple salts per invocation: salt, salt+stride, salt+2*stride, ...
    for (var t: u32 = 0u; t < repeats; t = t + 1u) {
        // Build CREATE2 preimage: 0xff || deployer(20) || salt(32) || init_code_hash(32)
        var preimage: array<u32, 200>;

        // 0xff prefix
        preimage[0] = 0xffu;

        // deployer (20 bytes) at positions 1..20
        for (var i: u32 = 0u; i < 20u; i = i + 1u) {
            preimage[1u + i] = get_deployer_byte(i);
        }

        // salt (32 bytes) at positions 21..52
        for (var i: u32 = 0u; i < 32u; i = i + 1u) {
            preimage[21u + i] = get_salt_be_byte_32(i, salt_le);
        }

        // init_code_hash (32 bytes) at positions 53..84
        for (var i: u32 = 0u; i < 32u; i = i + 1u) {
            preimage[53u + i] = get_init_hash_byte(i);
        }

        // Compute keccak256 hash
        let hash = keccak256(&preimage, 85u);

        // Address is the last 20 bytes of the 32-byte hash
        var addr: array<u32, 20>;
        addr[0] = hash[12];
        addr[1] = hash[13];
        addr[2] = hash[14];
        addr[3] = hash[15];
        addr[4] = hash[16];
        addr[5] = hash[17];
        addr[6] = hash[18];
        addr[7] = hash[19];
        addr[8] = hash[20];
        addr[9] = hash[21];
        addr[10] = hash[22];
        addr[11] = hash[23];
        addr[12] = hash[24];
        addr[13] = hash[25];
        addr[14] = hash[26];
        addr[15] = hash[27];
        addr[16] = hash[28];
        addr[17] = hash[29];
        addr[18] = hash[30];
        addr[19] = hash[31];

        // Match according to mode
        let nibs = in_buf.pattern_len;
        let mode = in_buf.match_mode;
        var ok = true;
        switch (mode) {
            case MODE_PREFIX: {
                if (nibs > 0u && !prefix_match(&addr, nibs)) { ok = false; }
            }
            case MODE_SUFFIX: {
                if (ok && nibs > 0u && !suffix_match(&addr, nibs)) { ok = false; }
            }
            case MODE_CONTAINS: {
                if (ok && !contains_match(&addr, nibs)) { ok = false; }
            }
            case MODE_MASK: {
                if (ok && !mask_match(&addr)) { ok = false; }
            }
            default: { // MODE_EXACT
                if (ok && !exact_match(&addr)) { ok = false; }
            }
        }

        if (ok) {
            // Try to record the first found result
            let prev = atomicAdd(&out_buf.found, 1u);
            if (prev == 0u) {
                // Store salt
                out_buf.salt_le = salt_le;

                // Pack and store address
                var addr_words: array<u32, 5>;
                pack_addr_words_le(&addr, &addr_words);
                for (var kk: u32 = 0u; kk < 5u; kk = kk + 1u) {
                    out_buf.addr_words[kk] = addr_words[kk];
                }
                // Early exit after recording a result
                return;
            }
        }

        // Advance salt by stride for next iteration
        salt_le = add128_le(salt_le.x, salt_le.y, salt_le.z, salt_le.w, stride);
    }
}
