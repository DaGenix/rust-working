// to convert between polynomial (A^7...1) basis A & normal basis X
// or to basis S which incorporates bit matrix of Sbox
// static A2X: [u64, ..8] = [0x9898989898989898, 0xF3F3F3F3F3F3F3F3, 0xF2F2F2F2F2F2F2F2, 0x4848484848484848, 0x0909090909090909, 0x8181818181818181, 0xA9A9A9A9A9A9A9A9, 0xFFFFFFFFFFFFFFFF];
// static X2A: [u64, ..8] = [0x6464646464646464, 0x7878787878787878, 0x6E6E6E6E6E6E6E6E, 0x8C8C8C8C8C8C8C8C, 0x6868686868686868, 0x2929292929292929, 0xDEDEDEDEDEDEDEDE, 0x6060606060606060];
// static X2S: [u64, ..8] = [0x5858585858585858, 0x2D2D2D2D2D2D2D2D, 0x9E9E9E9E9E9E9E9E, 0x0B0B0B0B0B0B0B0B, 0xDCDCDCDCDCDCDCDC, 0x0404040404040404, 0x0303030303030303, 0x2424242424242424];
// static S2X: [u64, ..8] = [0x8C8C8C8C8C8C8C8C, 0x7979797979797979, 0x0505050505050505, 0xEBEBEBEBEBEBEBEB, 0x1212121212121212, 0x0404040404040404, 0x5151515151515151, 0x5353535353535353];

static A2X: [u64, ..8] = [0x98, 0xF3, 0xF2, 0x48, 0x09, 0x81, 0xA9, 0xFF];
static X2A: [u64, ..8] = [0x64, 0x78, 0x6E, 0x8C, 0x68, 0x29, 0xDE, 0x60];
static X2S: [u64, ..8] = [0x58, 0x2D, 0x9E, 0x0B, 0xDC, 0x04, 0x03, 0x24];
static S2X: [u64, ..8] = [0x8C, 0x79, 0x05, 0xEB, 0x12, 0x04, 0x51, 0x53];

static A2X_new: [[uint, ..8], ..8] = [
    [0, 0, 0, -1, -1, 0, 0, -1],
    [-1, -1, 0, 0, -1, -1, -1, -1],
    [0, -1, 0, 0, -1, -1, -1, -1],
    [0, 0, 0, -1, 0, 0, -1, 0],
    [-1, 0, 0, -1, 0, 0, 0, 0],
    [-1, 0, 0, 0, 0, 0, 0, -1],
    [-1, 0, 0, -1, 0, -1, 0, -1],
    [-1, -1, -1, -1, -1, -1, -1, -1]
];

static X2A_new: [[uint, ..8], ..8] = [
    [0, 0, -1, 0, 0, -1, -1, 0],
    [0, 0, 0, -1, -1, -1, -1, 0],
    [0, -1, -1, -1, 0, -1, -1, 0],
    [0, 0, -1, -1, 0, 0, 0, -1],
    [0, 0, 0, -1, 0, -1, -1, 0],
    [-1, 0, 0, -1, 0, -1, 0, 0],
    [0, -1, -1, -1, -1, 0, -1, -1],
    [0, 0, 0, 0, 0, -1, -1, 0],
];

static X2S_new: [[uint, ..8], ..8] = [
    [0, 0, 0, -1, -1, 0, -1, 0],
    [-1, 0, -1, -1, 0, -1, 0, 0],
    [0, -1, -1, -1, -1, 0, 0, -1],
    [-1, -1, 0, -1, 0, 0, 0, 0],
    [0, 0, -1, -1, -1, 0, -1, -1],
    [0, 0, -1, 0, 0, 0, 0, 0],
    [-1, -1, 0, 0, 0, 0, 0, 0],
    [0, 0, -1, 0, 0, -1, 0, 0],
];

static S2X_new: [[uint, ..8], ..8] = [
    [0, 0, -1, -1, 0, 0, 0, -1],
    [-1, 0, 0, -1, -1, -1, -1, 0],
    [-1, 0, -1, 0, 0, 0, 0, 0],
    [-1, -1, 0, -1, 0, -1, -1, -1],
    [0, -1, 0, 0, -1, 0, 0, 0],
    [0, 0, -1, 0, 0, 0, 0, 0],
    [-1, 0, 0, 0, -1, 0, -1, 0],
    [-1, -1, 0, 0, -1, 0, -1, 0],
];

// multiply in GF(2^2), using normal basis (Omega^2,Omega)
fn G4_mul(x: u64, y: u64) -> u64 {
    let a = (x & 0x0202020202020202) >> 1;
    let b = (x & 0x0101010101010101);
    let c = (y & 0x0202020202020202) >> 1;
    let d = (y & 0x0101010101010101);
    let e = (a ^ b) & (c ^ d);
    let p = (a & c) ^ e;
    let q = (b & d) ^ e;
    return (p << 1) | q;
}

fn g4_mul(x: bs2_state, y: bs2_state) -> bs2_state {
    let (b, a) = x;
    let (d, c) = y;
    let e = (a ^ b) & (c ^ d);
    let p = (a & c) ^ e;
    let q = (b & d) ^ e;
    return (q, p);
}

// scale by N = Omega^2 in GF(2^2), using normal basis (Omega^2,Omega)
fn G4_scl_N(x: u64) -> u64 {
    let a = (x & 0x0202020202020202) >> 1;
    let b = (x & 0x0101010101010101);
    let p = b;
    let q = a ^ b;
    return (p << 1) | q;
}

fn g4_scl_n(x: bs2_state) -> bs2_state {
    let (b, a) = x;
    let p = b;
    let q = a ^ b;
    return (q, p);
}

// scale by N^2 = Omega in GF(2^2), using normal basis (Omega^2,Omega)
fn G4_scl_N2(x: u64) -> u64 {
    let a = (x & 0x0202020202020202) >> 1;
    let b = (x & 0x0101010101010101);
    let p = a ^ b;
    let q = a;
    return (p << 1) | q;
}

fn g4_scl_n2(x: bs2_state) -> bs2_state {
    let (b, a) = x;
    let p = a ^ b;
    let q = a;
    return (q, p);
}

// square in GF(2^2), using normal basis (Omega^2,Omega)
// NOTE: inverse is identical
fn G4_sq(x: u64) -> u64 {
    let a = (x & 0x0202020202020202) >> 1;
    let b = (x & 0x0101010101010101);
    return (b << 1) | a;
}

fn g4_sq(x: bs2_state) -> bs2_state {
    let (b, a) = x;
    return (a, b);
}

fn G4_inv(x: u64) -> u64 {
    // Same as sqaure
    return G4_sq(x);
}

fn g4_inv(x: bs2_state) -> bs2_state {
    // Same as sqaure
    return g4_sq(x);
}

// multiply in GF(2^4), using normal basis (alpha^8,alpha^2)
fn G16_mul(x: u64, y: u64) -> u64 {
    let a = (x & 0x0C0C0C0C0C0C0C0C) >> 2;
    let b = (x & 0x0303030303030303);
    let c = (y & 0x0C0C0C0C0C0C0C0C) >> 2;
    let d = (y & 0x0303030303030303);
    let e = G4_mul(a ^ b, c ^ d);
    let e = G4_scl_N(e);
    let p = G4_mul(a, c) ^ e;
    let q = G4_mul(b, d) ^ e;
    return (p << 2) | q;
}

fn g16_mul(x: bs4_state, y: bs4_state) -> bs4_state {
    let (b, a) = bs4_split(x);
    let (d, c) = bs4_split(y);
    let e = g4_mul(bs2_xor(a, b), bs2_xor(c, d));
    let e = g4_scl_n(e);
    let p = bs2_xor(g4_mul(a, c), e);
    let q = bs2_xor(g4_mul(b, d), e);
    return bs2_join(q, p);
}

// square & scale by nu in GF(2^4)/GF(2^2), normal basis (alpha^8,alpha^2)
// nu = beta^8 = N^2*alpha^2, N = w^2 */
fn G16_sq_scl(x: u64) -> u64 {
    let a = (x & 0x0C0C0C0C0C0C0C0C) >> 2;
    let b = (x & 0x0303030303030303);
    let p = G4_sq(a ^ b);
    let q = G4_scl_N2(G4_sq(b));
    return (p << 2) | q;
}

fn g16_sq_scl(x: bs4_state) -> bs4_state {
    let (b, a) = bs4_split(x);
    let p = g4_sq(bs2_xor(a, b));
    let q = g4_scl_n2(g4_sq(b));
    return bs2_join(q, p);
}

// inverse in GF(2^4), using normal basis (alpha^8,alpha^2)
fn G16_inv(x: u64) -> u64 {
    let a = (x & 0x0C0C0C0C0C0C0C0C) >> 2;
    let b = (x & 0x0303030303030303);
    let c = G4_scl_N(G4_sq(a ^ b));
    let d = G4_mul(a, b);
    let e = G4_inv(c ^ d);
    let p = G4_mul(e, b);
    let q = G4_mul(e, a);
    return (p <<2 ) | q;
}

fn g16_inv(x: bs4_state) -> bs4_state {
    let (b, a) = bs4_split(x);
    let c = g4_scl_n(g4_sq(bs2_xor(a, b)));
    let d = g4_mul(a, b);
    let e = g4_inv(bs2_xor(c, d));
    let p = g4_mul(e, b);
    let q = g4_mul(e, a);
    return bs2_join(q, p);
}

// inverse in GF(2^8), using normal basis (d^16,d)
fn G256_inv(x: u64) -> u64 {
    let a = (x & 0xF0F0F0F0F0F0F0F0) >> 4;
    let b = (x & 0x0F0F0F0F0F0F0F0F);
    let c = G16_sq_scl(a ^ b);
    let d = G16_mul(a, b);
    let e = G16_inv(c ^ d);
    let p = G16_mul(e, b);
    let q = G16_mul(e, a);
    return (p << 4) | q;
}

fn g256_inv(x: bs8_state) -> bs8_state {
    let (b, a) = bs8_split(x);
    let c = g16_sq_scl(bs4_xor(a, b));
    let d = g16_mul(a, b);
    let e = g16_inv(bs4_xor(c, d));
    let p = g16_mul(e, b);
    let q = g16_mul(e, a);
    return bs4_join(q, p);
}

fn helper(mut x: u64, b: &[u64, ..8]) -> u64 {
    let mut i = 7;
    let mut y = 0;
    while i >= 0 {
        if (x & 1) != 0 {
            y ^= b[i];
        }
        x >>= 1;
        i -= 1;
    }
    return y & 0xFF;
}

// convert to new basis in GF(2^8)
// i.e., bit matrix multiply
fn G256_newbasis(x: u64, k: &[u64, ..8]) -> u64 {
    let a = helper(x & 0x00000000000000FF, k);
    let b = helper((x & 0x000000000000FF00) >> 8, k) << 8;
    let c = helper((x & 0x0000000000FF0000) >> 16, k) << 16;
    let d = helper((x & 0x00000000FF000000) >> 24, k) << 24;
    let e = helper((x & 0x000000FF00000000) >> 32, k) << 32;
    let f = helper((x & 0x0000FF0000000000) >> 40, k) << 40;
    let g = helper((x & 0x00FF000000000000) >> 48, k) << 48;
    let h = helper((x & 0xFF00000000000000) >> 56, k) << 56;
    let t = a | b | c | d | e | f | g | h;
    return t;
}

// find Sbox of n in GF(2^8) mod POLY
fn Sbox(n: u64) -> u64 {
    let mut t = G256_newbasis(n, &A2X);
    t = G256_inv(t);
    t = G256_newbasis(t, &X2S);
    return t ^ 0x6363636363636363;
}

fn sbox(n: uint) -> uint {
    let bs = bs8(n);
    let nb = bs_newbasis(bs, &A2X_new);
    let inv = g256_inv(nb);
    let nb2 = bs_newbasis(inv, &X2S_new);
    return un_bs8(bs8_xor(nb2, (-1, -1, 0, 0, 0, -1, -1, 0)));
}

// find inverse Sbox of n in GF(2^8) mod POLY
fn iSbox(n: u64) -> u64 {
    let mut t = G256_newbasis(n, &S2X);
    t = G256_inv(t);
    t = G256_newbasis(t, &X2A);
    return t ^ 0x6363636363636363;
}

type bs8_state = (uint, uint, uint, uint, uint, uint, uint, uint);
type bs4_state = (uint, uint, uint, uint);
type bs2_state = (uint, uint);

fn bs8(x: uint) -> bs8_state {
    return (x & 1, (x >> 1) & 1, (x >> 2) & 1, (x >> 3) & 1, (x >> 4) & 1, (x >> 5) & 1,
        (x >> 6) & 1, (x >> 7) & 1);
}

fn un_bs8(bs: bs8_state) -> uint {
    let (bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7) = bs;
    return (bs0 & 1) | ((bs1 & 1) << 1) | ((bs2 & 1) << 2) | ((bs3 & 1) << 3) | ((bs4 & 1) << 4) |
        ((bs5 & 1) << 5) | ((bs6 & 1) << 6) | ((bs7 & 1) << 7);
}

fn bs4(x: uint) -> bs4_state {
    return (x & 1, (x >> 1) & 1, (x >> 2) & 1, (x >> 3) & 1);
}

fn un_bs4(bs: bs4_state) -> uint {
    let (bs0, bs1, bs2, bs3) = bs;
    return (bs0 & 1) | ((bs1 & 1) << 1) | ((bs2 & 1) << 2) | ((bs3 & 1) << 3);
}

fn bs2(x: uint) -> bs2_state {
    return (x & 1, (x >> 1) & 1);
}

fn un_bs2(bs: bs2_state) -> uint {
    let (bs0, bs1) = bs;
    return (bs0 & 1) | ((bs1 & 1) << 1);
}

fn bs8_split(bs8: bs8_state) -> (bs4_state, bs4_state) {
    match bs8 {
        (bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7) => ((bs0, bs1, bs2, bs3), (bs4, bs5, bs6, bs7))
    }
}

fn bs4_split(bs4: bs4_state) -> (bs2_state, bs2_state) {
    match bs4 {
        (bs0, bs1, bs2, bs3) => ((bs0, bs1), (bs2, bs3))
    }
}

fn bs8_xor(a: bs8_state, b: bs8_state) -> bs8_state {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = a;
    let (b0, b1, b2, b3, b4, b5, b6, b7) = b;
    (a0 ^ b0, a1 ^ b1, a2 ^ b2, a3 ^ b3, a4 ^ b4, a5 ^ b5, a6 ^ b6, a7 ^ b7)
}

fn bs4_xor(a: bs4_state, b: bs4_state) -> bs4_state {
    let (a0, a1, a2, a3) = a;
    let (b0, b1, b2, b3) = b;
    (a0 ^ b0, a1 ^ b1, a2 ^ b2, a3 ^ b3)
}

fn bs2_xor(a: bs2_state, b: bs2_state) -> bs2_state {
    let (a0, a1) = a;
    let (b0, b1) = b;
    (a0 ^ b0, a1 ^ b1)
}

fn bs4_join(a: bs4_state, b: bs4_state) -> bs8_state {
    let (a0, a1, a2, a3) = a;
    let (b0, b1, b2, b3) = b;
    (a0, a1, a2, a3, b0, b1, b2, b3)
}

fn bs2_join(a: bs2_state, b: bs2_state) -> bs4_state {
    let (a0, a1) = a;
    let (b0, b1) = b;
    (a0, a1, b0, b1)
}

fn bs_newbasis(bs: bs8_state, arr: &[[uint, ..8], ..8]) -> bs8_state {
    let (bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7) = bs;

    let mut bs0_out = 0;
    let mut bs1_out = 0;
    let mut bs2_out = 0;
    let mut bs3_out = 0;
    let mut bs4_out = 0;
    let mut bs5_out = 0;
    let mut bs6_out = 0;
    let mut bs7_out = 0;

    macro_rules! helper( ($bs:ident, $idx:expr) => (
            {
                bs0_out ^= $bs & arr[7 - $idx][0];
                bs1_out ^= $bs & arr[7 - $idx][1];
                bs2_out ^= $bs & arr[7 - $idx][2];
                bs3_out ^= $bs & arr[7 - $idx][3];
                bs4_out ^= $bs & arr[7 - $idx][4];
                bs5_out ^= $bs & arr[7 - $idx][5];
                bs6_out ^= $bs & arr[7 - $idx][6];
                bs7_out ^= $bs & arr[7 - $idx][7];
            }
        )
    )

    helper!(bs0, 0);
    helper!(bs1, 1);
    helper!(bs2, 2);
    helper!(bs3, 3);
    helper!(bs4, 4);
    helper!(bs5, 5);
    helper!(bs6, 6);
    helper!(bs7, 7);

    return (bs0_out, bs1_out, bs2_out, bs3_out, bs4_out, bs5_out, bs6_out, bs7_out);
}


/*
fn bs(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let bs0 =
        // 0th bit of all input bytes
        ((a >> 0) & 1) | ((a >>  8) & 1) | ((a >> 16) & 1) | ((a >> 24) & 1) |
        ((b >> 0) & 1) | ((b >>  8) & 1) | ((b >> 16) & 1) | ((c >> 24) & 1) |
        ((c >> 0) & 1) | ((c >>  8) & 1) | ((c >> 16) & 1) | ((c >> 24) & 1) |
        ((d >> 0) & 1) | ((d >>  8) & 1) | ((d >> 16) & 1) | ((d >> 24) & 1) |

        // 4th bit of all input bytes
        ((a >> 4) &  1) | ((a >> 12) & 1) | ((a >> 20) & 1) | ((a >> 28) & 1) |
        ((b >> 4) &  1) | ((b >> 12) & 1) | ((b >> 20) & 1) | ((b >> 28) & 1) |
        ((c >> 4) &  1) | ((c >> 12) & 1) | ((c >> 20) & 1) | ((c >> 28) & 1) |
        ((d >> 4) &  1) | ((d >> 12) & 1) | ((d >> 20) & 1) | ((d >> 28) & 1);

    let bs1 =
        // 1st bit of all input bytes
        ((a >> 1) & 1) | ((a >> 9) & 1) | ((a >> 17) & 1) | ((a >> 25) & 1) |
        ((b >> 1) & 1) | ((b >> 9) & 1) | ((b >> 17) & 1) | ((c >> 25) & 1) |
        ((c >> 1) & 1) | ((c >> 9) & 1) | ((c >> 17) & 1) | ((c >> 25) & 1) |
        ((d >> 1) & 1) | ((d >> 9) & 1) | ((d >> 17) & 1) | ((d >> 25) & 1) |

        // 5th bit of all input bytes
        ((a >> 5) & 1) | ((a >> 13) & 1) | ((a >> 21) & 1) | ((a >> 29) & 1) |
        ((b >> 5) & 1) | ((b >> 13) & 1) | ((b >> 21) & 1) | ((b >> 29) & 1) |
        ((c >> 5) & 1) | ((c >> 13) & 1) | ((c >> 21) & 1) | ((c >> 29) & 1) |
        ((d >> 5) & 1) | ((d >> 13) & 1) | ((d >> 21) & 1) | ((d >> 29) & 1);

    let bs2 =
        // 2nd bit of all input bytes
        ((a >> 2) & 1) | ((a >> 10) & 1) | ((a >> 18) & 1) | ((a >> 26) & 1) |
        ((b >> 2) & 1) | ((b >> 10) & 1) | ((b >> 18) & 1) | ((c >> 26) & 1) |
        ((c >> 2) & 1) | ((c >> 10) & 1) | ((c >> 18) & 1) | ((c >> 26) & 1) |
        ((d >> 2) & 1) | ((d >> 10) & 1) | ((d >> 18) & 1) | ((d >> 26) & 1) |

        // 6th bit of all input bytes
        ((a >> 6) & 1) | ((a >> 14) & 1) | ((a >> 22) & 1) | ((a >> 30) & 1) |
        ((b >> 6) & 1) | ((b >> 14) & 1) | ((b >> 22) & 1) | ((b >> 30) & 1) |
        ((c >> 6) & 1) | ((c >> 14) & 1) | ((c >> 22) & 1) | ((c >> 30) & 1) |
        ((d >> 6) & 1) | ((d >> 14) & 1) | ((d >> 22) & 1) | ((d >> 30) & 1);

    let bs3 =
        // 3rd bit of all input bytes
        ((a >> 3) & 1) | ((a >> 11) & 1) | ((a >> 19) & 1) | ((a >> 27) & 1) |
        ((b >> 3) & 1) | ((b >> 11) & 1) | ((b >> 19) & 1) | ((c >> 27) & 1) |
        ((c >> 3) & 1) | ((c >> 11) & 1) | ((c >> 19) & 1) | ((c >> 27) & 1) |
        ((d >> 3) & 1) | ((d >> 11) & 1) | ((d >> 19) & 1) | ((d >> 27) & 1) |

        // 7th bit of all input bytes
        ((a >> 7) & 1) | ((a >> 15) & 1) | ((a >> 23) & 1) | ((a >> 31) & 1) |
        ((b >> 7) & 1) | ((b >> 15) & 1) | ((b >> 23) & 1) | ((b >> 31) & 1) |
        ((c >> 7) & 1) | ((c >> 15) & 1) | ((c >> 23) & 1) | ((c >> 31) & 1) |
        ((d >> 7) & 1) | ((d >> 15) & 1) | ((d >> 23) & 1) | ((d >> 31) & 1);

    return (bs0, bs1, bs2, bs3);
}

fn unbs(bs0: u32, bs1: u32, bs2: u32, bs3: u32) -> (u32, u32, u32, u32) {
    fn pick(x: u32, bit: u32, shift: u32) -> u32 {
        ((x >> bit) & 1) << shift;
    }

    let a =
        pick(bs0,  0,  0) | pick(bs1,  0,  1) | pick(bs2,  0,  2) | pick(bs3,  0,  3) |
        pick(bs0, 16,  4) | pick(bs1, 16,  5) | pick(bs0, 16,  6) | pick(bs3, 16,  7) |

        pick(bs0,  1,  8) | pick(bs1,  1,  9) | pick(bs2,  1, 10) | pick(bs3,  1, 11) |
        pick(bs0, 17, 12) | pick(bs1, 17, 13) | pick(bs2, 17, 14) | pick(bs3, 17, 15) |

        pick(bs0,  2, 16) | pick(bs1,  2, 17) | pick(bs2,  2, 18) | pick(bs3,  2, 19) |
        pick(bs0, 18, 20) | pick(bs1, 18, 21) | pick(bs2, 18, 22) | pick(bs3, 18, 23) |

        pick(bs0,  3, 24) | pick(bs1,  3, 25) | pick(bs2,  3, 26) | pick(bs3,  3, 27) |
        pick(bs0, 19, 28) | pick(bs1, 19, 29) | pick(bs2, 19, 30) | pick(bs3, 19, 31);

    let b =
        pick(bs0,  1,  0) | pick(bs1,  1,  1) | pick(bs2,  1,  2) | pick(bs3,  1,  3) |
        pick(bs0, 17,  4) | pick(bs1, 17,  5) | pick(bs0, 17,  6) | pick(bs3, 17,  7) |

        pick(bs0,  1,  8) | pick(bs1,  1,  9) | pick(bs2,  1, 10) | pick(bs3,  1, 11) |
        pick(bs0, 17, 12) | pick(bs1, 17, 13) | pick(bs2, 17, 14) | pick(bs3, 17, 15) |

        pick(bs0,  2, 16) | pick(bs1,  2, 17) | pick(bs2,  2, 18) | pick(bs3,  2, 19) |
        pick(bs0, 18, 20) | pick(bs1, 18, 21) | pick(bs2, 18, 22) | pick(bs3, 18, 23) |

        pick(bs0,  3, 24) | pick(bs1,  3, 25) | pick(bs2,  3, 26) | pick(bs3,  3, 27) |
        pick(bs0, 19, 28) | pick(bs1, 19, 29) | pick(bs2, 19, 30) | pick(bs3, 19, 31);

}
*/

fn pack(a: u32, b: u32) -> u64 {
    return (a as u64) << 32 | (b as u64);
}

fn unpack(x: u64, outa: &mut u32, outb: &mut u32) {
    *outa = (x >> 32) as u32;
    *outb = x as u32;
}


fn main() {
//     for i in range(0, 8) {
//         print("[");
//         for j in range(0, 8) {
//             if S2X[i] & (1 << j) != 0 {
//                 print("-1, ");
//             } else {
//                 print("0, ");
//             }
//         }
//         print("],\n");
//     }

//     printfln!("val: 0x%x", Sbox(0x02) as uint);

//     for x in range(0u, 256) {
//         assert!(G256_newbasis(x as u64, &X2S) as uint == un_bs(bs_newbasis(bs(x), &X2S_new)))
//     }
//
//     printfln!("real: %x", G256_newbasis(77, &A2X) as uint);
//     printfln!("new : %x", un_bs(bs_newbasis(bs(77), &A2X_new)));

//     for x in range(0u, 256) {
//         for y in range(0u, 10) {
//             assert!(G256_inv(x as u64) as uint == un_bs8(g256_inv(bs8(x))));
//         }
//     }

    for x in range(0u, 256) {
        printfln!("Sbox(%?) = %x", x, (Sbox(x as u64) & 0xff) as uint);
        printfln!("sbox(%?) = %x", x, sbox(x));
        println("");

        assert!((Sbox(x as u64) & 0xff) as uint == sbox(x));
    }
}
