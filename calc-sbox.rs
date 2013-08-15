// to convert between polynomial (A^7...1) basis A & normal basis X
// or to basis S which incorporates bit matrix of Sbox
static A2X_new: [[u32, ..8], ..8] = [
    [0, 0, 0, -1, -1, 0, 0, -1],
    [-1, -1, 0, 0, -1, -1, -1, -1],
    [0, -1, 0, 0, -1, -1, -1, -1],
    [0, 0, 0, -1, 0, 0, -1, 0],
    [-1, 0, 0, -1, 0, 0, 0, 0],
    [-1, 0, 0, 0, 0, 0, 0, -1],
    [-1, 0, 0, -1, 0, -1, 0, -1],
    [-1, -1, -1, -1, -1, -1, -1, -1]
];
static X2A_new: [[u32, ..8], ..8] = [
    [0, 0, -1, 0, 0, -1, -1, 0],
    [0, 0, 0, -1, -1, -1, -1, 0],
    [0, -1, -1, -1, 0, -1, -1, 0],
    [0, 0, -1, -1, 0, 0, 0, -1],
    [0, 0, 0, -1, 0, -1, -1, 0],
    [-1, 0, 0, -1, 0, -1, 0, 0],
    [0, -1, -1, -1, -1, 0, -1, -1],
    [0, 0, 0, 0, 0, -1, -1, 0],
];
static X2S_new: [[u32, ..8], ..8] = [
    [0, 0, 0, -1, -1, 0, -1, 0],
    [-1, 0, -1, -1, 0, -1, 0, 0],
    [0, -1, -1, -1, -1, 0, 0, -1],
    [-1, -1, 0, -1, 0, 0, 0, 0],
    [0, 0, -1, -1, -1, 0, -1, -1],
    [0, 0, -1, 0, 0, 0, 0, 0],
    [-1, -1, 0, 0, 0, 0, 0, 0],
    [0, 0, -1, 0, 0, -1, 0, 0],
];
static S2X_new: [[u32, ..8], ..8] = [
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
fn g4_mul(x: bs2_state, y: bs2_state) -> bs2_state {
    let (b, a) = x;
    let (d, c) = y;
    let e = (a ^ b) & (c ^ d);
    let p = (a & c) ^ e;
    let q = (b & d) ^ e;
    return (q, p);
}

// scale by N = Omega^2 in GF(2^2), using normal basis (Omega^2,Omega)
fn g4_scl_n(x: bs2_state) -> bs2_state {
    let (b, a) = x;
    let p = b;
    let q = a ^ b;
    return (q, p);
}

// scale by N^2 = Omega in GF(2^2), using normal basis (Omega^2,Omega)
fn g4_scl_n2(x: bs2_state) -> bs2_state {
    let (b, a) = x;
    let p = a ^ b;
    let q = a;
    return (q, p);
}

// square in GF(2^2), using normal basis (Omega^2,Omega)
// NOTE: inverse is identical
fn g4_sq(x: bs2_state) -> bs2_state {
    let (b, a) = x;
    return (a, b);
}

fn g4_inv(x: bs2_state) -> bs2_state {
    // Same as sqaure
    return g4_sq(x);
}

// multiply in GF(2^4), using normal basis (alpha^8,alpha^2)
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
fn g16_sq_scl(x: bs4_state) -> bs4_state {
    let (b, a) = bs4_split(x);
    let p = g4_sq(bs2_xor(a, b));
    let q = g4_scl_n2(g4_sq(b));
    return bs2_join(q, p);
}

// inverse in GF(2^4), using normal basis (alpha^8,alpha^2)
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
fn g256_inv(x: bs8_state) -> bs8_state {
    let (b, a) = bs8_split(x);
    let c = g16_sq_scl(bs4_xor(a, b));
    let d = g16_mul(a, b);
    let e = g16_inv(bs4_xor(c, d));
    let p = g16_mul(e, b);
    let q = g16_mul(e, a);
    return bs4_join(q, p);
}

fn bs_newbasis(bs: bs8_state, arr: &[[u32, ..8], ..8]) -> bs8_state {
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

// find Sbox of n in GF(2^8) mod POLY
fn sbox(bs: bs8_state) -> bs8_state {
    let nb = bs_newbasis(bs, &A2X_new);
    let inv = g256_inv(nb);
    let nb2 = bs_newbasis(inv, &X2S_new);
    return bs8_xor(nb2, (-1, -1, 0, 0, 0, -1, -1, 0));
}

// find inverse Sbox of n in GF(2^8) mod POLY
fn isbox(bs: bs8_state) -> bs8_state {
    let nb = bs_newbasis(bs, &S2X_new);
    let inv = g256_inv(nb);
    let nb2 = bs_newbasis(inv, &X2A_new);
    return bs8_xor(nb2, (-1, -1, 0, 0, 0, -1, -1, 0));
}


type bs8_state = (u32, u32, u32, u32, u32, u32, u32, u32);
type bs4_state = (u32, u32, u32, u32);
type bs2_state = (u32, u32);

fn pick(x: u32, bit: u32, shift: u32) -> u32 {
    ((x >> bit) & 1) << shift
}

fn construct(a: u32, b: u32, c: u32, d: u32, bit: u32) -> u32 {
    pick(a, bit, 0)  | pick(a, bit + 8, 1)  | pick(a, bit + 16, 2)  | pick(a, bit + 24, 3) |
    pick(b, bit, 4)  | pick(b, bit + 8, 5)  | pick(b, bit + 16, 6)  | pick(b, bit + 24, 7) |
    pick(c, bit, 8)  | pick(c, bit + 8, 9)  | pick(c, bit + 16, 10) | pick(c, bit + 24, 11) |
    pick(d, bit, 12) | pick(d, bit + 8, 13) | pick(d, bit + 16, 14) | pick(d, bit + 24, 15)
}

fn bs8(a: u32, b: u32, c: u32, d: u32) -> bs8_state {
    let bs0 = construct(a, b, c, d, 0);
    let bs1 = construct(a, b, c, d, 1);
    let bs2 = construct(a, b, c, d, 2);
    let bs3 = construct(a, b, c, d, 3);
    let bs4 = construct(a, b, c, d, 4);
    let bs5 = construct(a, b, c, d, 5);
    let bs6 = construct(a, b, c, d, 6);
    let bs7 = construct(a, b, c, d, 7);
    return (bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7);
}

fn deconstruct(bs: bs8_state, bit: u32) -> u32 {
    let (bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7) = bs;

    pick(bs0, bit, 0) | pick(bs1, bit, 1) | pick(bs2, bit, 2) | pick(bs3, bit, 3) |
    pick(bs4, bit, 4) | pick(bs5, bit, 5) | pick(bs6, bit, 6) | pick(bs7, bit, 7) |

    pick(bs0, bit + 1, 8) | pick(bs1, bit + 1, 9) | pick(bs2, bit + 1, 10) | pick(bs3, bit + 1, 11) |
    pick(bs4, bit + 1, 12) | pick(bs5, bit + 1, 13) | pick(bs6, bit + 1, 14) | pick(bs7, bit + 1, 15) |

    pick(bs0, bit + 2, 16) | pick(bs1, bit + 2, 17) | pick(bs2, bit + 2, 18) | pick(bs3, bit + 2, 19) |
    pick(bs4, bit + 2, 20) | pick(bs5, bit + 2, 21) | pick(bs6, bit + 2, 22) | pick(bs7, bit + 2, 23) |

    pick(bs0, bit + 3, 24) | pick(bs1, bit + 3, 25) | pick(bs2, bit + 3, 26) | pick(bs3, bit + 3, 27) |
    pick(bs4, bit + 3, 28) | pick(bs5, bit + 3, 29) | pick(bs6, bit + 3, 30) | pick(bs7, bit + 3, 31)
}

fn un_bs8(bs: bs8_state) -> (u32, u32, u32, u32) {
    let a0 = deconstruct(bs, 0);
    let a1 = deconstruct(bs, 4);
    let a2 = deconstruct(bs, 8);
    let a3 = deconstruct(bs, 12);
    return (a0, a1, a2, a3);
}


fn bs4(x: u32) -> bs4_state {
    return (x & 1, (x >> 1) & 1, (x >> 2) & 1, (x >> 3) & 1);
}

fn un_bs4(bs: bs4_state) -> u32 {
    let (bs0, bs1, bs2, bs3) = bs;
    return (bs0 & 1) | ((bs1 & 1) << 1) | ((bs2 & 1) << 2) | ((bs3 & 1) << 3);
}

fn bs2(x: u32) -> bs2_state {
    return (x & 1, (x >> 1) & 1);
}

fn un_bs2(bs: bs2_state) -> u32 {
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

fn shift_rows(bs: bs8_state) -> bs8_state {
    let (bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7) = bs;

    fn sr(x: u32) -> u32 {
        // first 4 bits represent first row - don't shift
        (x & 0x000f) |
        // next 4 bits represent 2nd row - left rotate 1 bit
        ((x & 0x00e0) >> 1) | ((x & 0x0010) << 3) |
        // next 4 bits represent 3rd row - left rotate 2 bits
        ((x & 0x0c00) >> 2) | ((x & 0x0300) << 2) |
        // next 4 bits represent 4th row - left rotate 3 bits
        ((x & 0x8000) >> 3) | ((x & 0x7000) << 1)
    }

    (sr(bs0), sr(bs1), sr(bs2), sr(bs3), sr(bs4), sr(bs5), sr(bs6), sr(bs7))
}


fn mix_columns(bs: bs8_state) -> bs8_state {
    let (bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7) = bs;

    fn rl4(x: u32) -> u32 {
        ((x >> 4) & 0x0fff) | (x << 12)
    }

    fn rl8(x: u32) -> u32 {
        ((x >> 8) & 0x00ff) | (x << 8)
    }

    let bs0out = (bs7 ^ rl4(bs7)) ^ rl4(bs0) ^ rl8(bs0 ^ rl4(bs0));
    let bs1out = (bs0 ^ rl4(bs0)) ^ (bs7 ^ rl4(bs7)) ^ rl4(bs1) ^ rl8(bs1 ^ rl4(bs1));
    let bs2out = (bs1 ^ rl4(bs1)) ^ rl4(bs2) ^ rl8(bs2 ^ rl4(bs2));
    let bs3out = (bs2 ^ rl4(bs2)) ^ (bs7 ^ rl4(bs7)) ^ rl4(bs3) ^ rl8(bs3 ^ rl4(bs3));
    let bs4out = (bs3 ^ rl4(bs3)) ^ (bs7 ^ rl4(bs7)) ^ rl4(bs4) ^ rl8(bs4 ^ rl4(bs4));
    let bs5out = (bs4 ^ rl4(bs4)) ^ rl4(bs5) ^ rl8(bs5 ^ rl4(bs5));
    let bs6out = (bs5 ^ rl4(bs5)) ^ rl4(bs6) ^ rl8(bs6 ^ rl4(bs6));
    let bs7out = (bs6 ^ rl4(bs6)) ^ rl4(bs7) ^ rl8(bs7 ^ rl4(bs7));

    (bs0out, bs1out, bs2out, bs3out, bs4out, bs5out, bs6out, bs7out)
}

fn shift(r: u32, shift: u32) -> u32 {
    return (r >> shift) | (r << (32 - shift));
}

fn ffmulx(x: u32) -> u32 {
    static m1: u32 = 0x80808080;
    static m2: u32 = 0x7f7f7f7f;
    static m3: u32 = 0x0000001b;

    return ((x & m2) << 1) ^ (((x & m1) >> 7) * m3);
}

// Mix columns step
fn mcol(x: u32) -> u32 {
    let f2 = ffmulx(x);
    return f2 ^ shift(x ^ f2, 8) ^ shift(x, 16) ^ shift(x, 24);
}


fn main() {
    let a: u32 = 0xdb;
    let b: u32 = 0x13;
    let c: u32 = 0x53;
    let d: u32 = 0x45;

    let (ap, bp, cp, dp) = un_bs8(mix_columns(bs8(a, b, c, d)));

    printfln!("a: %x", ap as uint);
    printfln!("b: %x", bp as uint);
    printfln!("c: %x", cp as uint);
    printfln!("d: %x", dp as uint);
    println("");

//     let ap2 = mcol(((a & 0xff) >> 0) ^ ((b & 0xff) << 8) ^ ((c & 0xff) << 16) ^ ((d & 0xff) << 24));
//     let bp2 = mcol(((a & 0xff00) >> 8) ^ ((b & 0xff00) << 0) ^ ((c & 0xff00) << 8) ^ ((d & 0xff00) << 16));
//     let cp2 = mcol(((a & 0xff0000) >> 16) ^ ((b & 0xff0000) >> 8) ^ ((c & 0xff0000) >> 0) ^ ((d & 0xff0000) << 8));
//     let dp2 = mcol(((a & 0xff000000) >> 24) ^ ((b & 0xff000000) >> 16) ^ ((c & 0xff000000) >> 8) ^ ((d & 0xff000000) << 0));

//     printfln!("a: %x", ap2 as uint);
//     printfln!("b: %x", bp2 as uint);
//     printfln!("c: %x", cp2 as uint);
//     printfln!("d: %x", dp2 as uint);

    printfln!("r: %x", mcol(0x45_53_13_db) as uint);


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

//     printfln!("val: 0x%x", Sbox(0x02) as u32);

//     for x in range(0u, 256) {
//         assert!(G256_newbasis(x as u64, &X2S) as u32 == un_bs(bs_newbasis(bs(x), &X2S_new)))
//     }
//
//     printfln!("real: %x", G256_newbasis(77, &A2X) as u32);
//     printfln!("new : %x", un_bs(bs_newbasis(bs(77), &A2X_new)));

//     for x in range(0u, 256) {
//         for y in range(0u, 10) {
//             assert!(G256_inv(x as u64) as u32 == un_bs8(g256_inv(bs8(x))));
//         }
//     }

//     for x in range(0u, 256) {
//         printfln!("Sbox(%?) = %x", x, (Sbox(x as u64) & 0xff) as u32);
//         printfln!("sbox(%?) = %x", x, sbox(x));
//         println("");
//
//         assert!((iSbox(x as u64) & 0xff) as u32 == isbox(x));
//     }

//     let a = 0x03020100u32;
//     let b = 0x07060504u32;
//     let c = 0x0c0b0a09u32;
//     let d = 0x0f0e0f0du32;
//
//     let (ap, bp, cp, dp) = un_bs8(sbox(bs8(a, b, c, d)));
//
//     printfln!("a: %x", ap as uint);
//     printfln!("b: %x", bp as uint);
//     printfln!("c: %x", cp as uint);
//     printfln!("d: %x", dp as uint);
}


