// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use cryptoutil::{write_u32_le, read_u32v_le, FixedBuffer64};
use digest::Digest;


// A structure that represents that state of a digest computation for the MD5 function
struct EngineState {
    H0: u32,
    H1: u32,
    H2: u32,
    H3: u32
}

impl EngineState {
    fn new() -> EngineState {
        return EngineState {
            H0: 0x67452301,
            H1: 0xefcdab89,
            H2: 0x98badcfe,
            H3: 0x10325476
        };
    }

    fn reset(&mut self) {
        self.H0 = 0x67452301;
        self.H1 = 0xefcdab89;
        self.H2 = 0x98badcfe;
        self.H3 = 0x10325476;
    }

    fn process_block(&mut self, data: &[u8]) {
        fn rotate_left(x: u32, n: u32) -> u32 {
            return (x << n) | (x >> (32 - n));
        }

        fn F(u: u32, v: u32, w: u32) -> u32 {
            return (u & v) | (!u & w);
        }

        fn G(u: u32, v: u32, w: u32) -> u32 {
            return (u & w) | (v & !w);
        }

        fn H(u: u32, v: u32, w: u32) -> u32 {
            return u ^ v ^ w;
        }

        fn K(u: u32, v: u32, w: u32) -> u32 {
            return v ^ (u | !w);
        }

        let S11 = 7u32;
        let S12 = 12u32;
        let S13 = 17u32;
        let S14 = 22u32;

        let S21 = 5u32;
        let S22 = 9u32;
        let S23 = 14u32;
        let S24 = 20u32;

        let S31 = 4u32;
        let S32 = 11u32;
        let S33 = 16u32;
        let S34 = 23u32;

        let S41 = 6u32;
        let S42 = 10u32;
        let S43 = 15u32;
        let S44 = 21u32;

        let mut a = self.H0;
        let mut b = self.H1;
        let mut c = self.H2;
        let mut d = self.H3;

        let mut W = [0u32, ..16];

        read_u32v_le(W, data);

        //
        // Round 1 - F cycle, 16 times.
        //
        a = rotate_left(a + F(b, c, d) + W[0] + 0xd76aa478, S11) + b;
        d = rotate_left(d + F(a, b, c) + W[1] + 0xe8c7b756, S12) + a;
        c = rotate_left(c + F(d, a, b) + W[2] + 0x242070db, S13) + d;
        b = rotate_left(b + F(c, d, a) + W[3] + 0xc1bdceee, S14) + c;
        a = rotate_left(a + F(b, c, d) + W[4] + 0xf57c0faf, S11) + b;
        d = rotate_left(d + F(a, b, c) + W[5] + 0x4787c62a, S12) + a;
        c = rotate_left(c + F(d, a, b) + W[6] + 0xa8304613, S13) + d;
        b = rotate_left(b + F(c, d, a) + W[7] + 0xfd469501, S14) + c;
        a = rotate_left(a + F(b, c, d) + W[8] + 0x698098d8, S11) + b;
        d = rotate_left(d + F(a, b, c) + W[9] + 0x8b44f7af, S12) + a;
        c = rotate_left(c + F(d, a, b) + W[10] + 0xffff5bb1, S13) + d;
        b = rotate_left(b + F(c, d, a) + W[11] + 0x895cd7be, S14) + c;
        a = rotate_left(a + F(b, c, d) + W[12] + 0x6b901122, S11) + b;
        d = rotate_left(d + F(a, b, c) + W[13] + 0xfd987193, S12) + a;
        c = rotate_left(c + F(d, a, b) + W[14] + 0xa679438e, S13) + d;
        b = rotate_left(b + F(c, d, a) + W[15] + 0x49b40821, S14) + c;

        //
        // Round 2 - G cycle, 16 times.
        //
        a = rotate_left(a + G(b, c, d) + W[1] + 0xf61e2562, S21) + b;
        d = rotate_left(d + G(a, b, c) + W[6] + 0xc040b340, S22) + a;
        c = rotate_left(c + G(d, a, b) + W[11] + 0x265e5a51, S23) + d;
        b = rotate_left(b + G(c, d, a) + W[0] + 0xe9b6c7aa, S24) + c;
        a = rotate_left(a + G(b, c, d) + W[5] + 0xd62f105d, S21) + b;
        d = rotate_left(d + G(a, b, c) + W[10] + 0x02441453, S22) + a;
        c = rotate_left(c + G(d, a, b) + W[15] + 0xd8a1e681, S23) + d;
        b = rotate_left(b + G(c, d, a) + W[4] + 0xe7d3fbc8, S24) + c;
        a = rotate_left(a + G(b, c, d) + W[9] + 0x21e1cde6, S21) + b;
        d = rotate_left(d + G(a, b, c) + W[14] + 0xc33707d6, S22) + a;
        c = rotate_left(c + G(d, a, b) + W[3] + 0xf4d50d87, S23) + d;
        b = rotate_left(b + G(c, d, a) + W[8] + 0x455a14ed, S24) + c;
        a = rotate_left(a + G(b, c, d) + W[13] + 0xa9e3e905, S21) + b;
        d = rotate_left(d + G(a, b, c) + W[2] + 0xfcefa3f8, S22) + a;
        c = rotate_left(c + G(d, a, b) + W[7] + 0x676f02d9, S23) + d;
        b = rotate_left(b + G(c, d, a) + W[12] + 0x8d2a4c8a, S24) + c;

        //
        // Round 3 - H cycle, 16 times.
        //
        a = rotate_left(a + H(b, c, d) + W[5] + 0xfffa3942, S31) + b;
        d = rotate_left(d + H(a, b, c) + W[8] + 0x8771f681, S32) + a;
        c = rotate_left(c + H(d, a, b) + W[11] + 0x6d9d6122, S33) + d;
        b = rotate_left(b + H(c, d, a) + W[14] + 0xfde5380c, S34) + c;
        a = rotate_left(a + H(b, c, d) + W[1] + 0xa4beea44, S31) + b;
        d = rotate_left(d + H(a, b, c) + W[4] + 0x4bdecfa9, S32) + a;
        c = rotate_left(c + H(d, a, b) + W[7] + 0xf6bb4b60, S33) + d;
        b = rotate_left(b + H(c, d, a) + W[10] + 0xbebfbc70, S34) + c;
        a = rotate_left(a + H(b, c, d) + W[13] + 0x289b7ec6, S31) + b;
        d = rotate_left(d + H(a, b, c) + W[0] + 0xeaa127fa, S32) + a;
        c = rotate_left(c + H(d, a, b) + W[3] + 0xd4ef3085, S33) + d;
        b = rotate_left(b + H(c, d, a) + W[6] + 0x04881d05, S34) + c;
        a = rotate_left(a + H(b, c, d) + W[9] + 0xd9d4d039, S31) + b;
        d = rotate_left(d + H(a, b, c) + W[12] + 0xe6db99e5, S32) + a;
        c = rotate_left(c + H(d, a, b) + W[15] + 0x1fa27cf8, S33) + d;
        b = rotate_left(b + H(c, d, a) + W[2] + 0xc4ac5665, S34) + c;

        //
        // Round 4 - K cycle, 16 times.
        //
        a = rotate_left(a + K(b, c, d) + W[0] + 0xf4292244, S41) + b;
        d = rotate_left(d + K(a, b, c) + W[7] + 0x432aff97, S42) + a;
        c = rotate_left(c + K(d, a, b) + W[14] + 0xab9423a7, S43) + d;
        b = rotate_left(b + K(c, d, a) + W[5] + 0xfc93a039, S44) + c;
        a = rotate_left(a + K(b, c, d) + W[12] + 0x655b59c3, S41) + b;
        d = rotate_left(d + K(a, b, c) + W[3] + 0x8f0ccc92, S42) + a;
        c = rotate_left(c + K(d, a, b) + W[10] + 0xffeff47d, S43) + d;
        b = rotate_left(b + K(c, d, a) + W[1] + 0x85845dd1, S44) + c;
        a = rotate_left(a + K(b, c, d) + W[8] + 0x6fa87e4f, S41) + b;
        d = rotate_left(d + K(a, b, c) + W[15] + 0xfe2ce6e0, S42) + a;
        c = rotate_left(c + K(d, a, b) + W[6] + 0xa3014314, S43) + d;
        b = rotate_left(b + K(c, d, a) + W[13] + 0x4e0811a1, S44) + c;
        a = rotate_left(a + K(b, c, d) + W[4] + 0xf7537e82, S41) + b;
        d = rotate_left(d + K(a, b, c) + W[11] + 0xbd3af235, S42) + a;
        c = rotate_left(c + K(d, a, b) + W[2] + 0x2ad7d2bb, S43) + d;
        b = rotate_left(b + K(c, d, a) + W[9] + 0xeb86d391, S44) + c;

        self.H0 += a;
        self.H1 += b;
        self.H2 += c;
        self.H3 += d;
    }
}


// A structure that keeps track of the state of the Sha-512 operation and contains the logic
// necessary to perform the final calculations.
struct Engine {
    length: u64,
    buffer: FixedBuffer64,
    state: EngineState,
    finished: bool,
}

impl Engine {
    fn new() -> Engine {
        return Engine {
            length: 0,
            buffer: FixedBuffer64::new(),
            state: EngineState::new(),
            finished: false
        }
    }

    fn reset(&mut self) {
        self.length = 0;
        self.buffer.reset();
        self.state.reset();
        self.finished = false;
    }

    fn input(&mut self, in: &[u8]) {
        assert!(!self.finished)
        self.length += in.len() as u64;
        self.buffer.input(in, |in: &[u8]| { self.state.process_block(in) });
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }

        // Add byte with high order bit set - this must be the first byte at the end of the data.
        // The buffer always has at least one byte available, since input() always processes the
        // buffer when it gets full.
        self.buffer.next(1)[0] = 128;

        // If we have space for the bit counts in the current block, we can put them there,
        // otherwise, we need to fill the current block with 0s, process it, and then put the
        // bit count at the end of the next block and then process it.
        if self.buffer.remaining() < 8 {
            self.buffer.zero_until(64);
            self.state.process_block(self.buffer.full_buffer());
        }
        self.buffer.zero_until(56);
        write_u32_le(self.buffer.next(4), (self.length << 3) as u32);
        write_u32_le(self.buffer.next(4), (self.length >> 29) as u32);
        self.state.process_block(self.buffer.full_buffer());

        self.finished = true;
    }
}


struct Md5 {
    priv engine: Engine
}

impl Md5 {
    /**
     * Construct an new instance of a SHA-512 digest.
     */
    pub fn new() -> Md5 {
        return Md5 {
            engine: Engine::new()
        };
    }
}

impl Digest for Md5 {
    fn input(&mut self, d: &[u8]) {
        self.engine.input(d);
    }

    fn result(&mut self, out: &mut [u8]) {
        self.engine.finish();

        write_u32_le(out.mut_slice(0, 4), self.engine.state.H0);
        write_u32_le(out.mut_slice(4, 8), self.engine.state.H1);
        write_u32_le(out.mut_slice(8, 12), self.engine.state.H2);
        write_u32_le(out.mut_slice(12, 16), self.engine.state.H3);
    }

    fn reset(&mut self) {
        self.engine.reset();
    }

    fn output_bits(&self) -> uint { 128 }
}


#[cfg(test)]
mod tests {
    use digest::{Digest, DigestUtil};
    use md5::Md5;

    struct Test {
        input: ~str,
        output_str: ~str,
    }

    fn test_hash<D: Digest>(sh: &mut D, tests: &[Test]) {
        // Test that it works when accepting the message all at once
        for tests.iter().advance() |t| {
            sh.input_str(t.input);

            let out_str = sh.result_str();
            assert!(out_str == t.output_str);

            sh.reset();
        }

        // Test that it works when accepting the message in pieces
        for tests.iter().advance() |t| {
            let len = t.input.len();
            let mut left = len;
            while left > 0u {
                let take = (left + 1u) / 2u;
                sh.input_str(t.input.slice(len - left, take + len - left));
                left = left - take;
            }

            let out_str = sh.result_str();
            assert!(out_str == t.output_str);

            sh.reset();
        }
    }

    #[test]
    fn test_md5() {
        // Examples from wikipedia
        let wikipedia_tests = ~[
            Test {
                input: ~"",
                output_str: ~"d41d8cd98f00b204e9800998ecf8427e"
            },
            Test {
                input: ~"The quick brown fox jumps over the lazy dog",
                output_str: ~"9e107d9d372bb6826bd81d3542a419d6"
            },
            Test {
                input: ~"The quick brown fox jumps over the lazy dog.",
                output_str: ~"e4d909c290d0fb1ca068ffaddf22cbd0"
            },
        ];

        let tests = wikipedia_tests;

        let mut sh = Md5::new();

        test_hash(&mut sh, tests);
    }
}


#[cfg(test)]
mod bench {
    use md5::Md5;
    use extra::test::BenchHarness;


    #[bench]
    pub fn md5_10(bh: & mut BenchHarness) {
        let mut sh = Md5::new();
        let bytes = [1u8, ..10];
        do bh.iter {
            sh.input(bytes);
        }
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn md5_1k(bh: & mut BenchHarness) {
        let mut sh = Md5::new();
        let bytes = [1u8, ..1024];
        do bh.iter {
            sh.input(bytes);
        }
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn md5_64k(bh: & mut BenchHarness) {
        let mut sh = Md5::new();
        let bytes = [1u8, ..65536];
        do bh.iter {
            sh.input(bytes);
        }
        bh.bytes = bytes.len() as u64;
    }
}
