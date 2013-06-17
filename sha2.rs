use std::prelude::*;

use std::str;
use std::uint;
use std::vec;

struct Sha512 {
    xBuf: ~[u8],
    xBufOff: uint,
    byteCount1: u64,
    byteCount2: u64,
    H1: u64,
    H2: u64,
    H3: u64,
    H4: u64,
    H5: u64,
    H6: u64,
    H7: u64,
    H8: u64,
    W: ~[u64],
    wOff: uint
}

impl Sha512 {
    pub fn new() -> ~Sha512 {
        let s = ~Sha512 {
            xBuf: vec::from_elem(8, 0u8),
            xBufOff: 0,
            byteCount1: 0,
            byteCount2: 0,
            H1: 0x6a09e667f3bcc908u64,
            H2: 0xbb67ae8584caa73bu64,
            H3: 0x3c6ef372fe94f82bu64,
            H4: 0xa54ff53a5f1d36f1u64,
            H5: 0x510e527fade682d1u64,
            H6: 0x9b05688c2b3e6c1fu64,
            H7: 0x1f83d9abfb41bd6bu64,
            H8: 0x5be0cd19137e2179u64,
            W: vec::from_elem(80, 0u64),
            wOff: 0
        };
        return s;
    }
    
    fn update(&mut self, in: u8) {
        self.xBuf[self.xBufOff] = in;
        self.xBufOff += 1;

        if (self.xBufOff == self.xBuf.len()) {
            let w = toWord(self.xBuf);
            self.processWord(w);
            self.xBufOff = 0;
        }

        self.byteCount1 += 1;
    }

    fn update_vec(&mut self, in: &[u8]) {
        // TODO - processing full blocks would be more efficient!
        for in.each() |&b| {
            self.update(b);
        }
    }

    fn finish(&mut self) {
        self.adjustByteCounts();

        let lowBitLength: u64 = self.byteCount1 << 3;
        let hiBitLength: u64 = self.byteCount2;

        //
        // add the pad bytes.
        //
        self.update(128u8);

        while self.xBufOff != 0 {
            self.update(0u8);
        }

        self.processLength(lowBitLength, hiBitLength);

        self.processBlock();
    }

    fn doFinal(&mut self) -> ~[u8] {
        self.finish();
    
        let mut out = vec::from_elem(64, 0u8);

        fromWord(self.H1, vec::mut_slice(out, 0, 8));
        fromWord(self.H2, vec::mut_slice(out, 8, 16));
        fromWord(self.H3, vec::mut_slice(out, 16, 24));
        fromWord(self.H4, vec::mut_slice(out, 24, 32));
        fromWord(self.H5, vec::mut_slice(out, 32, 40));
        fromWord(self.H6, vec::mut_slice(out, 40, 48));
        fromWord(self.H7, vec::mut_slice(out, 48, 56));
        fromWord(self.H8, vec::mut_slice(out, 56, 64));

        self.reset();
        
        return out;
    }
    
    fn reset_real(&mut self) {
        self.byteCount1 = 0;
        self.byteCount2 = 0;

        self.xBufOff = 0;
        for uint::range(0, self.xBuf.len()) |i| {
            self.xBuf[i] = 0;
        }

        self.wOff = 0;
        for uint::range(0, self.W.len()) |i| {
            self.W[i] = 0;
        }
        
        self.H1 = 0x6a09e667f3bcc908u64;
        self.H2 = 0xbb67ae8584caa73bu64;
        self.H3 = 0x3c6ef372fe94f82bu64;
        self.H4 = 0xa54ff53a5f1d36f1u64;
        self.H5 = 0x510e527fade682d1u64;
        self.H6 = 0x9b05688c2b3e6c1fu64;
        self.H7 = 0x1f83d9abfb41bd6bu64;
        self.H8 = 0x5be0cd19137e2179u64;
    }

    // TODO - doesn't need to be &mut
    fn processWord(&mut self, in: u64) {
        self.W[self.wOff] = in;
        self.wOff += 1;
        if (self.wOff == 16) {
            self.processBlock();
        }
    }
    
    fn adjustByteCounts(&mut self) {
        if (self.byteCount1 > 0x1fffffffffffffffu64) {
            self.byteCount2 += (self.byteCount1 >> 61);
            self.byteCount1 &= 0x1fffffffffffffffu64;
        }
    }
    
    fn processLength(&mut self, lowW: u64, hiW: u64) {
        if (self.wOff > 14) {
            self.processBlock();
        }

        self.W[14] = hiW;
        self.W[15] = lowW;
    }
    
    fn processBlock(&mut self) {
        self.adjustByteCounts();

        //
        // expand 16 word block into 80 word blocks.
        //
        for uint::range(16, 80) |t| {
            self.W[t] = sigma1(self.W[t - 2]) + self.W[t - 7] + sigma0(self.W[t - 15]) + self.W[t - 16];
        }

        //
        // set up working variables.
        //
        let mut a = self.H1;
        let mut b = self.H2;
        let mut c = self.H3;
        let mut d = self.H4;
        let mut e = self.H5;
        let mut f = self.H6;
        let mut g = self.H7;
        let mut h = self.H8;

        let mut t = 0;
        for uint::range(0, 10) |_| {
            // t = 8 * i
            h += sum1(e) + ch(e, f, g) + K[t] + self.W[t]; t += 1;
            d += h;
            h += sum0(a) + maj(a, b, c);

            // t = 8 * i + 1
            g += sum1(d) + ch(d, e, f) + K[t] + self.W[t]; t += 1;
            c += g;
            g += sum0(h) + maj(h, a, b);

            // t = 8 * i + 2
            f += sum1(c) + ch(c, d, e) + K[t] + self.W[t]; t += 1;
            b += f;
            f += sum0(g) + maj(g, h, a);

            // t = 8 * i + 3
            e += sum1(b) + ch(b, c, d) + K[t] + self.W[t]; t += 1;
            a += e;
            e += sum0(f) + maj(f, g, h);

            // t = 8 * i + 4
            d += sum1(a) + ch(a, b, c) + K[t] + self.W[t]; t += 1;
            h += d;
            d += sum0(e) + maj(e, f, g);

            // t = 8 * i + 5
            c += sum1(h) + ch(h, a, b) + K[t] + self.W[t]; t += 1;
            g += c;
            c += sum0(d) + maj(d, e, f);

            // t = 8 * i + 6
            b += sum1(g) + ch(g, h, a) + K[t] + self.W[t]; t += 1;
            f += b;
            b += sum0(c) + maj(c, d, e);

            // t = 8 * i + 7
            a += sum1(f) + ch(f, g, h) + K[t] + self.W[t]; t += 1;
            e += a;
            a += sum0(b) + maj(b, c, d);
        }
 
        self.H1 += a;
        self.H2 += b;
        self.H3 += c;
        self.H4 += d;
        self.H5 += e;
        self.H6 += f;
        self.H7 += g;
        self.H8 += h;

        //
        // reset the offset and clean out the word buffer.
        //
        self.wOff = 0;
        for uint::range(0, 16) |i| {
            self.W[i] = 0;
        }
    }
}

trait Digest {
    fn input(&mut self, d: &[u8]);

    fn input_str(&mut self, d: &str);

    fn result(&mut self) -> ~[u8];

    fn result_str(&mut self) -> ~str;

    fn reset(&mut self);
}

impl Digest for Sha512 {
    fn input(&mut self, d: &[u8]) {
        self.update_vec(d);
    }

    fn input_str(&mut self, d: &str) {
        self.update_vec(d.as_bytes());
    }

    fn result(&mut self) -> ~[u8] {
        return self.doFinal();
    }

    // TODO - if you call result() should that reset the digest? What if the next call is result_str()?
    
    fn result_str(&mut self) -> ~str {
        return toHex(self.doFinal());
    }

    fn reset(&mut self) {
        self.reset_real();
    }
}

static K: [u64, ..80] = [
    0x428a2f98d728ae22u64, 0x7137449123ef65cdu64, 0xb5c0fbcfec4d3b2fu64, 0xe9b5dba58189dbbcu64,
    0x3956c25bf348b538u64, 0x59f111f1b605d019u64, 0x923f82a4af194f9bu64, 0xab1c5ed5da6d8118u64,
    0xd807aa98a3030242u64, 0x12835b0145706fbeu64, 0x243185be4ee4b28cu64, 0x550c7dc3d5ffb4e2u64,
    0x72be5d74f27b896fu64, 0x80deb1fe3b1696b1u64, 0x9bdc06a725c71235u64, 0xc19bf174cf692694u64,
    0xe49b69c19ef14ad2u64, 0xefbe4786384f25e3u64, 0x0fc19dc68b8cd5b5u64, 0x240ca1cc77ac9c65u64,
    0x2de92c6f592b0275u64, 0x4a7484aa6ea6e483u64, 0x5cb0a9dcbd41fbd4u64, 0x76f988da831153b5u64,
    0x983e5152ee66dfabu64, 0xa831c66d2db43210u64, 0xb00327c898fb213fu64, 0xbf597fc7beef0ee4u64,
    0xc6e00bf33da88fc2u64, 0xd5a79147930aa725u64, 0x06ca6351e003826fu64, 0x142929670a0e6e70u64,
    0x27b70a8546d22ffcu64, 0x2e1b21385c26c926u64, 0x4d2c6dfc5ac42aedu64, 0x53380d139d95b3dfu64,
    0x650a73548baf63deu64, 0x766a0abb3c77b2a8u64, 0x81c2c92e47edaee6u64, 0x92722c851482353bu64,
    0xa2bfe8a14cf10364u64, 0xa81a664bbc423001u64, 0xc24b8b70d0f89791u64, 0xc76c51a30654be30u64,
    0xd192e819d6ef5218u64, 0xd69906245565a910u64, 0xf40e35855771202au64, 0x106aa07032bbd1b8u64,
    0x19a4c116b8d2d0c8u64, 0x1e376c085141ab53u64, 0x2748774cdf8eeb99u64, 0x34b0bcb5e19b48a8u64,
    0x391c0cb3c5c95a63u64, 0x4ed8aa4ae3418acbu64, 0x5b9cca4f7763e373u64, 0x682e6ff3d6b2b8a3u64,
    0x748f82ee5defb2fcu64, 0x78a5636f43172f60u64, 0x84c87814a1f0ab72u64, 0x8cc702081a6439ecu64,
    0x90befffa23631e28u64, 0xa4506cebde82bde9u64, 0xbef9a3f7b2c67915u64, 0xc67178f2e372532bu64,
    0xca273eceea26619cu64, 0xd186b8c721c0c207u64, 0xeada7dd6cde0eb1eu64, 0xf57d4f7fee6ed178u64,
    0x06f067aa72176fbau64, 0x0a637dc5a2c898a6u64, 0x113f9804bef90daeu64, 0x1b710b35131c471bu64,
    0x28db77f523047d84u64, 0x32caab7b40c72493u64, 0x3c9ebe0a15c9bebcu64, 0x431d67c49c100d4cu64,
    0x4cc5d4becb3e42b6u64, 0x597f299cfc657e2au64, 0x5fcb6fab3ad6faecu64, 0x6c44198c4a475817u64
];

fn toWord(in: &[u8]) -> u64 {
    return (in[0] as u64) << 56 | 
           (in[1] as u64) << 48 | 
           (in[2] as u64) << 40 |
           (in[3] as u64) << 32 |
           (in[4] as u64) << 24 |
           (in[5] as u64) << 16 | 
           (in[6] as u64) << 8 | 
           (in[7] as u64);
}

fn fromWord(in: u64, out: &mut [u8]) {
    out[0] = (in >> 56) as u8;
    out[1] = (in >> 48) as u8;
    out[2] = (in >> 40) as u8;
    out[3] = (in >> 32) as u8;
    out[4] = (in >> 24) as u8;
    out[5] = (in >> 16) as u8;
    out[6] = (in >> 8) as u8;
    out[7] = (in) as u8;
}

fn ch(x: u64, y: u64, z: u64) -> u64 {
    return ((x & y) ^ ((!x) & z));
}

fn maj(x: u64, y: u64, z: u64) -> u64 {
    return ((x & y) ^ (x & z) ^ (y & z));
}

fn sum0(x: u64) -> u64 {
    return ((x << 36)|(x >> 28)) ^ ((x << 30)|(x >> 34)) ^ ((x << 25)|(x >> 39));
}

fn sum1(x: u64) -> u64 {
    return ((x << 50)|(x >> 14)) ^ ((x << 46)|(x >> 18)) ^ ((x << 23)|(x >> 41));
}

fn sigma0(x: u64) -> u64 {
    return ((x << 63)|(x >> 1)) ^ ((x << 56)|(x >> 8)) ^ (x >> 7);
}

fn sigma1(x: u64) -> u64 {
    return ((x << 45)|(x >> 19)) ^ ((x << 3)|(x >> 61)) ^ (x >> 6);
}

fn toHex(rr: &[u8]) -> ~str {
    let mut s = ~"";
    for rr.each |b| {
        let hex = uint::to_str_radix(*b as uint, 16u);
        if hex.len() == 1 {
            s += "0";
        }
        s += hex;
    }
    return s;
}

fn main() {
    let mut sha2 = Sha512::new();

    let hash = sha2.doFinal();
    println(toHex(hash));

    println("");

    sha2.update_vec("The quick brown fox".as_bytes());
    sha2.update_vec(" jumps over the lazy dog".as_bytes());
    let hash = sha2.doFinal();
    println(toHex(hash));

    println("");
    
    sha2.update_vec("The quick brown fox".as_bytes());
    sha2.update_vec(" jumps over the lazy dog.".as_bytes());
    let hash = sha2.doFinal();
    println(toHex(hash));
}

#[cfg(test)]
mod tests {
    use Sha512;
    use std::vec;

    #[test]
    fn test() {
        struct Test {
            input: ~str,
            output_str: ~str,
        }
        
        // Examples from wikipedia
        let wikipedia_tests = ~[
            Test {
                input: ~"",
                output_str: ~"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            },
            Test {
                input: ~"The quick brown fox jumps over the lazy dog",
                output_str: ~"07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
            },
            Test {
                input: ~"The quick brown fox jumps over the lazy dog.",
                output_str: ~"91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed"
            },
        ];

        let tests = wikipedia_tests;

        // Test that it works when accepting the message all at once

        let mut sh = Sha512::new();

        for tests.each |t| {
            sh.input_str(t.input);

            let out_str = sh.result_str();
            assert_eq!(out_str.len(), 128);
            assert!(out_str == t.output_str);

            sh.reset();
        }


        // Test that it works when accepting the message in pieces
        for tests.each |t| {
            let len = t.input.len();
            let mut left = len;
            while left > 0u {
                let take = (left + 1u) / 2u;
                sh.input_str(t.input.slice(len - left, take + len - left));
                left = left - take;
            }
 
            let out_str = sh.result_str();
            assert_eq!(out_str.len(), 128);
            assert!(out_str == t.output_str);

            sh.reset();
        }
    }
}
