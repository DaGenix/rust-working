use std::uint;

pub trait Digest {
    fn input(&mut self, d: &[u8]);

    fn result(&mut self) -> ~[u8];

    fn reset(&mut self);
    
    fn output_bits() -> uint;
}

fn to_hex(rr: &[u8]) -> ~str {
    let mut s = ~"";
    for rr.each |&b| {
        let hex = uint::to_str_radix(b as uint, 16u);
        if hex.len() == 1 {
            s += "0";
        }
        s += hex;
    }
    s
}

// These functions would be better as default implementations,
// but that doesn't seem to work with the current version of Rust.

pub fn input_str<D: Digest>(digest: &mut D, in: &str) {
    digest.input(in.as_bytes());
}

pub fn result_str<D: Digest>(digest: &mut D) -> ~str {
    to_hex(digest.result())
}
