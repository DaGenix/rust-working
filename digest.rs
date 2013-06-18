use std::uint;

pub trait Digest {
    fn input(&mut self, d: &[u8]);

    fn result(&mut self) -> ~[u8];

    fn reset(&mut self);
    
    fn output_bits() -> uint;
}

pub trait DigestUtil {
    fn input_str(&mut self, d: &str);

    fn result_str(&mut self) -> ~str;
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
    s
}

impl <T: Digest> DigestUtil for T {
    fn input_str(&mut self, d: &str) {
        self.input(d.as_bytes());
    }

    fn result_str(&mut self) -> ~str {
        toHex(self.result())
    }
}
