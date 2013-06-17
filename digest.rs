pub trait Digest {
    fn input(&mut self, d: &[u8]);

    fn input_str(&mut self, d: &str);

    fn result(&mut self) -> ~[u8];

    fn result_str(&mut self) -> ~str;

    fn reset(&mut self);
}
