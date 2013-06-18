// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::uint;

pub trait Digest {
    /**
     * Provide message data.
     *
     * # Arguments
     *
     * * input - A vector of message data
     */
    fn input(&mut self, input: &[u8]);

    /**
     * Retrieve the digest result. This method may be called multiple times.
     */
    fn result(&mut self) -> ~[u8];

    /**
     * Reset the digest. This method must be called after result() and before supplying more
     * data.
     */
    fn reset(&mut self);
    
    /**
     * Get the output size of the digest function, in bits.
     */
    fn output_bits() -> uint;
}

// These functions would be better as default implementations,
// but that doesn't seem to work with the current version of Rust.

/**
 * Convenience functon that feeds a string into a digest
 *
 * # Arguments
 *
 * * in The string to feed into the digest
 */
pub fn input_str<D: Digest>(digest: &mut D, in: &str) {
    digest.input(in.as_bytes());
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

/**
 * Convenience functon that retrieves the result of a digest as a
 * ~str in hexadecimal format.
 */
pub fn result_str<D: Digest>(digest: &mut D) -> ~str {
    to_hex(digest.result())
}
