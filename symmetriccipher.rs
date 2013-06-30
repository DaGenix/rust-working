// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Traits for algorithms that can function on a single
// block at a time.
pub trait SymmetricBlockEncryptor {
    fn init(&mut self, key: &[u8]);
    fn encrypt_block(&mut self, in: &[u8], out: &mut [u8]);
    fn key_size(&self) -> uint;
    fn block_size(&self) -> uint;
}
pub trait SymmetricBlockDecryptor {
    fn init(&mut self, key: &[u8]);
    fn decrypt_block(&mut self, in: &[u8], out: &mut [u8]);
    fn key_size(&self) -> uint;
    fn block_size(&self) -> uint;
}

// Traits for modes - ECB, CBC, CFB, OFB, or CTR Mode
// Depending on the mode, you may need to process data in full blocks
pub trait SymmetricEncryptionMode {

}
pub trait SymmetricDecryptionMode {

}

// Traits for working with a stream of data - may buffer data
// if less than a full block is available, depending on the
// mode being used.
pub trait SymmetricStreamEncryptor {

}
pub trait SymmetricStreamDecryptor {

}
