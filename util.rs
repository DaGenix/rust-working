// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cast::transmute;

pub fn vec_to_array64(in: &[u8]) -> &[u8, ..8] {
    if(in.len() != 8) {
        fail!();
    }
    unsafe {
        let tmp: &[u8, ..8] = transmute(in.unsafe_ref(0));
        return tmp;
    }
}

pub fn vec_to_array128(in: &[u8]) -> &[u8, ..16] {
    if(in.len() != 16) {
        fail!();
    }
    unsafe {
        let tmp: &[u8, ..16] = transmute(in.unsafe_ref(0));
        return tmp;
    }
}

pub fn vec_to_array192(in: &[u8]) -> &[u8, ..24] {
    if(in.len() != 24) {
        fail!();
    }
    unsafe {
        let tmp: &[u8, ..24] = transmute(in.unsafe_ref(0));
        return tmp;
    }
}

pub fn vec_to_array256(in: &[u8]) -> &[u8, ..32] {
    if(in.len() != 32) {
        fail!();
    }
    unsafe {
        let tmp: &[u8, ..32] = transmute(in.unsafe_ref(0));
        return tmp;
    }
}

// This should go in either 'sys' or 'os'
#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
fn cpuid(func: u32) -> (u32, u32, u32, u32) {
    let mut a = 0u32;
    let mut b = 0u32;
    let mut c = 0u32;
    let mut d = 0u32;

    unsafe {
        asm!(
        "
        movl $4, %eax;
        cpuid;
        movl %eax, $0;
        movl %ebx, $1;
        movl %ecx, $2;
        movl %edx, $3;
        "
        : "=r" (a), "=r" (b), "=r" (c), "=r" (d)
        : "r" (func)
        : "eax", "ebx", "ecx", "edx"
        : "volatile"
        )
    }

    return (a, b, c, d);
}

#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
pub fn supports_aesni() -> bool {
    let (_, _, c, _) = cpuid(1);
    return (c & 0x02000000) != 0;
}
