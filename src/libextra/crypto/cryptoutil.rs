// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// TODO - add in missing docs!
#[allow(missing_doc)];

use std::uint;


// Copy all of src into dst. The vectors must be of equal size.
pub fn copy_u8_vec(dst: &mut [u8], src: &[u8]) {
    use std::ptr::copy_memory;
    assert!(dst.len() == src.len());
    unsafe {
        copy_memory(dst.unsafe_mut_ref(0), src.unsafe_ref(0), dst.len());
    }
}

// Zero out the vector
pub fn zero_u8_vec(dst: &mut [u8]) {
    use std::ptr::zero_memory;
    unsafe {
        zero_memory(dst.unsafe_mut_ref(0), dst.len());
    }
}

// Write a u64 into the vector, which must be 8 bytes long. The value
// is written in big-endian form.
pub fn write_u64_be(dst: &mut[u8], in: u64) {
    use std::cast::transmute;
    use std::unstable::intrinsics::to_be64;
    assert!(dst.len() == 8);
    unsafe {
        let x: *mut i64 = transmute(dst.unsafe_mut_ref(0));
        *x = to_be64(in as i64);
    }
}

// Write a u32 into the vector, which must be 4 bytes long. The value
// is written in big-endian form.
pub fn write_u32_be(dst: &mut[u8], in: u32) {
    use std::cast::transmute;
    use std::unstable::intrinsics::to_be32;
    assert!(dst.len() == 4);
    unsafe {
        let x: *mut i32 = transmute(dst.unsafe_mut_ref(0));
        *x = to_be32(in as i32);
    }
}

// Read a vector of bytes into a vector of u64s. The values are read as
// if they are in big-endian format.
pub fn read_u64v_be(dst: &mut[u64], in: &[u8]) {
    use std::cast::transmute;
    use std::unstable::intrinsics::to_be64;
    assert!(dst.len() * 8 == in.len());
    unsafe {
        let mut x: *mut i64 = transmute(dst.unsafe_mut_ref(0));
        let mut y: *i64 = transmute(in.unsafe_ref(0));
        for uint::range(0, dst.len()) |_| {
            *x = to_be64(*y);
            x = x.offset(1);
            y = y.offset(1);
        }
    }
}

// Read a vector of bytes into a vector of u32s. The values are read as
// if they are in big-endian format.
pub fn read_u32v_be(dst: &mut[u32], in: &[u8]) {
    use std::cast::transmute;
    use std::unstable::intrinsics::to_be32;
    assert!(dst.len() * 4 == in.len());
    unsafe {
        let mut x: *mut i32 = transmute(dst.unsafe_mut_ref(0));
        let mut y: *i32 = transmute(in.unsafe_ref(0));
        for uint::range(0, dst.len()) |_| {
            *x = to_be32(*y);
            x = x.offset(1);
            y = y.offset(1);
        }
    }
}


macro_rules! impl_fixed_buffer( ($name:ident, $size:expr) => (
    impl $name {
        pub fn new() -> $name {
            return $name {
                buffer: [0u8, ..$size],
                buffer_idx: 0
            };
        }

        pub fn input(&mut self, in: &[u8], func: &fn(&[u8])) {
            let mut i = 0;

            // TODO - File a bug for this being necessary!
            let size = $size;

            // If there is already data in the buffer, copy as much as we can into that buffer
            // and process the buffer if it becomes full
            if self.buffer_idx != 0 {
                let buffer_remaining = size - self.buffer_idx;
                if in.len() >= buffer_remaining {
                        copy_u8_vec(self.buffer.mut_slice(self.buffer_idx, size),
                            in.slice(0, buffer_remaining));
                    self.buffer_idx = 0;
                    func(self.buffer);
                    i += buffer_remaining;
                } else {
                    copy_u8_vec(self.buffer.mut_slice(self.buffer_idx, self.buffer_idx + in.len()), in);
                    self.buffer_idx += in.len();
                    return;
                }
            }

            // While we have at least a full block's worth of data, process that data without
            // copying it into the buffer
            while in.len() - i >= size {
                func(in.slice(i, i + size));
                i += size;
            }

            // Copy any input data (which must be less than a full block) into the buffer (which
            // is currently empty)
            let in_remaining = in.len() - i;
            copy_u8_vec(self.buffer.mut_slice(0, in_remaining), in.slice(i, in.len()));
            self.buffer_idx += in_remaining;
        }

        pub fn reset(&mut self) {
            self.buffer_idx = 0;
        }

        pub fn zero_until(&mut self, idx: uint) {
            assert!(idx >= self.buffer_idx);
            zero_u8_vec(self.buffer.mut_slice(self.buffer_idx, idx));
            self.buffer_idx = idx;
        }

        pub fn position(&self) -> uint { self.buffer_idx }

        pub fn remaining(&self) -> uint { $size - self.buffer_idx }

        pub fn next<'s>(&'s mut self, len: uint) -> &'s mut [u8] {
            self.buffer_idx += len;
            return self.buffer.mut_slice(self.buffer_idx - len, self.buffer_idx);
        }

        pub fn full_buffer<'s>(&'s mut self) -> &'s [u8] {
            assert!(self.buffer_idx == $size);
            self.buffer_idx = 0;
            return self.buffer.slice(0, $size);
        }
    }
))

pub struct FixedBuffer64 {
    priv buffer: [u8, ..64],
    priv buffer_idx: uint,
}
impl_fixed_buffer!(FixedBuffer64, 64)

pub struct FixedBuffer128 {
    priv buffer: [u8, ..128],
    priv buffer_idx: uint,
}
impl_fixed_buffer!(FixedBuffer128, 128)

