// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::vec::bytes::{MutableByteVector, copy_memory};


/// Write a u64 into a vector, which must be 8 bytes long. The value is written in big-endian
/// format.
pub fn write_u64_be(dst: &mut[u8], in: u64) {
    use std::cast::transmute;
    use std::unstable::intrinsics::to_be64;
    assert!(dst.len() == 8);
    unsafe {
        let x: *mut i64 = transmute(dst.unsafe_mut_ref(0));
        *x = to_be64(in as i64);
    }
}

/// Write a u32 into a vector, which must be 4 bytes long. The value is written in big-endian
/// format.
pub fn write_u32_be(dst: &mut[u8], in: u32) {
    use std::cast::transmute;
    use std::unstable::intrinsics::to_be32;
    assert!(dst.len() == 4);
    unsafe {
        let x: *mut i32 = transmute(dst.unsafe_mut_ref(0));
        *x = to_be32(in as i32);
    }
}

/// Read a vector of bytes into a vector of u64s. The values are read in big-endian format.
pub fn read_u64v_be(dst: &mut[u64], in: &[u8]) {
    use std::cast::transmute;
    use std::unstable::intrinsics::to_be64;
    assert!(dst.len() * 8 == in.len());
    unsafe {
        let mut x: *mut i64 = transmute(dst.unsafe_mut_ref(0));
        let mut y: *i64 = transmute(in.unsafe_ref(0));
        for dst.len().times() {
            *x = to_be64(*y);
            x = x.offset(1);
            y = y.offset(1);
        }
    }
}

/// Read a vector of bytes into a vector of u32s. The values are read in big-endian format.
pub fn read_u32v_be(dst: &mut[u32], in: &[u8]) {
    use std::cast::transmute;
    use std::unstable::intrinsics::to_be32;
    assert!(dst.len() * 4 == in.len());
    unsafe {
        let mut x: *mut i32 = transmute(dst.unsafe_mut_ref(0));
        let mut y: *i32 = transmute(in.unsafe_ref(0));
        for dst.len().times() {
            *x = to_be32(*y);
            x = x.offset(1);
            y = y.offset(1);
        }
    }
}


macro_rules! impl_fixed_buffer( ($name:ident, $size:expr) => (
    impl $name {
        /// Create a new buffer
        pub fn new() -> $name {
            return $name {
                buffer: [0u8, ..$size],
                buffer_idx: 0
            };
        }

        /// Input a buffer a bytes. If the buffer becomes full, proccess it with the provided
        /// function and then clear the buffer.
        pub fn input(&mut self, in: &[u8], func: &fn(&[u8])) {
            let mut i = 0;

            // TODO - File a bug for this being necessary!
            let size = $size;

            // If there is already data in the buffer, copy as much as we can into that buffer
            // and process the buffer if it becomes full
            if self.buffer_idx != 0 {
                let buffer_remaining = size - self.buffer_idx;
                if in.len() >= buffer_remaining {
                        copy_memory(
                            self.buffer.mut_slice(self.buffer_idx, size),
                            in.slice_to(buffer_remaining),
                            buffer_remaining);
                    self.buffer_idx = 0;
                    func(self.buffer);
                    i += buffer_remaining;
                } else {
                    copy_memory(
                        self.buffer.mut_slice(self.buffer_idx, self.buffer_idx + in.len()),
                        in,
                        in.len());
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
            copy_memory(
                self.buffer.mut_slice(0, in_remaining),
                in.slice_from(i),
                in.len() - i);
            self.buffer_idx += in_remaining;
        }

        /// Reset the buffer.
        pub fn reset(&mut self) {
            self.buffer_idx = 0;
        }

        /// Zero the buffer up until the specified index. The buffer position currently must be less
        /// than that index.
        pub fn zero_until(&mut self, idx: uint) {
            assert!(idx >= self.buffer_idx);
            self.buffer.mut_slice(self.buffer_idx, idx).set_memory(0);
            self.buffer_idx = idx;
        }

        /// Get the current position of the buffer.
        pub fn position(&self) -> uint { self.buffer_idx }

        /// Get the number of bytes remaining in the buffer until it is full.
        pub fn remaining(&self) -> uint { $size - self.buffer_idx }

        /// Get a slice of the buffer of the specified size. There must be at least that many bytes
        /// remaining in the buffer.
        pub fn next<'s>(&'s mut self, len: uint) -> &'s mut [u8] {
            self.buffer_idx += len;
            return self.buffer.mut_slice(self.buffer_idx - len, self.buffer_idx);
        }

        /// Get the current buffer. The buffer must already be full.
        pub fn full_buffer<'s>(&'s mut self) -> &'s [u8] {
            assert!(self.buffer_idx == $size);
            self.buffer_idx = 0;
            return self.buffer.slice_to($size);
        }
    }
))

/// A fixed size buffer of 128 bytes useful for cryptographic operations.
pub struct FixedBuffer64 {
    priv buffer: [u8, ..64],
    priv buffer_idx: uint,
}
impl_fixed_buffer!(FixedBuffer64, 64)

/// A fixed size buffer of 64 bytes useful for cryptographic operations.
pub struct FixedBuffer128 {
    priv buffer: [u8, ..128],
    priv buffer_idx: uint,
}
impl_fixed_buffer!(FixedBuffer128, 128)
