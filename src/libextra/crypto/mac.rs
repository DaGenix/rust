// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use cryptoutil::fixed_time_eq;


/// TMP
pub trait Mac {
    /// TMP
    fn input(&mut self, data: &[u8]);

    /// TMP
    fn reset(&mut self);

    /// TMP
    fn result(&mut self) -> MacResult;

    /// TMP
    fn raw_result(&mut self, output: &mut [u8]);

    /// TMP
    fn output_bytes(&self) -> uint;
}


/// TMP
pub struct MacResult {
    priv code: ~[u8]
}

impl MacResult {
    /// TMP
    pub fn new(code: &[u8]) -> MacResult {
        return MacResult {
            code: code.to_owned()
        };
    }

    /// TMP
    pub fn new_from_owned(code: ~[u8]) -> MacResult {
        return MacResult {
            code: code
        };
    }

    /// TMP
    pub fn code<'s>(&'s self) -> &'s ~[u8] {
        return &'s self.code;
    }
}

impl Eq for MacResult {
    fn eq(&self, x: &MacResult) -> bool {
        let lhs = self.code();
        let rhs = x.code();
        return fixed_time_eq(*lhs, *rhs);
    }
}
