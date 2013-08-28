// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::vec;

use digest::Digest;
use mac::{Mac, MacResult};


pub struct Hmac<D> {
    priv digest: D,
    priv block_key: ~[u8],
    priv finished: bool
}

fn derive_key(key: &[u8], mask: u8) -> ~[u8] {
    let mut x = key.to_owned();
    for i in range(0, key.len()) {
        x[i] ^= mask;
    }
    return x;
}

fn determine_block_key<D: Digest>(digest: &mut D, key: &[u8]) -> ~[u8] {
    let bs = Digest::block_size::<D>();
    let mut block_key = vec::from_elem(bs, 0u8);
    if key.len() <= bs {
        vec::bytes::copy_memory(block_key, key, key.len());
        for i in range(key.len(), block_key.len()) {
            block_key[i] = 0;
        }
    } else {
        let output_size = Digest::output_bytes::<D>();
        digest.input(key);
        digest.result(block_key.mut_slice_to(output_size));
        digest.reset();
        for i in range(output_size, block_key.len()) {
            block_key[i] = 0;
        }
    }
    return block_key;
}

impl <D: Digest> Hmac<D> {
    fn new(mut digest: D, key: &[u8]) -> Hmac<D> {
        let block_key = determine_block_key(&mut digest, key);

        digest.input(derive_key(block_key, 0x36));

        return Hmac {
            digest: digest,
            block_key: block_key,
            finished: false
        }
    }
}

impl <D: Digest> Mac for Hmac<D> {
    fn input(&mut self, data: &[u8]) {
        assert!(!self.finished);
        self.digest.input(data);
    }

    fn reset(&mut self) {
        self.digest.reset();
        self.digest.input(derive_key(self.block_key, 0x36));
        self.finished = false;
    }

    fn reset_key(&mut self, key: &[u8]) {
        self.digest.reset();
        self.block_key = determine_block_key(&mut self.digest, key);
        self.digest.input(derive_key(self.block_key, 0x36));
        self.finished = false;
    }

    fn result(&mut self) -> MacResult {
        let output_size = Digest::output_bytes::<D>();
        let mut tmp = vec::from_elem(output_size, 0u8);

        if !self.finished {
            self.digest.result(tmp);

            self.digest.reset();
            self.digest.input(derive_key(self.block_key, 0x5c));
            self.digest.input(tmp);

            self.finished = true;
        }

        self.digest.result(tmp);

        return MacResult::new_from_owned(tmp);
    }

    fn output_bytes() -> uint { Digest::output_bytes::<D>() }
}


#[cfg(test)]
mod test {
    use mac::{Mac, MacResult};
    use hmac::Hmac;
    use digest::Digest;
    use md5::Md5;
    use sha1::Md5;
    use sha2::Sha256;

    fn from_str(input: &str) -> ~[u8] {
        use std::u8;
        use std::uint;
        let mut out: ~[u8] = ~[];
        do uint::range_step(0, input.len(), 2) |i| {
            out.push(u8::from_str_radix(input.slice(i, i+2), 16).unwrap());
            true
        };
        return out;
    }

    #[test]
    fn test_hmac_md5() {
        let mut hmac = Hmac::new(Md5::new(), "key".as_bytes());
        hmac.input("The quick brown fox jumps over the lazy dog".as_bytes());
        let result = hmac.result();
        let expected = MacResult::new_from_owned(from_str("80070713463e7749b90c2dc24911e275"));
        assert!(result == expected);
    }
}
