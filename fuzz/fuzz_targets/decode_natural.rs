// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(fuzzing, no_main)]

#[cfg(any(fuzzing, test))]
fn do_test(data: &[u8]) {
    use simplicity::encode_natural;
    use simplicity::{BitIter, BitWriter};

    let mut iter = BitIter::new(data.iter().cloned());

    if let Ok(natural) = iter.read_natural(None) {
        let bit_len = iter.n_total_read();

        let mut sink = Vec::<u8>::new();
        let mut w = BitWriter::from(&mut sink);
        encode_natural(natural, &mut w).expect("encoding to vector");
        w.flush_all().expect("flushing");
        assert_eq!(w.n_total_written(), bit_len);

        // decode_natural() may stop reading `data` mid-byte:
        // copy trailing bits from `data` to `sink`
        if bit_len % 8 != 0 {
            let mask = !(1u8 << (8 - (bit_len % 8)));
            let idx = sink.len() - 1;
            sink[idx] |= data[idx] & mask;
        }
        assert_eq!(sink, &data[0..sink.len()]);
    }
}

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data| do_test(data));

#[cfg(not(fuzzing))]
fn main() {}

#[cfg(test)]
mod tests {
    use base64::Engine;

    #[test]
    fn duplicate_crash() {
        let data = base64::prelude::BASE64_STANDARD
            .decode("Cg==")
            .expect("base64 should be valid");
        super::do_test(&data);
    }
}
