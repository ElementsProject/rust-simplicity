// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(fuzzing, no_main)]

#[cfg(any(fuzzing, test))]
fn do_test(data: &[u8]) {
    use simplicity::jet::Core;
    use simplicity::{BitIter, BitWriter, RedeemNode};

    let prog_iter = BitIter::new(data.iter().cloned());
    let wit_iter = BitIter::new(core::iter::repeat(0));
    if let Ok(program) = RedeemNode::<Core>::decode(prog_iter, wit_iter) {
        let mut prog_reser = Vec::<u8>::new();
        let mut wit_reser = std::io::sink();

        let mut prog_w = BitWriter::from(&mut prog_reser);
        let mut wit_w = BitWriter::from(&mut wit_reser);
        program
            .encode(&mut prog_w, &mut wit_w)
            .expect("encoding to vector");
        prog_w.flush_all().expect("flushing");
        wit_w.flush_all().expect("flushing");

        assert_eq!(prog_reser, &data[0..prog_reser.len()]);
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
