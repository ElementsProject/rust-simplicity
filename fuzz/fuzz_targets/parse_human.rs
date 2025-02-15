// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(fuzzing, no_main)]

#[cfg(any(fuzzing, test))]
fn do_test(data: &[u8]) {
    use simplicity::human_encoding::Forest;
    use simplicity::jet::Elements;

    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    if let Ok(program) = Forest::<Elements>::parse(s) {
        let reserialize = program.string_serialize();
        let round_trip = Forest::<Elements>::parse(&reserialize).unwrap();
        assert_eq!(program, round_trip);
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
