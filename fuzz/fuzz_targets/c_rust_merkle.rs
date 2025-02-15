// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(fuzzing, no_main)]

#[cfg(any(fuzzing, test))]
fn do_test(data: &[u8]) {
    use simplicity::ffi::tests::{ffi::SimplicityErr, run_program, TestUpTo};
    use simplicity::hashes::sha256::Midstate;
    use simplicity::jet::Elements;
    use simplicity::{BitIter, RedeemNode};

    // To decode the program length, we first try decoding the program using
    // `decode_expression` which will not error on a length check. Alternately
    // we could decode using RedeemNode::decode and then extract the length
    // from the error return.
    //
    // If the program doesn't decode, just use the first byte as a "length".
    let prog_len = {
        let mut iter = BitIter::from(data);
        match simplicity::decode::decode_expression::<_, Elements>(&mut iter) {
            Ok(_) => (iter.n_total_read() + 7) / 8,
            Err(_) => match data.first() {
                Some(&n) => core::cmp::min(data.len(), n.into()),
                None => return,
            },
        }
    };

    let (program, witness) = data.split_at(prog_len);
    let c_result = run_program(program, witness, TestUpTo::CheckOneOne);

    let prog_iter = BitIter::from(program);
    let wit_iter = BitIter::from(witness);
    let rust_result = RedeemNode::<Elements>::decode(prog_iter, wit_iter);

    match (c_result, rust_result) {
        (Ok(_), Err(e)) => panic!("C accepted code that Rust rejected: {}", e),
        (Err(SimplicityErr::FailCode), Ok(_)) => {} // fine, we parse FAIL but C doesn't
        (Err(e), Ok(_)) => panic!("Rust accepted code that C rejected: {}", e),
        (Err(_), Err(_)) => {} // whatever, just skip
        (Ok(c_data), Ok(rust_data)) => {
            /*
            use simplicity::dag::{DagLike, InternalSharing};
            for data in rust_data.as_ref().post_order_iter::<InternalSharing>() {
                println!("{}: {} [{:?} {:?}]", data.index, data.node.inner(), data.left_index, data.right_index);
            }
            println!("{}", rust_data.cmr());
            println!("{}", rust_data.amr());
            println!("{}", rust_data.imr());
            */
            assert_eq!(&Midstate::from(c_data.cmr)[..], rust_data.cmr().as_ref(),);
            assert_eq!(&Midstate::from(c_data.amr)[..], rust_data.amr().as_ref(),);
            assert_eq!(&Midstate::from(c_data.imr)[..], rust_data.imr().as_ref(),);
        }
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
