// SPDX-License-Identifier: CC0-1.0

pub mod ffi;

use std::ptr;

use crate::ffi::{c_size_t, sha256::CSha256Midstate, ubounded, UBOUNDED_MAX};
use crate::tests::ffi::{
    bitstream::{simplicity_closeBitstream, CBitstream},
    dag::{
        simplicity_computeAnnotatedMerkleRoot, simplicity_fillWitnessData,
        simplicity_verifyNoDuplicateIdentityHashes, CAnalyses, CCombinatorCounters,
    },
    deserialize::simplicity_decodeMallocDag,
    eval::{simplicity_analyseBounds, simplicity_evalTCOProgram},
    type_inference::simplicity_mallocTypeInference,
    SimplicityErr,
};

/// The result of parsing, typechecking, and running a Simplicity program
/// through the C FFI
#[derive(Copy, Clone, Debug)]
pub struct TestOutput {
    /// The AMR of the root node
    pub amr: CSha256Midstate,
    /// The CMR of the root node
    pub cmr: CSha256Midstate,
    /// The IHR of the root node
    pub ihr: CSha256Midstate,
    /// The cost bound of the program
    pub cost_bound: ubounded,
    /// Whether or not evaluation succeded
    pub eval_result: SimplicityErr,
}

/// How far to run the test
///
/// If you stop the test early, the returned output will be incomplete.
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Debug)]
pub enum TestUpTo {
    /// Just decode the program, not the witnesses. Will compute and retrieve the root CMR.
    DecodeProgram,
    /// Also do type inference
    TypeInference,
    /// Fill in the witness data, now that their types are known
    FillWitnessData,
    /// Compute and retrieve the root AMR.
    ComputeAmr,
    /// Compute and retrieve the root IHR; check that all IHRs are unique
    ComputeIhr,
    /// Compute and retrieve the expected cost without any bounds
    ComputeCostUnbounded,
    /// Compute and retrieve the expected cost with strict bounds
    ComputeCostBounded,
    /// Fail the analysis if insufficient cells are provided
    CheckCellCount,
    /// Fail the analysis if insufficient budget is provided
    CheckBudget,
    /// Check that the program is 1-1. This will exclude arbitrary expressions, so
    /// you may want to stop at `ComputeIhr` to get the maximum merkle root coverage.
    CheckOneOne,
    /// Evaluate the program and retrieve whether it succeded.
    Everything,
}

/// Run a program, check its merkle roots, and that it succeeds
pub fn run_test(
    program: &[u8],
    witness: &[u8],
    target_amr: &[u32; 8],
    target_cmr: &[u32; 8],
    target_ihr: &[u32; 8],
    cost_bound: ubounded,
) {
    let result = run_program(program, witness, TestUpTo::Everything).expect("running program");
    assert_eq!(result.amr, CSha256Midstate { s: *target_amr });
    assert_eq!(result.cmr, CSha256Midstate { s: *target_cmr });
    assert_eq!(result.ihr, CSha256Midstate { s: *target_ihr });
    assert_eq!(result.cost_bound, cost_bound);
    assert_eq!(result.eval_result, SimplicityErr::NoError);
}

/// Run a program, check its merkle roots, and that it fails
pub fn run_test_fail(
    program: &[u8],
    witness: &[u8],
    target_result: SimplicityErr,
    target_amr: &[u32; 8],
    target_cmr: &[u32; 8],
    target_ihr: &[u32; 8],
    cost_bound: ubounded,
) {
    let result = run_program(program, witness, TestUpTo::Everything).expect("running program");
    assert_eq!(result.amr, CSha256Midstate { s: *target_amr });
    assert_eq!(result.cmr, CSha256Midstate { s: *target_cmr });
    assert_eq!(result.ihr, CSha256Midstate { s: *target_ihr });
    assert_eq!(result.cost_bound, cost_bound);
    assert_eq!(result.eval_result, target_result);
}

struct FreeOnDrop(*mut u8);
impl Drop for FreeOnDrop {
    fn drop(&mut self) {
        unsafe {
            crate::alloc::rust_free(self.0);
        }
    }
}

/// Run a program and return data about it
///
/// This is mostly a direct port of `run_program` in C `tests.c`.
pub fn run_program(
    program: &[u8],
    witness: &[u8],
    test_up_to: TestUpTo,
) -> Result<TestOutput, SimplicityErr> {
    let mut result = TestOutput {
        amr: CSha256Midstate::default(),
        cmr: CSha256Midstate::default(),
        ihr: CSha256Midstate::default(),
        cost_bound: 0,
        eval_result: SimplicityErr::NoError,
    };

    let mut prog_stream = CBitstream::from(program);
    let mut wit_stream = CBitstream::from(witness);
    let mut census = CCombinatorCounters::default();
    unsafe {
        // 1. Parse DAG.
        let mut dag = ptr::null_mut();
        let len = SimplicityErr::from_i32(simplicity_decodeMallocDag(
            &mut dag,
            &mut census,
            &mut prog_stream,
        ))? as usize;
        assert!(!dag.is_null());
        let _d1 = FreeOnDrop(dag as *mut u8);
        SimplicityErr::from_i32(simplicity_closeBitstream(&mut prog_stream))?;
        if test_up_to <= TestUpTo::DecodeProgram {
            return Ok(result);
        }

        // 2. Check CMR.
        result.cmr = (*dag.offset(len as isize - 1)).cmr;

        // 3. Do type inference.
        let mut type_dag = ptr::null_mut();
        simplicity_mallocTypeInference(&mut type_dag, dag, len, &census).into_result()?;
        assert!(!type_dag.is_null());
        let _d2 = FreeOnDrop(type_dag as *mut u8);
        if test_up_to <= TestUpTo::TypeInference {
            return Ok(result);
        }

        // 4. Fill witness data, now that we know the types
        simplicity_fillWitnessData(dag, type_dag, len as c_size_t, &mut wit_stream)
            .into_result()?;
        SimplicityErr::from_i32(simplicity_closeBitstream(&mut wit_stream))?;
        if test_up_to <= TestUpTo::FillWitnessData {
            return Ok(result);
        }

        // 5. Check AMR
        let mut analyses = vec![CAnalyses::default(); len];
        simplicity_computeAnnotatedMerkleRoot(analyses.as_mut_ptr(), dag, type_dag, len);
        result.amr = analyses[len - 1].annotated_merkle_root;
        if test_up_to <= TestUpTo::ComputeAmr {
            return Ok(result);
        }

        // 6. Check IHR
        simplicity_verifyNoDuplicateIdentityHashes(&mut result.ihr, dag, type_dag, len)
            .into_result()?;
        if test_up_to <= TestUpTo::ComputeIhr {
            return Ok(result);
        }

        // 7. Test cost computation
        let mut cell_bound: ubounded = 0;
        let mut word_bound: ubounded = 0;
        let mut frame_bound: ubounded = 0;
        let mut cost_bound: ubounded = 0;
        // 7a. Analysis when cost is unbounded
        simplicity_analyseBounds(
            &mut cell_bound,
            &mut word_bound,
            &mut frame_bound,
            &mut cost_bound,
            UBOUNDED_MAX,
            UBOUNDED_MAX,
            dag,
            type_dag,
            len,
        )
        .into_result()?;
        result.cost_bound = cost_bound;
        if test_up_to <= TestUpTo::ComputeCostUnbounded {
            return Ok(result);
        }
        // 7b. analysis with strict bounds
        simplicity_analyseBounds(
            &mut cell_bound,
            &mut word_bound,
            &mut frame_bound,
            &mut cost_bound,
            cell_bound,
            cost_bound,
            dag,
            type_dag,
            len,
        )
        .into_result()?;
        if test_up_to <= TestUpTo::ComputeCostBounded {
            return Ok(result);
        }
        // 7c. analysis with strict cell bounds
        if 0 < cell_bound {
            let res = simplicity_analyseBounds(
                &mut cell_bound,
                &mut word_bound,
                &mut frame_bound,
                &mut cost_bound,
                cell_bound - 1,
                cost_bound,
                dag,
                type_dag,
                len,
            )
            .into_result()
            .expect_err("should fail");
            assert_eq!(res, SimplicityErr::ExecMemory);
        }
        if test_up_to <= TestUpTo::CheckCellCount {
            return Ok(result);
        }
        // 7d. analysis with strict cost bounds
        if 0 < cost_bound {
            let res = simplicity_analyseBounds(
                &mut cell_bound,
                &mut word_bound,
                &mut frame_bound,
                &mut cost_bound,
                cell_bound,
                cost_bound - 1,
                dag,
                type_dag,
                len,
            )
            .into_result()
            .expect_err("should fail");
            assert_eq!(res, SimplicityErr::ExecBudget);
        }
        if test_up_to <= TestUpTo::CheckBudget {
            return Ok(result);
        }

        // 8. Check that thtis is a 1->1 program. This must be done before evalTCOProgram
        if (*dag.offset(len as isize - 1)).aux_types.types[0] != 0
            || (*dag.offset(len as isize - 1)).aux_types.types[1] != 0
        {
            return Err(SimplicityErr::TypeInferenceNotProgram);
        }
        if test_up_to <= TestUpTo::CheckOneOne {
            return Ok(result);
        }

        // 9. Run the program
        result.eval_result =
            simplicity_evalTCOProgram(dag, type_dag, len, ptr::null(), ptr::null());
    }

    Ok(result)
}

pub fn parse_root(ptr: &[u32; 8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    for i in 0..8 {
        let x = ptr[i];
        a[i * 4] = (x >> 24) as u8;
        a[i * 4 + 1] = (x >> 16) as u8;
        a[i * 4 + 2] = (x >> 8) as u8;
        a[i * 4 + 3] = x as u8;
    }
    a
}

/// Data structure to hold test cases from C simplicity
pub struct TestData {
    pub cmr: [u8; 32],
    pub amr: [u8; 32],
    pub ihr: [u8; 32],
    pub prog: Vec<u8>,
    pub witness: Vec<u8>,
    pub cost: ubounded,
}

#[cfg(feature = "test-utils")]
mod test_data {
    use super::*;
    use std::slice;
    pub fn schnorr0_test_data() -> TestData {
        unsafe {
            TestData {
                cmr: parse_root(&ffi::schnorr0_cmr),
                amr: parse_root(&ffi::schnorr0_amr),
                ihr: parse_root(&ffi::schnorr0_ihr),
                prog: slice::from_raw_parts(ffi::schnorr0.as_ptr(), ffi::sizeof_schnorr0).into(),
                witness: slice::from_raw_parts(
                    ffi::schnorr0_witness.as_ptr(),
                    ffi::sizeof_schnorr0_witness,
                )
                .into(),
                cost: ffi::schnorr0_cost,
            }
        }
    }

    pub fn schnorr6_test_data() -> TestData {
        unsafe {
            TestData {
                cmr: parse_root(&ffi::schnorr6_cmr),
                amr: parse_root(&ffi::schnorr6_amr),
                ihr: parse_root(&ffi::schnorr6_ihr),
                prog: slice::from_raw_parts(ffi::schnorr6.as_ptr(), ffi::sizeof_schnorr6).into(),
                witness: slice::from_raw_parts(
                    ffi::schnorr6_witness.as_ptr(),
                    ffi::sizeof_schnorr6_witness,
                )
                .into(),
                cost: ffi::schnorr6_cost,
            }
        }
    }

    pub fn ctx8_pruned_test_data() -> TestData {
        unsafe {
            TestData {
                cmr: parse_root(&ffi::ctx8Pruned_cmr),
                amr: parse_root(&ffi::ctx8Pruned_amr),
                ihr: parse_root(&ffi::ctx8Pruned_ihr),
                prog: slice::from_raw_parts(ffi::ctx8Pruned.as_ptr(), ffi::sizeof_ctx8Pruned)
                    .into(),
                witness: slice::from_raw_parts(
                    ffi::ctx8Pruned_witness.as_ptr(),
                    ffi::sizeof_ctx8Pruned_witness,
                )
                .into(),
                cost: ffi::ctx8Pruned_cost,
            }
        }
    }

    pub fn ctx8_unpruned_test_data() -> TestData {
        unsafe {
            TestData {
                cmr: parse_root(&ffi::ctx8Unpruned_cmr),
                amr: parse_root(&ffi::ctx8Unpruned_amr),
                ihr: parse_root(&ffi::ctx8Unpruned_ihr),
                prog: slice::from_raw_parts(ffi::ctx8Unpruned.as_ptr(), ffi::sizeof_ctx8Unpruned)
                    .into(),
                witness: slice::from_raw_parts(
                    ffi::ctx8Unpruned_witness.as_ptr(),
                    ffi::sizeof_ctx8Unpruned_witness,
                )
                .into(),
                cost: ffi::ctx8Unpruned_cost,
            }
        }
    }
}

#[cfg(feature = "test-utils")]
pub use test_data::*;

#[cfg(all(test, feature = "test-utils"))]
mod test_code {
    use super::*;

    #[test]
    fn ctx8_pruned() {
        unsafe {
            assert_eq!(ffi::sizeof_ctx8Pruned, ffi::ctx8Pruned.len());
            assert_eq!(
                ffi::sizeof_ctx8Pruned_witness,
                ffi::ctx8Pruned_witness.len()
            );
            run_test(
                &ffi::ctx8Pruned,
                &ffi::ctx8Pruned_witness,
                &ffi::ctx8Pruned_amr,
                &ffi::ctx8Pruned_cmr,
                &ffi::ctx8Pruned_ihr,
                ffi::ctx8Pruned_cost,
            );
        }
    }

    #[test]
    fn ctx8_unpruned() {
        unsafe {
            assert_eq!(ffi::sizeof_ctx8Unpruned, ffi::ctx8Unpruned.len());
            assert_eq!(
                ffi::sizeof_ctx8Unpruned_witness,
                ffi::ctx8Unpruned_witness.len()
            );
            run_test_fail(
                &ffi::ctx8Unpruned,
                &ffi::ctx8Unpruned_witness,
                SimplicityErr::AntiDoS,
                &ffi::ctx8Unpruned_amr,
                &ffi::ctx8Unpruned_cmr,
                &ffi::ctx8Unpruned_ihr,
                ffi::ctx8Unpruned_cost,
            );
        }
    }

    #[test]
    fn schnorr0() {
        unsafe {
            assert_eq!(ffi::sizeof_schnorr0, ffi::schnorr0.len());
            assert_eq!(ffi::sizeof_schnorr0_witness, ffi::schnorr0_witness.len());
            run_test(
                &ffi::schnorr0,
                &ffi::schnorr0_witness,
                &ffi::schnorr0_amr,
                &ffi::schnorr0_cmr,
                &ffi::schnorr0_ihr,
                ffi::schnorr0_cost,
            );
        }
    }

    #[test]
    fn schnorr6() {
        unsafe {
            assert_eq!(ffi::sizeof_schnorr6, ffi::schnorr6.len());
            assert_eq!(ffi::sizeof_schnorr6_witness, ffi::schnorr6_witness.len());
            run_test_fail(
                &ffi::schnorr6,
                &ffi::schnorr6_witness,
                SimplicityErr::ExecJet,
                &ffi::schnorr6_amr,
                &ffi::schnorr6_cmr,
                &ffi::schnorr6_ihr,
                ffi::schnorr6_cost,
            );
        }
    }
}
