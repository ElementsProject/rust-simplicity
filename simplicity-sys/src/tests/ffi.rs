// SPDX-License-Identifier: CC0-1.0

//! FFI Bindings for testing
//!
//! This module contains bindings to the C library types and functions
//! that are required to run tests.
//! It is split into several modules, each one corresponding to a `.h` file
//! in the C library.
//!
//! All types are converted to CamelCase and prefixed with the letter C;
//! function names are unchanged.

#![allow(non_camel_case_types)]

use std::fmt;

use crate::ffi::{c_int, c_size_t, c_uchar, c_void, ubounded};

/// Simplicity error codes
///
/// If you update this list, please also update [`SimplicityErr::from_i32`].
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SimplicityErr {
    NoError = 0,
    Malloc = -1,
    NotYetImplemented = -3,
    DataOutOfRange = -2,
    DataOutOfOrder = -4,
    FailCode = -6,
    StopCode = -8,
    Hidden = -10,
    BitstreamEof = -12,
    BitstreamTrailingBytes = -14,
    BitstreamIllegalPadding = -16,
    TypeInferenceUnification = -18,
    TypeInferenceOccursCheck = -20,
    TypeInferenceNotProgram = -22,
    WitnessEof = -24,
    WitnessTrailingBytes = -26,
    WitnessIllegalPadding = -28,
    UnsharedSubexpression = -30,
    Cmr = -32,
    ExecBudget = -34,
    ExecMemory = -36,
    ExecJet = -38,
    ExecAssert = -40,
    AntiDoS = -42,
    HiddenRoot = -44,
    Amr = -46,
}

extern "C" {
    pub static c_sizeof_simplicity_err: c_size_t;
    pub static c_alignof_simplicity_err: c_size_t;
}

impl fmt::Display for SimplicityErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl SimplicityErr {
    /// Converts the error code into a `Result` by splitting off the `NoError` case.
    pub fn into_result(self) -> Result<(), Self> {
        if self == SimplicityErr::NoError {
            Ok(())
        } else {
            Err(self)
        }
    }

    /// Converts an `i32` result to either a positive value or an error code
    ///
    /// # Panics
    /// Panics if the i32 result is not one of the error values returned from Simplicity.
    pub fn from_i32(n: i32) -> Result<u32, Self> {
        match n {
            n if n >= 0 => Ok(n as u32),
            -1 => Err(SimplicityErr::Malloc),
            -2 => Err(SimplicityErr::DataOutOfRange),
            -3 => Err(SimplicityErr::NotYetImplemented),
            -4 => Err(SimplicityErr::DataOutOfOrder),
            -6 => Err(SimplicityErr::FailCode),
            -8 => Err(SimplicityErr::StopCode),
            -10 => Err(SimplicityErr::Hidden),
            -12 => Err(SimplicityErr::BitstreamEof),
            -14 => Err(SimplicityErr::BitstreamTrailingBytes),
            -16 => Err(SimplicityErr::BitstreamIllegalPadding),
            -18 => Err(SimplicityErr::TypeInferenceUnification),
            -20 => Err(SimplicityErr::TypeInferenceOccursCheck),
            -22 => Err(SimplicityErr::TypeInferenceNotProgram),
            -24 => Err(SimplicityErr::WitnessEof),
            -26 => Err(SimplicityErr::WitnessTrailingBytes),
            -28 => Err(SimplicityErr::WitnessIllegalPadding),
            -30 => Err(SimplicityErr::UnsharedSubexpression),
            -32 => Err(SimplicityErr::Cmr),
            -34 => Err(SimplicityErr::ExecBudget),
            -36 => Err(SimplicityErr::ExecMemory),
            -38 => Err(SimplicityErr::ExecJet),
            -40 => Err(SimplicityErr::ExecAssert),
            -42 => Err(SimplicityErr::AntiDoS),
            -44 => Err(SimplicityErr::HiddenRoot),
            -46 => Err(SimplicityErr::Amr),
            x => panic!("unexpected error code {}", x),
        }
    }
}

pub mod bitstream {
    use super::*;
    use crate::tests::ffi::bitstring::CBitstring;

    /// Stream of bits.
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct CBitstream {
        pub arr: *const c_uchar,
        pub len: c_size_t,
        pub offset: c_uchar,
    }

    impl From<&[u8]> for CBitstream {
        fn from(sl: &[u8]) -> CBitstream {
            CBitstream {
                arr: sl.as_ptr(),
                len: sl.len(),
                offset: 0,
            }
        }
    }

    extern "C" {
        pub static c_sizeof_bitstream: c_size_t;
        pub static c_alignof_bitstream: c_size_t;

        pub fn simplicity_closeBitstream(stream: *mut CBitstream) -> i32;
        pub fn simplicity_readNBits(n: c_int, stream: *mut CBitstream) -> i32;
        pub fn simplicity_decodeUptoMaxInt(stream: *mut CBitstream) -> i32;
        pub fn simplicity_readBitstring(
            result: *mut CBitstring,
            n: c_size_t,
            stream: *mut CBitstream,
        ) -> i32;
    }
}

pub mod bitstring {
    use super::*;

    /// String of bits.
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct CBitstring {
        arr: *const c_uchar,
        len: c_size_t,
        offset: c_size_t,
    }

    impl Default for CBitstring {
        fn default() -> Self {
            CBitstring {
                arr: std::ptr::null(),
                len: 0,
                offset: 0,
            }
        }
    }

    extern "C" {
        pub static c_sizeof_bitstring: c_size_t;
        pub static c_alignof_bitstring: c_size_t;
    }
}

pub mod dag {
    use super::*;
    use crate::ffi::sha256::CSha256Midstate;
    use crate::tests::ffi::bitstream::CBitstream;
    use crate::tests::ffi::bitstring::CBitstring;
    use crate::tests::ffi::ty::CType;
    use crate::tests::ffi::SimplicityErr;

    /// Kind of Simplicity node.
    #[repr(C)]
    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub enum CTag {
        COMP,
        CASE,
        ASSERTL,
        ASSERTR,
        PAIR,
        DISCONNECT,
        INJL,
        INJR,
        TAKE,
        DROP,
        IDEN,
        UNIT,
        HIDDEN,
        WITNESS,
        JET,
        WORD,
    }

    /// Used to count the different kinds of combinators in a Simplicity DAG.
    #[repr(C)]
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
    pub struct CCombinatorCounters {
        pub comp_cnt: c_size_t,
        pub case_cnt: c_size_t,
        pub pair_cnt: c_size_t,
        pub disconnect_cnt: c_size_t,
        pub injl_cnt: c_size_t,
        pub injr_cnt: c_size_t,
        pub take_cnt: c_size_t,
        pub drop_cnt: c_size_t,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    /// Anonymous
    pub union CAuxTypes {
        /// scratch space for verifyCanonicalOrder
        pub aux: c_size_t,
        /// source type, target type
        pub types: [c_size_t; 2],
    }

    #[repr(C)]
    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    /// Anonymous
    pub struct CSourceIx {
        source_ix: c_size_t,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    /// Anonymous
    pub struct CChild2 {
        child: [c_size_t; 2],
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    /// Anonymous
    pub union CSourceChildValue {
        source_ix: CSourceIx,
        child: CChild2,
        compact_value: CBitstring,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct CDagNode {
        pub jet: *const c_void,
        pub cmr: CSha256Midstate,
        pub aux_types: CAuxTypes,
        pub source_ix_or_child_or_compact_value: CSourceChildValue,
        pub target_ix: c_size_t,
        pub cost: ubounded,
        pub tag: CTag,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
    /// Static analyses for a particular node of a Simplicity DAG
    pub struct CAnalyses {
        pub annotated_merkle_root: CSha256Midstate,
    }

    extern "C" {
        pub static c_sizeof_tag: c_size_t;
        pub static c_alignof_tag: c_size_t;
        pub static c_sizeof_combinator_counters: c_size_t;
        pub static c_alignof_combinator_counters: c_size_t;
        pub static c_sizeof_dag_node: c_size_t;
        pub static c_alignof_dag_node: c_size_t;
        pub static c_sizeof_analyses: c_size_t;
        pub static c_alignof_analyses: c_size_t;

        /// Compute the CMR of a jet of scribe(v) : ONE |- TWO^(2^n) that outputs a given
        /// bitstring
        pub fn simplicity_computeWordCMR(value: *const CBitstring, n: c_size_t) -> CSha256Midstate;

        /// Given a well-formed dag\[i + 1\], set the `cmr` field of every node in `dag`
        pub fn simplicity_computeCommitmentMerkleRoot(dag: *mut CDagNode, i: c_size_t);

        /// Given a well-typed dag representing a Simplicity expression, compute
        /// the annotated Merkle roots of all subexpressions.
        pub fn simplicity_computeAnnotatedMerkleRoot(
            analyses: *mut CAnalyses,
            dag: *const CDagNode,
            ty: *const CType,
            len: c_size_t,
        );

        /// Verifies that the 'dag' is in canonical order, meaning that nodes
        /// under the left branches have lower indices than nodes under
        pub fn simplicity_verifyCanonicalOrder(dag: *mut CDagNode, len: c_size_t) -> SimplicityErr;

        /// Fills in the 'WITNESS' nodes of a 'dag' with the data from 'witness'
        pub fn simplicity_fillWitnessData(
            dag: *mut CDagNode,
            type_dag: *mut CType,
            len: c_size_t,
            witness: *mut CBitstream,
        ) -> SimplicityErr;

        /// Computes the identity Merkle roots of every subexpression in a well-typed 'dag' with witnesses    .
        pub fn simplicity_verifyNoDuplicateIdentityHashes(
            ihr: *mut CSha256Midstate,
            dag: *const CDagNode,
            type_dag: *const CType,
            len: c_size_t,
        ) -> SimplicityErr;
    }
}

pub mod deserialize {
    use crate::tests::ffi::bitstream::CBitstream;
    use crate::tests::ffi::dag::{CCombinatorCounters, CDagNode};

    extern "C" {
        pub fn simplicity_decodeMallocDag(
            dag: *mut *mut CDagNode,
            combinator_counters: *mut CCombinatorCounters,
            stream: *mut CBitstream,
        ) -> i32;
    }
}

pub mod eval {
    use super::*;
    use crate::c_jets::c_env::CElementsTxEnv;
    use crate::ffi::UWORD;
    use crate::tests::ffi::dag::CDagNode;
    use crate::tests::ffi::ty::CType;
    use crate::tests::ffi::SimplicityErr;
    use std::ptr;

    pub const CHECK_NONE: c_uchar = 0;
    pub const CHECK_EXEC: c_uchar = 0x10;
    pub const CHECK_CASE: c_uchar = 0x60;
    pub const CHECK_ALL: c_uchar = 0xFF;

    extern "C" {
        /// Run the Bit Machine on the well-typed Simplicity expression 'dag\[len\]'.
        pub fn simplicity_evalTCOExpression(
            anti_dos_checks: c_uchar,
            output: *mut UWORD,
            input: *const UWORD,
            dag: *const CDagNode,
            type_dag: *mut CType,
            len: c_size_t,
            budget: *const ubounded,
            env: *const CElementsTxEnv,
        ) -> SimplicityErr;

        /// Given a well-typed dag representing a Simplicity expression,
        /// compute the memory and CPU requirements for evaluation.
        ///
        /// Refer to C documentation for preconditions.
        pub fn simplicity_analyseBounds(
            cell_bound: *mut ubounded,
            UWORD_bound: *mut ubounded,
            frame_bound: *mut ubounded,
            cost_bound: *mut ubounded,
            max_cells: ubounded,
            max_cost: ubounded,
            dag: *const CDagNode,
            type_dag: *const CType,
            len: c_size_t,
        ) -> SimplicityErr;
    }

    /// Run the Bit Machine on the well-typed Simplicity program 'dag\[len\]'.
    ///
    /// Defined inline in eval.h; since it is a 1-liner we just copy it into Rust.
    ///
    /// # Safety
    ///
    /// This function directly wraps `evalTCOExpression`; see the documentation for
    /// that function in the C source code for preconditions.
    #[allow(non_snake_case)]
    pub unsafe fn simplicity_evalTCOProgram(
        dag: *const CDagNode,
        type_dag: *mut CType,
        len: c_size_t,
        budget: *const ubounded,
        env: *const CElementsTxEnv,
    ) -> SimplicityErr {
        simplicity_evalTCOExpression(
            CHECK_ALL,
            ptr::null_mut(),
            ptr::null(),
            dag,
            type_dag,
            len,
            budget,
            env,
        )
    }
}

/// Renamed from `type` in the C code
pub mod ty {
    use super::*;
    use crate::ffi::sha256::CSha256Midstate;

    /// Name of a Simplicity type
    #[repr(C)]
    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub enum CTypeName {
        ONE,
        SUM,
        PRODUCT,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    /// Anonymous
    pub union CSkipBack {
        /// Used by `typeSkip`
        pub skip: c_size_t,
        /// Sometimes used as scratch space when traversing types
        pub back: c_size_t,
    }

    /// Simplicity type DAG
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct CType {
        pub type_arg: [c_size_t; 2],
        pub skip_back: CSkipBack,
        pub type_merkle_root: CSha256Midstate,
        pub bit_size: ubounded,
        pub kind: CTypeName,
    }

    extern "C" {
        pub static c_sizeof_typename: c_size_t;
        pub static c_alignof_typename: c_size_t;
        pub static c_sizeof_type: c_size_t;
        pub static c_alignof_type: c_size_t;

        /// Given a well-formed 'type_dag', compute the bitSizes, skips, and type Merkle roots of all subexpressions.
        pub fn simplicity_computeTypeAnalyses(type_dag: *mut CType, len: c_size_t);
    }
}

pub mod type_inference {
    use super::*;
    use crate::tests::ffi::dag::{CCombinatorCounters, CDagNode};
    use crate::tests::ffi::ty::CType;
    use crate::tests::ffi::SimplicityErr;

    extern "C" {
        /// If the Simplicity DAG, 'dag', has a principal type (including constraints
        /// due to sharing of subexpressions), then allocate a well-formed type DAG
        /// containing all the types needed for all the subexpressions of 'dag'.
        pub fn simplicity_mallocTypeInference(
            type_dag: *mut *mut CType,
            dag: *mut CDagNode,
            len: c_size_t,
            census: *const CCombinatorCounters,
        ) -> SimplicityErr;
    }
}

extern "C" {
    pub static sizeof_ctx8Pruned: c_size_t;
    pub static ctx8Pruned: [u8; 5015];
    pub static sizeof_ctx8Pruned_witness: c_size_t;
    pub static ctx8Pruned_witness: [u8; 0];
    pub static ctx8Pruned_amr: [u32; 8];
    pub static ctx8Pruned_cmr: [u32; 8];
    pub static ctx8Pruned_ihr: [u32; 8];
    pub static ctx8Pruned_cost: ubounded;

    pub static sizeof_ctx8Unpruned: c_size_t;
    pub static ctx8Unpruned: [u8; 4809];
    pub static sizeof_ctx8Unpruned_witness: c_size_t;
    pub static ctx8Unpruned_witness: [u8; 0];
    pub static ctx8Unpruned_amr: [u32; 8];
    pub static ctx8Unpruned_cmr: [u32; 8];
    pub static ctx8Unpruned_ihr: [u32; 8];
    pub static ctx8Unpruned_cost: ubounded;

    pub static sizeof_schnorr0: c_size_t;
    pub static schnorr0: [u8; 71];
    pub static sizeof_schnorr0_witness: c_size_t;
    pub static schnorr0_witness: [u8; 64];
    pub static schnorr0_amr: [u32; 8];
    pub static schnorr0_cmr: [u32; 8];
    pub static schnorr0_ihr: [u32; 8];
    pub static schnorr0_cost: ubounded;

    pub static sizeof_schnorr6: c_size_t;
    pub static schnorr6: [u8; 71];
    pub static sizeof_schnorr6_witness: c_size_t;
    pub static schnorr6_witness: [u8; 64];
    pub static schnorr6_amr: [u32; 8];
    pub static schnorr6_cmr: [u32; 8];
    pub static schnorr6_ihr: [u32; 8];
    pub static schnorr6_cost: ubounded;

    /*
    // FIXME enable this test; is not 1->1, requires extra frame setup
    pub static sizeof_hashBlock: c_size_t;
    pub static hashBlock: [u8; 3259];
    pub static hashBlock_amr: [u32; 8];
    pub static hashBlock_cmr: [u32; 8];
    pub static hashBlock_ihr: [u32; 8];

    // FIXME enable this test; requires a little but of extra work to set up an Elements env
    pub static elementsCheckSigHashAllTx1: [u8; 1151];
    pub static elementsCheckSigHashAllTx1_amr: [u32; 8];
    pub static elementsCheckSigHashAllTx1_cmr: [u32; 8];
    pub static elementsCheckSigHashAllTx1_ihr: [u32; 8];
    */
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    #[rustfmt::skip]
    fn test_sizes() {
        unsafe {
            assert_eq!(size_of::<SimplicityErr>(), c_sizeof_simplicity_err);
            assert_eq!(size_of::<bitstream::CBitstream>(), bitstream::c_sizeof_bitstream);
            assert_eq!(size_of::<bitstring::CBitstring>(), bitstring::c_sizeof_bitstring);
            assert_eq!(size_of::<dag::CTag>(), dag::c_sizeof_tag);
            assert_eq!(size_of::<dag::CCombinatorCounters>(), dag::c_sizeof_combinator_counters);
            assert_eq!(size_of::<dag::CDagNode>(), dag::c_sizeof_dag_node);
            assert_eq!(size_of::<dag::CAnalyses>(), dag::c_sizeof_analyses);
            assert_eq!(size_of::<ty::CType>(), ty::c_sizeof_type);
            assert_eq!(size_of::<ty::CTypeName>(), ty::c_sizeof_typename);
        }
    }

    #[test]
    #[rustfmt::skip]
    fn test_aligns() {
        unsafe {
            assert_eq!(align_of::<bitstream::CBitstream>(), bitstream::c_alignof_bitstream);
            assert_eq!(align_of::<bitstring::CBitstring>(), bitstring::c_alignof_bitstring);
            assert_eq!(align_of::<dag::CTag>(), dag::c_alignof_tag);
            assert_eq!(align_of::<dag::CCombinatorCounters>(), dag::c_alignof_combinator_counters);
            assert_eq!(align_of::<dag::CDagNode>(), dag::c_alignof_dag_node);
            assert_eq!(align_of::<dag::CAnalyses>(), dag::c_alignof_analyses);
            assert_eq!(align_of::<ty::CType>(), ty::c_alignof_type);
        }
    }
}
