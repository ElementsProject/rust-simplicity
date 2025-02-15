// SPDX-License-Identifier: CC0-1.0

//! High level APIs to creating read/write CFrames
//!

use std::mem;

use super::frame_ffi;
use super::frame_ffi::CFrameItem;
use crate::ffi::UWORD;

impl CFrameItem {
    /// Allocate a new frame item with dummy values
    unsafe fn new_unchecked() -> Self {
        Self {
            edge: std::ptr::null(),
            len: 0,
        }
    }

    /// Initialize a new read frame.
    /// 'n' is the number of cells for the read frame.
    /// 'from' is a pointer to the beginning of the new slice for the array of u8 to hold the frame's cells.
    ///
    /// Note: The C implementation uses array of UWORD for `from`. UWORD maps to uint_fast16_t which
    /// maps to usize on both 32-bit and 64-bit platforms.
    ///
    /// # Safety
    ///
    /// `from` must be a valid pointer to a contiguous allocation of at least `n` usizes.
    pub unsafe fn new_read(n: usize, from: *const UWORD) -> Self {
        // Allocate a new vector of required size
        let mut frame = CFrameItem::new_unchecked();
        frame_ffi::c_initReadFrame(&mut frame, n, from);
        frame
    }

    /// Initialize a new write frame.
    /// 'n' is the number of cells for the write frame.
    /// 'from' is a pointer to the one-past-the-end of the new slice for the array of UWORDS to hold the frame's cells.
    ///
    /// # Safety
    ///
    /// `from` must be a valid pointer **one past the end** of a contiguous allocation
    /// of at least `n` usizes.
    pub unsafe fn new_write(n: usize, from: *mut UWORD) -> Self {
        // Allocate a new vector of required size
        let mut frame = CFrameItem::new_unchecked();
        frame_ffi::c_initWriteFrame(&mut frame, n, from);
        frame
    }
}

/// Number of UWORDs required to hold n bits
pub fn uword_width(n_bits: usize) -> usize {
    n_bits.div_ceil(8 * mem::size_of::<UWORD>())
}

/// Number of bytes required to hold n bits
pub fn byte_width(n_bits: usize) -> usize {
    uword_width(n_bits) * mem::size_of::<UWORD>()
}
