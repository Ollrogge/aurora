use crate::CpuFlags;
use bitflags::bitflags;

bitflags! {
    /// The xPSR register.
    pub struct XPSR_Flags: u32 {
        /// T (Thumb state) bit.
        ///
        /// Always 1 as ARM Cortex-M4 uses the Thumb instruction set.
        const THUMB_STATE = 1 << 24;
        /// Indicates if an instruction has resulted in a saturation condition.
        const SATURATION_FLAG = 1 << 27;
        /// Overflow flag.
        ///
        /// Set to 1 if an instruction resulted in an overflow. Otherwise, it's set to 0.
        const OVERFLOW_FLAG = 1 << 28;
        /// Carry or borrow flag.
        ///
        /// Set to 1 if an instruction resulted in a carry condition. Otherwise, it's set to 0.
        const CARRY_FLAG = 1 << 29;
        /// Zero flag.
        ///
        /// Set to 1 if the result of an instruction is zero. Otherwise, it's set to 0.
        const ZERO_FLAG = 1 << 30;
        /// Negative or less than flag.
        ///
        /// Set to 1 if the result of an instruction is negative. Otherwise, it's set to 0.
        const SIGN_FLAG = 1 << 31;
    }
}
