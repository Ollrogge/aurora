use std::fmt;
use std::str::FromStr;

use zydis::Register as ZydisRegister;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Register32(Register32),
}

impl RegisterValue<usize> for Register {
    fn value(self, registers: &user_regs_struct) -> usize {
        match self {
            Self::Register32(register) => register.value(registers) as usize,
        }
    }
}

impl FromStr for Register {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Register32::from_str(s).and_then(|reg| Ok(reg.into()))
    }
}

pub trait ArchRegister {
    fn arch_register(self) -> Register;
}

pub trait RegisterValue<T> {
    fn value(self, registers: &user_regs_struct) -> T;
}

// **ARM** only has 32 bit registers. Nothing smaller

/*
       r0 to r12 are general-purpose registers.
    sp is the stack pointer.
    lr is the link register.
    pc is the program counter.
    xpsr is the program status register.

Please note that compared to ARMv7-A, it lacks a few registers like fp (frame pointer) and ip (intra-procedure-call scratch register). In the context of ARMv7-M, the Frame Pointer (fp) usage is optional, and it is usually aliased to r7 or r11 if used. There is no dedicated ip register in the ARMv7-M architecture.


 */

pub struct user_regs_struct {
    pub r0: u32,
    pub r1: u32,
    pub r2: u32,
    pub r3: u32,
    pub r4: u32,
    pub r5: u32,
    pub r6: u32,
    pub r7: u32,
    pub r8: u32,
    pub r9: u32,
    pub r10: u32,
    pub r11: u32,
    pub r12: u32,
    pub sp: u32,   // Stack pointer
    pub lr: u32,   // Link register
    pub pc: u32,   // Program counter
    pub xpsr: u32, // Special-purpose program status registers (Cortex-M)
    pub cpsr: u32, // current program status register
    pub spsr: u32, // saved program status register
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register32 {
    // General-purpose registers
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    SP,
    LR,

    PC,

    // Special-purpose program status registers (Cortex-M)
    xPSR,

    // Current Program Status register
    CPSR,

    // Saved Program Status Registers
    SPSR,
}

impl ArchRegister for Register32 {
    fn arch_register(self) -> Register {
        Register::Register32(self)
    }
}

impl RegisterValue<u32> for Register32 {
    fn value(self, registers: &user_regs_struct) -> u32 {
        match self {
            Self::R0 => registers.r0,
            Self::R1 => registers.r1,
            Self::R2 => registers.r2,
            Self::R3 => registers.r3,
            Self::R4 => registers.r4,
            Self::R5 => registers.r5,
            Self::R6 => registers.r6,
            Self::R7 => registers.r7,
            Self::R8 => registers.r8,
            Self::R9 => registers.r9,
            Self::R10 => registers.r10,
            Self::R11 => registers.r11,
            Self::R12 => registers.r12,
            Self::SP => registers.sp,
            Self::LR => registers.lr,
            Self::PC => registers.pc,
            Self::xPSR => registers.xpsr,
            Self::CPSR => registers.cpsr,
            Self::SPSR => registers.spsr,
        }
    }
}

impl From<Register32> for Register {
    fn from(register: Register32) -> Self {
        Register::Register32(register)
    }
}

impl fmt::Display for Register32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::R0 => "r0",
                Self::R1 => "r1",
                Self::R2 => "r2",
                Self::R3 => "r3",
                Self::R4 => "r4",
                Self::R5 => "r5",
                Self::R6 => "r6",
                Self::R7 => "r7",
                Self::R8 => "r8",
                Self::R9 => "r9",
                Self::R10 => "r10",
                Self::R11 => "r11",
                Self::R12 => "r12",
                Self::SP => "sp",
                Self::LR => "lr",
                Self::PC => "pc",
                Self::xPSR => "xPSR",
                Self::CPSR => "CPSR",
                Self::SPSR => "SPSR",
            }
        )
    }
}

impl FromStr for Register32 {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "r0" => Self::R0,
            "r1" => Self::R1,
            "r2" => Self::R2,
            "r3" => Self::R3,
            "r4" => Self::R4,
            "r5" => Self::R5,
            "r6" => Self::R6,
            "r7" => Self::R7,
            "r8" => Self::R8,
            "r9" => Self::R9,
            "r10" => Self::R10,
            "r11" => Self::R11,
            "r12" => Self::R12,
            "sp" => Self::SP,
            "lr" => Self::LR,
            "pc" => Self::PC,
            "xPSR" => Self::xPSR,
            "CPSR" => Self::CPSR,
            "SPSR" => Self::SPSR,
            _ => return Err(()),
        })
    }
}
