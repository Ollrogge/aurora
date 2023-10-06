use std::any::Any;
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

use capstone::arch::arm::ArmReg::*;
use capstone::RegId;
use lazy_static::lazy_static;
use nix::libc::user_regs_struct;
use zydis::Register as ZydisRegister;

use crate::config::CpuArchitecture;

pub trait ArchRegister {
    fn arch_register(self) -> Register;
}

// yolo
pub trait RegisterStruct {
    fn as_any(&self) -> &dyn Any;
}
impl RegisterStruct for user_regs_struct {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
impl RegisterStruct for user_regs_struct_arm {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait RegisterValue<T> {
    fn value(self, registers: &dyn RegisterStruct) -> T;
}

lazy_static! {
    pub static ref REGISTERS_ARM: Vec<&'static str> = vec![
        "r0",
        "r1",
        "r2",
        "r3",
        "r4",
        "r5",
        "r6",
        "r7",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "sp",
        "lr",
        "pc",
        "xPSR",
        "CPSR",
        "SPSR", // (not implemented by hoedur)
        "memory_address",
        "memory_value",
    ];
}

lazy_static! {
    pub static ref REGISTERS_X86: Vec<&'static str> = vec![
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "seg_cs",
        "seg_ss",
        "seg_ds",
        "seg_es",
        "seg_fs",
        "seg_gs",
        "eflags",
        "memory_address",
        "memory_value",
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register64 {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rbp,
    Rsi,
    Rdi,
    Rsp,
    Rip,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    SegCs,
    SegSs,
    SegDs,
    SegEs,
    SegFs,
    SegGs,
    Eflags,
    MemoryAddress,
    MemoryValue,
}

impl ArchRegister for Register64 {
    fn arch_register(self) -> Register {
        Register::RegisterX86(RegisterX86::Register64(self))
    }
}
impl RegisterValue<u64> for Register64 {
    fn value(self, registers: &dyn RegisterStruct) -> u64 {
        let registers = registers
            .as_any()
            .downcast_ref::<user_regs_struct>()
            .unwrap();
        match self {
            Self::Rax => registers.rax,
            Self::Rbx => registers.rbx,
            Self::Rcx => registers.rcx,
            Self::Rdx => registers.rdx,
            Self::Rbp => registers.rbp,
            Self::Rsi => registers.rsi,
            Self::Rdi => registers.rdi,
            Self::Rsp => registers.rsp,
            Self::Rip => registers.rip,
            Self::R8 => registers.r8,
            Self::R9 => registers.r9,
            Self::R10 => registers.r10,
            Self::R11 => registers.r11,
            Self::R12 => registers.r12,
            Self::R13 => registers.r13,
            Self::R14 => registers.r14,
            Self::R15 => registers.r15,
            _ => 0,
        }
    }
}

impl From<Register64> for Register {
    fn from(register: Register64) -> Self {
        Register::RegisterX86(RegisterX86::Register64(register))
    }
}

impl fmt::Display for Register64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Rax => "rax",
                Self::Rbx => "rbx",
                Self::Rcx => "rcx",
                Self::Rdx => "rdx",
                Self::Rbp => "rbp",
                Self::Rsi => "rsi",
                Self::Rdi => "rdi",
                Self::Rsp => "rsp",
                Self::Rip => "rip",
                Self::R8 => "r8",
                Self::R9 => "r9",
                Self::R10 => "r10",
                Self::R11 => "r11",
                Self::R12 => "r12",
                Self::R13 => "r13",
                Self::R14 => "r14",
                Self::R15 => "r15",
                _ => "",
            }
        )
    }
}

impl FromStr for Register64 {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "rax" => Self::Rax,
            "rbx" => Self::Rbx,
            "rcx" => Self::Rcx,
            "rdx" => Self::Rdx,
            "rbp" => Self::Rbp,
            "rsi" => Self::Rsi,
            "rdi" => Self::Rdi,
            "rsp" => Self::Rsp,
            "rip" => Self::Rip,
            "r8" => Self::R8,
            "r9" => Self::R9,
            "r10" => Self::R10,
            "r11" => Self::R11,
            "r12" => Self::R12,
            "r13" => Self::R13,
            "r14" => Self::R14,
            "r15" => Self::R15,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register32 {
    Eax,
    Ebx,
    Ecx,
    Edx,
    Ebp,
    Esi,
    Edi,
    Esp,
    Eip,
    R8d,
    R9d,
    R10d,
    R11d,
    R12d,
    R13d,
    R14d,
    R15d,
}

impl ArchRegister for Register32 {
    fn arch_register(self) -> Register {
        Register::RegisterX86(RegisterX86::Register64(match self {
            Self::Eax => Register64::Rax,
            Self::Ebx => Register64::Rbx,
            Self::Ecx => Register64::Rcx,
            Self::Edx => Register64::Rdx,
            Self::Ebp => Register64::Rbp,
            Self::Esi => Register64::Rsi,
            Self::Edi => Register64::Rdi,
            Self::Esp => Register64::Rsp,
            Self::Eip => Register64::Rip,
            Self::R8d => Register64::R8,
            Self::R9d => Register64::R9,
            Self::R10d => Register64::R10,
            Self::R11d => Register64::R11,
            Self::R12d => Register64::R12,
            Self::R13d => Register64::R13,
            Self::R14d => Register64::R14,
            Self::R15d => Register64::R15,
        }))
    }
}
impl RegisterValue<u32> for Register32 {
    fn value(self, registers: &dyn RegisterStruct) -> u32 {
        let registers = registers
            .as_any()
            .downcast_ref::<user_regs_struct>()
            .unwrap();
        (self.arch_register().value(registers) & 0xFFFF_FFFF) as u32
    }
}

impl From<Register32> for RegisterX86 {
    fn from(register: Register32) -> Self {
        RegisterX86::Register32(register)
    }
}

impl From<Register64> for RegisterX86 {
    fn from(register: Register64) -> Self {
        RegisterX86::Register64(register)
    }
}

impl fmt::Display for Register32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Eax => "eax",
                Self::Ebx => "ebx",
                Self::Ecx => "ecx",
                Self::Edx => "edx",
                Self::Ebp => "ebp",
                Self::Esi => "esi",
                Self::Edi => "edi",
                Self::Esp => "esp",
                Self::Eip => "eip",
                Self::R8d => "r8d",
                Self::R9d => "r9d",
                Self::R10d => "r10d",
                Self::R11d => "r11d",
                Self::R12d => "r12d",
                Self::R13d => "r13d",
                Self::R14d => "r14d",
                Self::R15d => "r15d",
            }
        )
    }
}

impl FromStr for Register32 {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "eax" => Self::Eax,
            "ebx" => Self::Ebx,
            "ecx" => Self::Ecx,
            "edx" => Self::Edx,
            "ebp" => Self::Ebp,
            "esi" => Self::Esi,
            "edi" => Self::Edi,
            "esp" => Self::Esp,
            "eip" => Self::Eip,
            "r8d" => Self::R8d,
            "r9d" => Self::R9d,
            "r10d" => Self::R10d,
            "r11d" => Self::R11d,
            "r12d" => Self::R12d,
            "r13d" => Self::R13d,
            "r14d" => Self::R14d,
            "r15d" => Self::R15d,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register16 {
    Ax,
    Bx,
    Cx,
    Dx,
    Bp,
    Si,
    Di,
    Sp,
    Ip,
    Cs,
    Ss,
    Ds,
    Es,
    Fs,
    Gs,
    R8w,
    R9w,
    R10w,
    R11w,
    R12w,
    R13w,
    R14w,
    R15w,
}

impl ArchRegister for Register16 {
    fn arch_register(self) -> Register {
        Register::RegisterX86(match self {
            Self::Ax => RegisterX86::Register64(Register64::Rax),
            Self::Bx => RegisterX86::Register64(Register64::Rbx),
            Self::Cx => RegisterX86::Register64(Register64::Rcx),
            Self::Dx => RegisterX86::Register64(Register64::Rdx),
            Self::Bp => RegisterX86::Register64(Register64::Rbp),
            Self::Si => RegisterX86::Register64(Register64::Rsi),
            Self::Di => RegisterX86::Register64(Register64::Rdi),
            Self::Sp => RegisterX86::Register64(Register64::Rsp),
            Self::Ip => RegisterX86::Register64(Register64::Rip),
            Self::Cs => RegisterX86::Register16(Register16::Cs),
            Self::Ss => RegisterX86::Register16(Register16::Ss),
            Self::Ds => RegisterX86::Register16(Register16::Ds),
            Self::Es => RegisterX86::Register16(Register16::Es),
            Self::Fs => RegisterX86::Register16(Register16::Fs),
            Self::Gs => RegisterX86::Register16(Register16::Gs),
            Self::R8w => RegisterX86::Register64(Register64::R8),
            Self::R9w => RegisterX86::Register64(Register64::R9),
            Self::R10w => RegisterX86::Register64(Register64::R10),
            Self::R11w => RegisterX86::Register64(Register64::R11),
            Self::R12w => RegisterX86::Register64(Register64::R12),
            Self::R13w => RegisterX86::Register64(Register64::R13),
            Self::R14w => RegisterX86::Register64(Register64::R14),
            Self::R15w => RegisterX86::Register64(Register64::R15),
        })
    }
}
impl RegisterValue<u16> for Register16 {
    fn value(self, registers: &dyn RegisterStruct) -> u16 {
        let registers = registers
            .as_any()
            .downcast_ref::<user_regs_struct>()
            .unwrap();
        match self {
            Self::Cs => registers.cs as u16,
            Self::Ss => registers.ss as u16,
            Self::Ds => registers.ds as u16,
            Self::Es => registers.es as u16,
            Self::Fs => registers.fs as u16,
            Self::Gs => registers.gs as u16,
            _ => (self.arch_register().value(registers) & 0xFFFF) as u16,
        }
    }
}

impl From<Register16> for RegisterX86 {
    fn from(register: Register16) -> Self {
        RegisterX86::Register16(register)
    }
}

impl fmt::Display for Register16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Ax => "ax",
                Self::Bx => "bx",
                Self::Cx => "cx",
                Self::Dx => "dx",
                Self::Bp => "bp",
                Self::Si => "si",
                Self::Di => "di",
                Self::Sp => "sp",
                Self::Ip => "ip",
                Self::Cs => "cs",
                Self::Ss => "ss",
                Self::Ds => "ds",
                Self::Es => "es",
                Self::Fs => "fs",
                Self::Gs => "gs",
                Self::R8w => "r8w",
                Self::R9w => "r9w",
                Self::R10w => "r10w",
                Self::R11w => "r11w",
                Self::R12w => "r12w",
                Self::R13w => "r13w",
                Self::R14w => "r14w",
                Self::R15w => "r15w",
            }
        )
    }
}

impl FromStr for Register16 {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "ax" => Self::Ax,
            "bx" => Self::Bx,
            "cx" => Self::Cx,
            "dx" => Self::Dx,
            "bp" => Self::Bp,
            "si" => Self::Si,
            "di" => Self::Di,
            "sp" => Self::Sp,
            "ip" => Self::Ip,
            "cs" => Self::Cs,
            "ss" => Self::Ss,
            "ds" => Self::Ds,
            "es" => Self::Es,
            "fs" => Self::Fs,
            "gs" => Self::Gs,
            "r8w" => Self::R8w,
            "r9w" => Self::R9w,
            "r10w" => Self::R10w,
            "r11w" => Self::R11w,
            "r12w" => Self::R12w,
            "r13w" => Self::R13w,
            "r14w" => Self::R14w,
            "r15w" => Self::R15w,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register8Low {
    Al,
    Bl,
    Cl,
    Dl,
    Bpl,
    Sil,
    Dil,
    Spl,
    R8b,
    R9b,
    R10b,
    R11b,
    R12b,
    R13b,
    R14b,
    R15b,
}

impl ArchRegister for Register8Low {
    fn arch_register(self) -> Register {
        Register::RegisterX86(match self {
            Self::Al => RegisterX86::Register64(Register64::Rax),
            Self::Bl => RegisterX86::Register64(Register64::Rbx),
            Self::Cl => RegisterX86::Register64(Register64::Rcx),
            Self::Dl => RegisterX86::Register64(Register64::Rdx),
            Self::Bpl => RegisterX86::Register64(Register64::Rbp),
            Self::Sil => RegisterX86::Register64(Register64::Rsi),
            Self::Dil => RegisterX86::Register64(Register64::Rdi),
            Self::Spl => RegisterX86::Register64(Register64::Rsp),
            Self::R8b => RegisterX86::Register64(Register64::R8),
            Self::R9b => RegisterX86::Register64(Register64::R9),
            Self::R10b => RegisterX86::Register64(Register64::R10),
            Self::R11b => RegisterX86::Register64(Register64::R11),
            Self::R12b => RegisterX86::Register64(Register64::R12),
            Self::R13b => RegisterX86::Register64(Register64::R13),
            Self::R14b => RegisterX86::Register64(Register64::R14),
            Self::R15b => RegisterX86::Register64(Register64::R15),
        })
    }
}
impl RegisterValue<u8> for Register8Low {
    fn value(self, registers: &dyn RegisterStruct) -> u8 {
        let registers = registers
            .as_any()
            .downcast_ref::<user_regs_struct>()
            .unwrap();
        (self.arch_register().value(registers) & 0xFF) as u8
    }
}

impl From<Register8Low> for RegisterX86 {
    fn from(register: Register8Low) -> Self {
        RegisterX86::Register8Low(register)
    }
}

impl fmt::Display for Register8Low {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Al => "al",
                Self::Bl => "bl",
                Self::Cl => "cl",
                Self::Dl => "dl",
                Self::Bpl => "bpl",
                Self::Sil => "sil",
                Self::Dil => "dil",
                Self::Spl => "spl",
                Self::R8b => "r8b",
                Self::R9b => "r9b",
                Self::R10b => "r10b",
                Self::R11b => "r11b",
                Self::R12b => "r12b",
                Self::R13b => "r13b",
                Self::R14b => "r14b",
                Self::R15b => "r15b",
            }
        )
    }
}

impl FromStr for Register8Low {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "al" => Self::Al,
            "bl" => Self::Bl,
            "cl" => Self::Cl,
            "dl" => Self::Dl,
            "bpl" => Self::Bpl,
            "sil" => Self::Sil,
            "dil" => Self::Dil,
            "spl" => Self::Spl,
            "r8b" => Self::R8b,
            "r9b" => Self::R9b,
            "r10b" => Self::R10b,
            "r11b" => Self::R11b,
            "r12b" => Self::R12b,
            "r13b" => Self::R13b,
            "r14b" => Self::R14b,
            "r15b" => Self::R15b,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register8High {
    Ah,
    Bh,
    Ch,
    Dh,
}

impl ArchRegister for Register8High {
    fn arch_register(self) -> Register {
        Register::RegisterX86(RegisterX86::Register64(match self {
            Self::Ah => Register64::Rax,
            Self::Bh => Register64::Rbx,
            Self::Ch => Register64::Rcx,
            Self::Dh => Register64::Rdx,
        }))
    }
}
impl RegisterValue<u8> for Register8High {
    fn value(self, registers: &dyn RegisterStruct) -> u8 {
        let registers = registers
            .as_any()
            .downcast_ref::<user_regs_struct>()
            .unwrap();
        ((self.arch_register().value(registers) >> 8) & 0xFF) as u8
    }
}

impl From<Register8High> for RegisterX86 {
    fn from(register: Register8High) -> Self {
        RegisterX86::Register8High(register)
    }
}

impl From<RegisterX86> for Register {
    fn from(register: RegisterX86) -> Self {
        Register::RegisterX86(register)
    }
}

impl fmt::Display for Register8High {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Ah => "ah",
                Self::Bh => "bh",
                Self::Ch => "ch",
                Self::Dh => "dh",
            }
        )
    }
}
impl FromStr for Register8High {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "ah" => Self::Ah,
            "bh" => Self::Bh,
            "ch" => Self::Ch,
            "dh" => Self::Dh,
            _ => return Err(()),
        })
    }
}

#[derive(Debug)]
pub struct user_regs_struct_arm {
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
                   // pub spsr: u32, // saved program status register ( not implemented by hoedur)
}

impl TryFrom<Vec<u32>> for user_regs_struct_arm {
    type Error = &'static str;

    fn try_from(v: Vec<u32>) -> Result<Self, Self::Error> {
        if v.len() < 18 {
            return Err("The input vector does not have enough elements to populate the struct");
        }

        Ok(user_regs_struct_arm {
            r0: v[0],
            r1: v[1],
            r2: v[2],
            r3: v[3],
            r4: v[4],
            r5: v[5],
            r6: v[6],
            r7: v[7],
            r8: v[8],
            r9: v[9],
            r10: v[10],
            r11: v[11],
            r12: v[12],
            sp: v[13],
            lr: v[14],
            pc: v[15],
            xpsr: v[16],
            cpsr: v[17],
            //spsr: v[18],
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterArm {
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
    MemoryAddress, // address written
    MemoryValue,   // value written
}

impl RegisterArm {
    pub fn from_regid(id: RegId) -> Option<Self> {
        match id.0 as u32 {
            ARM_REG_R0 => Some(RegisterArm::R0),
            ARM_REG_R1 => Some(RegisterArm::R1),
            ARM_REG_R2 => Some(RegisterArm::R2),
            ARM_REG_R3 => Some(RegisterArm::R3),
            ARM_REG_R4 => Some(RegisterArm::R4),
            ARM_REG_R5 => Some(RegisterArm::R5),
            ARM_REG_R6 => Some(RegisterArm::R6),
            ARM_REG_R7 => Some(RegisterArm::R7),
            ARM_REG_R8 => Some(RegisterArm::R8),
            ARM_REG_R9 => Some(RegisterArm::R9),
            ARM_REG_R10 => Some(RegisterArm::R10),
            ARM_REG_R11 => Some(RegisterArm::R11),
            ARM_REG_R12 => Some(RegisterArm::R12),
            ARM_REG_SP => Some(RegisterArm::SP),
            ARM_REG_LR => Some(RegisterArm::LR),
            ARM_REG_PC => Some(RegisterArm::PC),
            ARM_REG_SPSR => Some(RegisterArm::SPSR),
            _ => {
                //println!("Registerarm: unhandled regid: {:?}", id);
                //unimplemented!();
                None
            }
        }
    }
}

impl From<RegisterArm> for Register {
    fn from(register: RegisterArm) -> Self {
        Register::RegisterArm(register)
    }
}

impl fmt::Display for RegisterArm {
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
                _ => "",
            }
        )
    }
}

impl FromStr for RegisterArm {
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

impl RegisterValue<u32> for RegisterArm {
    fn value(self, registers: &dyn RegisterStruct) -> u32 {
        let registers = registers
            .as_any()
            .downcast_ref::<user_regs_struct_arm>()
            .unwrap();

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
            // Self::SPSR => registers.spsr,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterX86 {
    Register64(Register64),
    Register32(Register32),
    Register16(Register16),
    Register8Low(Register8Low),
    Register8High(Register8High),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    RegisterX86(RegisterX86),
    RegisterArm(RegisterArm),
}

impl RegisterX86 {
    pub fn from_zydis_register(reg: ZydisRegister) -> Option<Self> {
        match reg {
            ZydisRegister::AL => Some(Register8Low::Al.into()),
            ZydisRegister::CL => Some(Register8Low::Cl.into()),
            ZydisRegister::DL => Some(Register8Low::Dl.into()),
            ZydisRegister::BL => Some(Register8Low::Bl.into()),
            ZydisRegister::AH => Some(Register8High::Ah.into()),
            ZydisRegister::CH => Some(Register8High::Ch.into()),
            ZydisRegister::DH => Some(Register8High::Dh.into()),
            ZydisRegister::BH => Some(Register8High::Bh.into()),
            ZydisRegister::SPL => Some(Register8Low::Spl.into()),
            ZydisRegister::BPL => Some(Register8Low::Bpl.into()),
            ZydisRegister::SIL => Some(Register8Low::Sil.into()),
            ZydisRegister::DIL => Some(Register8Low::Dil.into()),
            ZydisRegister::R8B => Some(Register8Low::R8b.into()),
            ZydisRegister::R9B => Some(Register8Low::R9b.into()),
            ZydisRegister::R10B => Some(Register8Low::R10b.into()),
            ZydisRegister::R11B => Some(Register8Low::R11b.into()),
            ZydisRegister::R12B => Some(Register8Low::R12b.into()),
            ZydisRegister::R13B => Some(Register8Low::R13b.into()),
            ZydisRegister::R14B => Some(Register8Low::R14b.into()),
            ZydisRegister::R15B => Some(Register8Low::R15b.into()),
            ZydisRegister::AX => Some(Register16::Ax.into()),
            ZydisRegister::CX => Some(Register16::Cx.into()),
            ZydisRegister::DX => Some(Register16::Dx.into()),
            ZydisRegister::BX => Some(Register16::Bx.into()),
            ZydisRegister::SP => Some(Register16::Sp.into()),
            ZydisRegister::BP => Some(Register16::Bp.into()),
            ZydisRegister::SI => Some(Register16::Si.into()),
            ZydisRegister::DI => Some(Register16::Di.into()),
            ZydisRegister::R8W => Some(Register16::R8w.into()),
            ZydisRegister::R9W => Some(Register16::R9w.into()),
            ZydisRegister::R10W => Some(Register16::R10w.into()),
            ZydisRegister::R11W => Some(Register16::R11w.into()),
            ZydisRegister::R12W => Some(Register16::R12w.into()),
            ZydisRegister::R13W => Some(Register16::R13w.into()),
            ZydisRegister::R14W => Some(Register16::R14w.into()),
            ZydisRegister::R15W => Some(Register16::R15w.into()),
            ZydisRegister::EAX => Some(Register32::Eax.into()),
            ZydisRegister::ECX => Some(Register32::Ecx.into()),
            ZydisRegister::EDX => Some(Register32::Edx.into()),
            ZydisRegister::EBX => Some(Register32::Ebx.into()),
            ZydisRegister::ESP => Some(Register32::Esp.into()),
            ZydisRegister::EBP => Some(Register32::Ebp.into()),
            ZydisRegister::ESI => Some(Register32::Esi.into()),
            ZydisRegister::EDI => Some(Register32::Edi.into()),
            ZydisRegister::R8D => Some(Register32::R8d.into()),
            ZydisRegister::R9D => Some(Register32::R9d.into()),
            ZydisRegister::R10D => Some(Register32::R10d.into()),
            ZydisRegister::R11D => Some(Register32::R11d.into()),
            ZydisRegister::R12D => Some(Register32::R12d.into()),
            ZydisRegister::R13D => Some(Register32::R13d.into()),
            ZydisRegister::R14D => Some(Register32::R14d.into()),
            ZydisRegister::R15D => Some(Register32::R15d.into()),
            ZydisRegister::RAX => Some(Register64::Rax.into()),
            ZydisRegister::RCX => Some(Register64::Rcx.into()),
            ZydisRegister::RDX => Some(Register64::Rdx.into()),
            ZydisRegister::RBX => Some(Register64::Rbx.into()),
            ZydisRegister::RSP => Some(Register64::Rsp.into()),
            ZydisRegister::RBP => Some(Register64::Rbp.into()),
            ZydisRegister::RSI => Some(Register64::Rsi.into()),
            ZydisRegister::RDI => Some(Register64::Rdi.into()),
            ZydisRegister::R8 => Some(Register64::R8.into()),
            ZydisRegister::R9 => Some(Register64::R9.into()),
            ZydisRegister::R10 => Some(Register64::R10.into()),
            ZydisRegister::R11 => Some(Register64::R11.into()),
            ZydisRegister::R12 => Some(Register64::R12.into()),
            ZydisRegister::R13 => Some(Register64::R13.into()),
            ZydisRegister::R14 => Some(Register64::R14.into()),
            ZydisRegister::R15 => Some(Register64::R15.into()),
            // ZydisRegister::FLAGS => Some(Register64::Flags.into()),
            // ZydisRegister::EFLAGS => Some(Register64::Eflags.into()),
            // ZydisRegister::RFLAGS => Some(Register64::Rflags.into()),
            ZydisRegister::IP => Some(Register16::Ip.into()),
            ZydisRegister::EIP => Some(Register32::Eip.into()),
            ZydisRegister::RIP => Some(Register64::Rip.into()),
            ZydisRegister::ES => Some(Register16::Es.into()),
            ZydisRegister::CS => Some(Register16::Cs.into()),
            ZydisRegister::SS => Some(Register16::Ss.into()),
            ZydisRegister::DS => Some(Register16::Ds.into()),
            ZydisRegister::FS => Some(Register16::Fs.into()),
            ZydisRegister::GS => Some(Register16::Gs.into()),
            ZydisRegister::NONE => None,
            _ => None,
        }
    }
}

impl RegisterValue<usize> for Register {
    fn value(self, registers: &dyn RegisterStruct) -> usize {
        match self {
            Self::RegisterX86(reg) => match reg {
                RegisterX86::Register64(register) => register.value(registers) as usize,
                RegisterX86::Register32(register) => register.value(registers) as usize,
                RegisterX86::Register16(register) => register.value(registers) as usize,
                RegisterX86::Register8High(register) => register.value(registers) as usize,
                RegisterX86::Register8Low(register) => register.value(registers) as usize,
            },
            Self::RegisterArm(reg) => reg.value(registers) as usize,
        }
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegisterX86(reg) => match reg {
                RegisterX86::Register64(register) => register.fmt(f),
                RegisterX86::Register32(register) => register.fmt(f),
                RegisterX86::Register16(register) => register.fmt(f),
                RegisterX86::Register8Low(register) => register.fmt(f),
                RegisterX86::Register8High(register) => register.fmt(f),
            },
            Self::RegisterArm(reg) => reg.fmt(f),
        }
    }
}

impl FromStr for RegisterX86 {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Register64::from_str(s)
            .and_then(|reg| Ok(RegisterX86::Register64(reg)))
            .or_else(|_| Register32::from_str(s).and_then(|reg| Ok(RegisterX86::Register32(reg))))
            .or_else(|_| Register16::from_str(s).and_then(|reg| Ok(RegisterX86::Register16(reg))))
            .or_else(|_| {
                Register8Low::from_str(s).and_then(|reg| Ok(RegisterX86::Register8Low(reg)))
            })
            .or_else(|_| {
                Register8High::from_str(s).and_then(|reg| Ok(RegisterX86::Register8High(reg)))
            })
    }
}
