use nix::libc::user_regs_struct;
use std::str::FromStr;

use crate::arm::xpsr_flags::XPSR_Flags;

use super::rflags::RFlags;
use anyhow::{Context, Result};
use capstone::{
    arch::arm::{ArmInsnDetail, ArmOpMem, ArmOperandType},
    arch::DetailsArchInsn,
    prelude::*,
    RegId,
};
use trace_analysis::register::{Register, RegisterArm, RegisterStruct, RegisterValue, RegisterX86};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuFlags {
    ARM(XPSR_Flags),
    X86(RFlags),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    Compare(ComparePredicate),
    Edge(EdgePredicate),
    FlagSet(CpuFlags),
    Visited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparePredicate {
    pub destination: ValueDestination,
    pub compare: Compare,
    pub value: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueDestination {
    Address(MemoryLocation),
    Memory(AccessSize, MemoryLocation),
    Register(Register),
}

impl ValueDestination {
    pub fn register(register: Register) -> Self {
        Self::Register(register)
    }
}

pub type AccessSize = u8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryLocation {
    segment: Option<Register>,
    base: Option<Register>,
    index: Option<Register>,
    scale: u8,
    displacement: Option<i64>,
}

impl MemoryLocation {
    fn from_memory_info(mem: &zydis::ffi::MemoryInfo) -> Self {
        Self {
            segment: RegisterX86::from_zydis_register(mem.segment).map(|x| x.into()),
            base: RegisterX86::from_zydis_register(mem.base).map(|x| x.into()),
            index: RegisterX86::from_zydis_register(mem.index).map(|x| x.into()),
            scale: mem.scale,
            displacement: if mem.disp.has_displacement {
                Some(mem.disp.displacement)
            } else {
                None
            },
        }
    }

    pub fn from_arm_op_mem(mem: ArmOpMem) -> MemoryLocation {
        MemoryLocation {
            segment: None,
            base: RegisterArm::from_regid(mem.base()).map(|x| x.into()),
            index: RegisterArm::from_regid(mem.index()).map(|x| x.into()),
            // todo: i dont understand why this can be -1
            scale: mem.scale() as u8,
            displacement: Some(mem.disp() as i64),
        }
    }
}

impl MemoryLocation {
    pub fn address(&self, registers: &dyn RegisterStruct) -> usize {
        let address = self
            .base
            .and_then(|reg| Some(reg.value(registers)))
            .unwrap_or(0)
            + self
                .index
                .and_then(|reg| Some(reg.value(registers) * self.scale as usize))
                .unwrap_or(0);

        match self.displacement {
            Some(displacement) => {
                if displacement >= 0 {
                    address + displacement.abs() as usize
                } else {
                    address - displacement.abs() as usize
                }
            }
            None => address,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compare {
    Less,
    Greater,
    GreaterOrEqual,
    Equal,
    NotEqual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgePredicate {
    pub source: usize,
    pub transition: EdgeTransition,
    pub destination: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeTransition {
    Taken,
    NotTaken,
}

pub fn convert_predicate(
    predicate: &str,
    instruction: zydis::DecodedInstruction,
) -> Option<Predicate> {
    let parts: Vec<_> = predicate.split(' ').collect();
    let function = match parts.len() {
        1 | 2 => parts[0],
        3 => parts[1],
        _ => unimplemented!(),
    };

    if function.contains("edge") {
        let source = usize::from_str_radix(&parts[0][2..], 16).expect("failed to parse source");
        let destination =
            usize::from_str_radix(&parts[2][2..], 16).expect("failed to parse destination");
        let transition = match function {
            "has_edge_to" => EdgeTransition::Taken,
            "edge_only_taken_to" => EdgeTransition::NotTaken,
            "last_edge_to" => return None,
            _ => unimplemented!(),
        };

        return Some(Predicate::Edge(EdgePredicate {
            source,
            transition,
            destination,
        }));
    } else if function.contains("reg_val") {
        let value = usize::from_str_radix(&parts[2][2..], 16).expect("failed to parse value");
        let memory_locations = instruction.operands[..instruction.operand_count as usize]
            .into_iter()
            .filter(|op| match op.ty {
                zydis::OperandType::MEMORY => true,
                _ => false,
            });
        let memory = memory_locations
            .last()
            .and_then(|op| Some(MemoryLocation::from_memory_info(&op.mem)));

        let destination = match parts[0] {
            "memory_address" => ValueDestination::Address(memory.expect("no memory location")),
            "memory_value" => ValueDestination::Memory(
                instruction.operand_width,
                memory.expect("no memory location"),
            ),

            "seg_cs" => return None,
            "seg_ss" => return None,
            "seg_ds" => return None,
            "seg_es" => return None,
            "seg_fs" => return None,
            "seg_gs" => return None,

            "eflags" => return None,

            register => ValueDestination::Register(
                RegisterX86::from_str(register)
                    .expect("failed to parse register")
                    .into(),
            ),
        };

        let compare = match function {
            "min_reg_val_less" => Compare::Less,
            "max_reg_val_less" => Compare::Less,
            "last_reg_val_less" => return None,
            "max_min_diff_reg_val_less" => return None,

            "min_reg_val_greater_or_equal" => Compare::GreaterOrEqual,
            "max_reg_val_greater_or_equal" => Compare::GreaterOrEqual,
            "last_reg_val_greater_or_equal" => return None,
            "max_min_diff_reg_val_greater_or_equal" => return None,

            _ => unimplemented!(),
        };

        return Some(Predicate::Compare(ComparePredicate {
            destination,
            compare,
            value,
        }));
    } else if function.contains("ins_count") {
        // "ins_count_less"
        // "ins_count_greater_or_equal"
    } else if function.contains("selector_val") {
        // "selector_val_less_name"
        // "selector_val_less"
        // "selector_val_greater_or_equal_name"
        // "selector_val_greater_or_equal"
    } else if function.contains("num_successors") {
        // "num_successors_greater" =>
        // "num_successors_equal" =>
    } else if function.contains("flag") {
        let flag = match function {
            "min_carry_flag_set" => RFlags::CARRY_FLAG,
            "min_parity_flag_set" => RFlags::PARITY_FLAG,
            "min_adjust_flag_set" => RFlags::AUXILIARY_CARRY_FLAG,
            "min_zero_flag_set" => RFlags::ZERO_FLAG,
            "min_sign_flag_set" => RFlags::SIGN_FLAG,
            "min_trap_flag_set" => RFlags::TRAP_FLAG,
            "min_interrupt_flag_set" => RFlags::INTERRUPT_FLAG,
            "min_direction_flag_set" => RFlags::DIRECTION_FLAG,
            "min_overflow_flag_set" => RFlags::OVERFLOW_FLAG,

            "max_carry_flag_set" => RFlags::CARRY_FLAG,
            "max_parity_flag_set" => RFlags::PARITY_FLAG,
            "max_adjust_flag_set" => RFlags::AUXILIARY_CARRY_FLAG,
            "max_zero_flag_set" => RFlags::ZERO_FLAG,
            "max_sign_flag_set" => RFlags::SIGN_FLAG,
            "max_trap_flag_set" => RFlags::TRAP_FLAG,
            "max_interrupt_flag_set" => RFlags::INTERRUPT_FLAG,
            "max_direction_flag_set" => RFlags::DIRECTION_FLAG,
            "max_overflow_flag_set" => RFlags::OVERFLOW_FLAG,

            "last_carry_flag_set" => return None,
            "last_parity_flag_set" => return None,
            "last_adjust_flag_set" => return None,
            "last_zero_flag_set" => return None,
            "last_sign_flag_set" => return None,
            "last_trap_flag_set" => return None,
            "last_interrupt_flag_set" => return None,
            "last_direction_flag_set" => return None,
            "last_overflow_flag_set" => return None,

            _ => unimplemented!(),
        };

        return Some(Predicate::FlagSet(CpuFlags::X86(flag)));
    } else if function == "is_visited" {
        return Some(Predicate::Visited);
    } else {
        log::error!("unknown predicate function {:?}", function);
        unimplemented!()
    }

    None
}

pub fn convert_predicate_arm(
    predicate: &str,
    instruction: capstone::InsnDetail,
) -> Result<Option<Predicate>> {
    let parts: Vec<_> = predicate.split(' ').collect();
    let function = match parts.len() {
        1 | 2 => parts[0],
        3 => parts[1],
        _ => unimplemented!(),
    };

    let arch_detail = instruction.arch_detail();

    let arm_isn_detail = arch_detail
        .arm()
        .context("instruction is not an arm inst")?;

    // edge
    if function.contains("edge") {
        let source = usize::from_str_radix(&parts[0][2..], 16).expect("failed to parse source");
        let destination =
            usize::from_str_radix(&parts[2][2..], 16).expect("failed to parse destination");
        let transition = match function {
            "has_edge_to" => EdgeTransition::Taken,
            "edge_only_taken_to" => EdgeTransition::NotTaken,
            "last_edge_to" => return Ok(None),
            _ => unimplemented!(),
        };

        log::info!(
            "edge predicate: {:?} {:?} {:?}",
            source,
            transition,
            destination
        );

        return Ok(Some(Predicate::Edge(EdgePredicate {
            source,
            transition,
            destination,
        })));
    // compare: <destination> <compare-type> <value>
    } else if function.contains("reg_val") {
        let value = usize::from_str_radix(&parts[2][2..], 16).expect("failed to parse value");
        let memory_locations =
            arm_isn_detail
                .operands()
                .into_iter()
                .filter_map(|op| match op.op_type {
                    ArmOperandType::Mem(mem) => Some(mem),
                    _ => None,
                });

        log::info!(
            "reg_val memory locations: {:?} parts: {:?}",
            memory_locations,
            parts
        );

        let memory = memory_locations
            .last()
            .and_then(|op| Some(MemoryLocation::from_arm_op_mem(op)));

        let destination = match parts[0] {
            "memory_address" => ValueDestination::Address(memory.expect("no memory location")),
            // todo: is operand_width always 4 byte ?
            "memory_value" => ValueDestination::Memory(4, memory.expect("no memory location")),
            register => ValueDestination::Register(
                RegisterArm::from_str(register)
                    .expect("failed to parse register")
                    .into(),
            ),
        };

        let compare = match function {
            "min_reg_val_less" => Compare::Less,
            "max_reg_val_less" => Compare::Less,
            "last_reg_val_less" => return Ok(None),
            "max_min_diff_reg_val_less" => return Ok(None),

            "min_reg_val_greater_or_equal" => Compare::GreaterOrEqual,
            "max_reg_val_greater_or_equal" => Compare::GreaterOrEqual,
            "last_reg_val_greater_or_equal" => return Ok(None),
            "max_min_diff_reg_val_greater_or_equal" => return Ok(None),

            _ => unimplemented!(),
        };

        return Ok(Some(Predicate::Compare(ComparePredicate {
            destination,
            compare,
            value,
        })));
    } else if function.contains("ins_count") {
        log::info!("ins_count unhandled ? {}", function);
        // "ins_count_less"
        // "ins_count_greater_or_equal"
    } else if function.contains("selector_val") {
        log::info!("selector val unhandled ? {}", function);
        // "selector_val_less_name"
        // "selector_val_less"
        // "selector_val_greater_or_equal_name"
        // "selector_val_greater_or_equal"
    } else if function.contains("num_successors") {
        log::info!("num_succcessors unhandled ? {}", function);
        // "num_successors_greater" =>
        // "num_successors_equal" =>
    } else if function.contains("flag") {
        let flag = match function {
            "min_carry_flag_set" => XPSR_Flags::CARRY_FLAG,
            "min_zero_flag_set" => XPSR_Flags::ZERO_FLAG,
            "min_sign_flag_set" => XPSR_Flags::SIGN_FLAG,
            "min_overflow_flag_set" => XPSR_Flags::OVERFLOW_FLAG,
            "min_saturation_flag_set" => XPSR_Flags::SATURATION_FLAG,

            "max_carry_flag_set" => XPSR_Flags::CARRY_FLAG,
            "max_zero_flag_set" => XPSR_Flags::ZERO_FLAG,
            "max_sign_flag_set" => XPSR_Flags::SIGN_FLAG,
            "max_overflow_flag_set" => XPSR_Flags::OVERFLOW_FLAG,
            "max_saturation_flag_set" => XPSR_Flags::SATURATION_FLAG,

            "last_carry_flag_set" => return Ok(None),
            "last_zero_flag_set" => return Ok(None),
            "last_sign_flag_set" => return Ok(None),
            "last_overflow_flag_set" => return Ok(None),
            "last_saturation_flag_set" => return Ok(None),
            _ => {
                println!("Unknown flag: {}", function);
                unimplemented!()
            }
        };

        return Ok(Some(Predicate::FlagSet(CpuFlags::ARM(flag))));
    }

    Ok(None)
}
