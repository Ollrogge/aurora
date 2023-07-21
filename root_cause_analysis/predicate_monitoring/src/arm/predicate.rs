use std::sync::Arc;

// TODO: merge shared functionality between x86 and arm
use super::register::Register;
use anyhow::{Context, Result};
use capstone::{
    arch::arm::{ArmInsnDetail, ArmOpMem, ArmOperandType},
    arch::DetailsArchInsn,
    prelude::*,
    InsnDetail,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    Compare(ComparePredicate),
    Edge(EdgePredicate),
    //FlagSet(RFlags),
    Visited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparePredicate {
    pub destination: ValueDestination,
    pub compare: Compare,
    pub value: usize,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryLocation {
    base: RegId,
    index: RegId,
    scale: i32,
    displacement: i32,
}

impl MemoryLocation {
    pub fn from_arm_op_mem(mem: ArmOpMem) -> MemoryLocation {
        MemoryLocation {
            base: mem.base(),
            index: mem.index(),
            scale: mem.scale(),
            displacement: mem.disp(),
        }
    }
}

pub type AccessSize = u8;

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

pub fn convert_predicate(
    predicate: &str,
    instruction_detail: InsnDetail,
) -> Result<Option<Predicate>> {
    let parts: Vec<_> = predicate.split(' ').collect();
    let function = match parts.len() {
        1 | 2 => parts[0],
        3 => parts[1],
        _ => unimplemented!(),
    };

    let arch_detail = instruction_detail
        .arch_detail()
        .arm()
        .context("instruction is not an arm inst")?;

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

        return Ok(Some(Predicate::Edge(EdgePredicate {
            source,
            transition,
            destination,
        })));
    } else if function.contains("reg_val") {
        let value = usize::from_str_radix(&parts[2][2..], 16).expect("failed to parse value");
        let memory_locations =
            arch_detail
                .operands()
                .into_iter()
                .filter_map(|op| match op.op_type {
                    ArmOperandType::Mem(mem) => Some(mem),
                    _ => None,
                });

        let memory = memory_locations
            .last()
            .and_then(|op| Some(MemoryLocation::from_arm_op_mem(op)))
            .context("Unable to create memory location")?;
    }

    Ok(None)
}
