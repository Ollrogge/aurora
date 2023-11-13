use crate::addr2line_lib::{addr2func, addr2line};
use crate::config::{Config, CpuArchitecture};
use crate::register::{Register64 as RegisterX86, RegisterArm};
use crate::trace::{Instruction, Register, Selector};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedPredicate {
    pub name: String,
    pub score: f64,
    pub address: usize,
    pub id: usize,
    pub addr2line_info: String,
}

lazy_static! {
    static ref ID: AtomicUsize = AtomicUsize::new(0);
}

impl SerializedPredicate {
    pub fn new(config: &Config, name: String, address: usize, score: f64) -> SerializedPredicate {
        let to_be_hashed = format!("{}{}{}", name, address, score);
        let mut hasher = DefaultHasher::new();
        to_be_hashed.hash(&mut hasher);
        let hash = hasher.finish();

        SerializedPredicate {
            name,
            score,
            address,
            id: hash as usize,
            addr2line_info: "".to_string(),
        }
    }

    pub fn to_string(&self) -> String {
        format!("{:#018x} -- {} -- {}", self.address, self.name, self.score)
    }

    pub fn set_addr2line_info(&mut self, info: String) {
        self.addr2line_info = info;
    }

    pub fn get_func_name(&self) -> String {
        let parts: Vec<&str> = self.addr2line_info.split(" ").collect();

        let mut func_name = parts[1].to_string();
        func_name.retain(|c| !c.is_whitespace());

        func_name
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(&self).expect(&format!(
            "Could not serialize predicate {}",
            self.to_string()
        ))
    }
}

#[derive(Clone, PartialEq)]
pub enum Predicate {
    Simple(SimplePredicate),
    Composite(CompositePredicate),
}

impl Predicate {
    pub fn execute(&self, instruction_option: &Option<&Instruction>) -> bool {
        match self {
            Predicate::Composite(composite) => composite.execute(instruction_option),
            Predicate::Simple(simple) => simple.execute(instruction_option),
        }
    }

    pub fn get_name(&self) -> &String {
        match self {
            Predicate::Composite(composite) => &composite.name,
            Predicate::Simple(simple) => &simple.name,
        }
    }

    pub fn get_address(&self) -> usize {
        match self {
            Predicate::Composite(composite) => composite.address,
            Predicate::Simple(simple) => simple.address,
        }
    }

    pub fn set_score(&mut self, score: f64) {
        match self {
            Predicate::Composite(composite) => composite.score = score,
            Predicate::Simple(simple) => simple.score = score,
        }
    }

    pub fn get_score(&self) -> f64 {
        match self {
            Predicate::Composite(composite) => composite.score,
            Predicate::Simple(simple) => simple.score,
        }
    }

    pub fn to_serialized(&self, config: &Config) -> SerializedPredicate {
        match self {
            Predicate::Composite(composite) => composite.to_serialized(config),
            Predicate::Simple(simple) => simple.to_serialized(config),
        }
    }

    pub fn to_serialized_with_func_name(&self, config: &Config) -> SerializedPredicate {
        match self {
            Predicate::Composite(composite) => composite.to_serialized_with_func_name(config),
            Predicate::Simple(simple) => simple.to_serialized_with_func_name(config),
        }
    }

    pub fn get_p1(&self) -> Option<usize> {
        match self {
            Predicate::Composite(composite) => composite.p1,
            Predicate::Simple(simple) => simple.p1,
        }
    }

    pub fn get_p2(&self) -> Option<usize> {
        match self {
            Predicate::Composite(composite) => composite.p2,
            Predicate::Simple(simple) => simple.p2,
        }
    }
}

#[derive(Clone)]
pub struct CompositePredicate {
    pub name: String,
    pub p1: Option<usize>,
    pub p2: Option<usize>,
    predicates: Vec<Predicate>,
    function: Option<fn(&Instruction, Option<usize>, Option<usize>) -> bool>,
    pub score: f64,
    pub address: usize,
}

impl PartialEq for CompositePredicate {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.p1 == other.p1
            && self.p2 == other.p2
            && self.score == other.score
            && self.address == other.address
    }
}

impl CompositePredicate {
    pub fn new(
        name: &str,
        address: usize,
        predicates: Vec<Predicate>,
        function: Option<fn(&Instruction, Option<usize>, Option<usize>) -> bool>,
        p1: Option<usize>,
        p2: Option<usize>,
    ) -> CompositePredicate {
        CompositePredicate {
            name: name.to_string(),
            address,
            p1,
            p2,
            predicates,
            function,
            score: 0.0,
        }
    }

    pub fn to_serialized(&self, config: &Config) -> SerializedPredicate {
        SerializedPredicate::new(config, self.name.to_string(), self.address, self.score)
    }

    pub fn to_serialized_with_func_name(&self, config: &Config) -> SerializedPredicate {
        let mut pred =
            SerializedPredicate::new(config, self.name.to_string(), self.address, self.score);

        let info = addr2line(config, pred.address);

        pred.set_addr2line_info(info);

        pred
    }

    pub fn execute(&self, instruction_option: &Option<&Instruction>) -> bool {
        match instruction_option {
            Some(instruction) => {
                let results: Vec<bool> = self
                    .predicates
                    .iter()
                    .map(|p| p.execute(&Some(instruction)))
                    .collect();

                results.iter().all(|&x| x)
            }
            None => false,
        }
    }

    // currently we assume just one inner predicate
    pub fn get_inner(&self) -> &Predicate {
        &self.predicates[0]
    }

    pub fn get_best_score(&self) -> f64 {
        self.predicates
            .iter()
            .max_by(|a, b| a.get_score().partial_cmp(&b.get_score()).unwrap())
            .unwrap()
            .get_score()
    }
}

#[derive(Clone)]
pub struct SimplePredicate {
    pub name: String,
    pub p1: Option<usize>,
    pub p2: Option<usize>,
    function: fn(&Instruction, Option<usize>, Option<usize>) -> bool,
    pub score: f64,
    pub address: usize,
}

impl PartialEq for SimplePredicate {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.p1 == other.p1
            && self.p2 == other.p2
            && self.score == other.score
            && self.address == other.address
    }
}

impl SimplePredicate {
    pub fn new(
        name: &str,
        address: usize,
        function: fn(&Instruction, Option<usize>, Option<usize>) -> bool,
        p1: Option<usize>,
        p2: Option<usize>,
    ) -> SimplePredicate {
        SimplePredicate {
            name: name.to_string(),
            address,
            p1,
            p2,
            function,
            score: 0.0,
        }
    }

    pub fn gen_empty(address: usize) -> Predicate {
        Predicate::Simple(SimplePredicate::new("empty", address, empty, None, None))
    }

    pub fn to_serialized(&self, config: &Config) -> SerializedPredicate {
        SerializedPredicate::new(config, self.name.to_string(), self.address, self.score)
    }

    pub fn to_serialized_with_func_name(&self, config: &Config) -> SerializedPredicate {
        let mut pred =
            SerializedPredicate::new(config, self.name.to_string(), self.address, self.score);

        let info = addr2line(config, pred.address);

        pred.set_addr2line_info(info);

        pred
    }

    pub fn execute(&self, instruction_option: &Option<&Instruction>) -> bool {
        match instruction_option {
            Some(instruction) => (self.function)(instruction, self.p1, self.p2),
            None => false,
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}", self.name)
    }
}

pub fn empty(_: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    false
}

pub fn is_visited(_: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    true
}

pub fn reaches(inst: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    inst.reaches_crash_address
}

pub fn selector_val_less_name(selector: &Selector) -> String {
    match selector {
        Selector::RegMin => format!("min_reg_val_less"),
        Selector::RegMax => format!("max_reg_val_less"),
        Selector::RegMaxMinDiff => format!("max_min_diff_reg_val_less"),
        Selector::InsCount => format!("ins_count_less"),
        _ => unreachable!(),
    }
}

pub fn selector_val_less(
    selector: &Selector,
) -> fn(&Instruction, Option<usize>, Option<usize>) -> bool {
    match selector {
        Selector::RegMin => min_reg_val_less,
        Selector::RegMax => max_reg_val_less,
        Selector::RegMaxMinDiff => max_min_diff_reg_val_less,
        //        Selector::InsCount => ins_count_less,
        _ => unreachable!(),
    }
}

pub fn min_reg_val_less(
    instruction: &Instruction,
    reg_index: Option<usize>,
    value: Option<usize>,
) -> bool {
    match instruction.registers_min.get(reg_index.unwrap()) {
        Some(reg) => reg.value() < value.unwrap() as u64,
        None => false,
    }
}

pub fn max_reg_val_less(
    instruction: &Instruction,
    reg_index: Option<usize>,
    value: Option<usize>,
) -> bool {
    match instruction.registers_max.get(reg_index.unwrap()) {
        Some(reg) => reg.value() < value.unwrap() as u64,
        None => false,
    }
}

pub fn max_min_diff_reg_val_less(
    instruction: &Instruction,
    reg_index: Option<usize>,
    value: Option<usize>,
) -> bool {
    match (
        instruction.registers_max.get(reg_index.unwrap()),
        instruction.registers_min.get(reg_index.unwrap()),
    ) {
        (Some(reg_max), Some(reg_min)) => reg_max.value() - reg_min.value() < value.unwrap() as u64,
        _ => false,
    }
}

pub fn selector_val_greater_or_equal_name(selector: &Selector) -> String {
    match selector {
        Selector::RegMin => format!("min_reg_val_greater_or_equal"),
        Selector::RegMax => format!("max_reg_val_greater_or_equal"),
        Selector::RegMaxMinDiff => format!("max_min_diff_reg_val_greater_or_equal"),
        Selector::InsCount => format!("ins_count_greater_or_equal"),
        _ => unreachable!(),
    }
}

pub fn selector_val_greater_or_equal(
    selector: &Selector,
) -> fn(&Instruction, Option<usize>, Option<usize>) -> bool {
    match selector {
        Selector::RegMin => min_reg_val_greater_or_equal,
        Selector::RegMax => max_reg_val_greater_or_equal,
        Selector::RegMaxMinDiff => max_min_diff_reg_val_greater_or_equal,
        //        Selector::InsCount => ins_count_greater_or_equal,
        _ => unreachable!(),
    }
}

pub fn min_reg_val_greater_or_equal(
    instruction: &Instruction,
    reg_index: Option<usize>,
    value: Option<usize>,
) -> bool {
    match instruction.registers_min.get(reg_index.unwrap()) {
        Some(reg) => reg.value() >= value.unwrap() as u64,
        None => false,
    }
}

pub fn max_reg_val_greater_or_equal(
    instruction: &Instruction,
    reg_index: Option<usize>,
    value: Option<usize>,
) -> bool {
    match instruction.registers_max.get(reg_index.unwrap()) {
        Some(reg) => reg.value() >= value.unwrap() as u64,
        None => false,
    }
}

pub fn max_min_diff_reg_val_greater_or_equal(
    instruction: &Instruction,
    reg_index: Option<usize>,
    value: Option<usize>,
) -> bool {
    match (
        instruction.registers_max.get(reg_index.unwrap()),
        instruction.registers_min.get(reg_index.unwrap()),
    ) {
        (Some(reg_max), Some(reg_min)) => {
            reg_max.value() - reg_min.value() >= value.unwrap() as u64
        }
        _ => false,
    }
}

fn is_flag_bit_set(instruction: &Instruction, reg_type: Selector, pos: u64) -> bool {
    let flags_idx = match instruction.arch {
        CpuArchitecture::X86 => RegisterX86::Eflags as usize - 1,
        CpuArchitecture::ARM => RegisterArm::xPSR as usize,
    };
    match reg_type {
        Selector::RegMin => is_reg_bit_set(instruction.registers_min.get(flags_idx), pos),
        Selector::RegMax => is_reg_bit_set(instruction.registers_max.get(flags_idx), pos),
        //        Selector::RegLast => is_reg_bit_set(instruction.registers_last.get(22), pos),
        _ => unreachable!(),
    }
}

fn is_reg_bit_set(reg: Option<&Register>, pos: u64) -> bool {
    match reg.is_some() {
        true => match reg.unwrap().value() & (1 << pos) {
            0 => false,
            _ => true,
        },
        _ => false,
    }
}

pub fn min_carry_flag_set(instruction: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMin, 0),
        CpuArchitecture::ARM => is_flag_bit_set(instruction, Selector::RegMin, 29),
    }
}

pub fn min_parity_flag_set(instruction: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMin, 2),
        CpuArchitecture::ARM => false,
    }
}

pub fn min_adjust_flag_set(instruction: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMin, 4),
        CpuArchitecture::ARM => false,
    }
}

pub fn min_zero_flag_set(instruction: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMin, 6),
        CpuArchitecture::ARM => is_flag_bit_set(instruction, Selector::RegMin, 30),
    }
}

pub fn min_sign_flag_set(instruction: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMin, 7),
        CpuArchitecture::ARM => is_flag_bit_set(instruction, Selector::RegMin, 31),
    }
}

pub fn min_trap_flag_set(instruction: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMin, 8),
        CpuArchitecture::ARM => false,
    }
}

pub fn min_interrupt_flag_set(
    instruction: &Instruction,
    _: Option<usize>,
    _: Option<usize>,
) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMin, 9),
        //todo: BASEPRI / PRIMASK register
        CpuArchitecture::ARM => false,
    }
}

pub fn min_direction_flag_set(
    instruction: &Instruction,
    _: Option<usize>,
    _: Option<usize>,
) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMin, 10),
        CpuArchitecture::ARM => false,
    }
}

pub fn min_overflow_flag_set(
    instruction: &Instruction,
    _: Option<usize>,
    _: Option<usize>,
) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMin, 11),
        CpuArchitecture::ARM => is_flag_bit_set(instruction, Selector::RegMin, 28),
    }
}

pub fn min_saturation_flag_set(
    instruction: &Instruction,
    _: Option<usize>,
    _: Option<usize>,
) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => false,
        CpuArchitecture::ARM => is_flag_bit_set(instruction, Selector::RegMin, 27),
    }
}

pub fn max_carry_flag_set(instruction: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMax, 0),
        CpuArchitecture::ARM => is_flag_bit_set(instruction, Selector::RegMax, 29),
    }
}

pub fn max_parity_flag_set(instruction: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMax, 2),
        CpuArchitecture::ARM => false,
    }
}

pub fn max_adjust_flag_set(instruction: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMax, 4),
        CpuArchitecture::ARM => false,
    }
}

pub fn max_zero_flag_set(instruction: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMax, 6),
        CpuArchitecture::ARM => is_flag_bit_set(instruction, Selector::RegMax, 30),
    }
}

pub fn max_sign_flag_set(instruction: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMax, 7),
        CpuArchitecture::ARM => is_flag_bit_set(instruction, Selector::RegMax, 31),
    }
}

pub fn max_trap_flag_set(instruction: &Instruction, _: Option<usize>, _: Option<usize>) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMax, 8),
        CpuArchitecture::ARM => false,
    }
}

pub fn max_interrupt_flag_set(
    instruction: &Instruction,
    _: Option<usize>,
    _: Option<usize>,
) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMax, 9),
        //todo: BASEPRI / PRIMASK register
        CpuArchitecture::ARM => false,
    }
}

pub fn max_direction_flag_set(
    instruction: &Instruction,
    _: Option<usize>,
    _: Option<usize>,
) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMax, 10),
        CpuArchitecture::ARM => false,
    }
}

pub fn max_overflow_flag_set(
    instruction: &Instruction,
    _: Option<usize>,
    _: Option<usize>,
) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => is_flag_bit_set(instruction, Selector::RegMax, 11),
        CpuArchitecture::ARM => is_flag_bit_set(instruction, Selector::RegMax, 28),
    }
}

pub fn max_saturation_flag_set(
    instruction: &Instruction,
    _: Option<usize>,
    _: Option<usize>,
) -> bool {
    match instruction.arch {
        CpuArchitecture::X86 => false,
        CpuArchitecture::ARM => is_flag_bit_set(instruction, Selector::RegMax, 27),
    }
}

pub fn num_successors_greater(
    instruction: &Instruction,
    n: Option<usize>,
    _: Option<usize>,
) -> bool {
    instruction.successors.len() > n.unwrap()
}

pub fn num_successors_equal(instruction: &Instruction, n: Option<usize>, _: Option<usize>) -> bool {
    instruction.successors.len() == n.unwrap()
}

pub fn has_edge_to(instruction: &Instruction, address: Option<usize>, _: Option<usize>) -> bool {
    // an unconditional branch is kinda useless and misleading
    instruction
        .successors
        .iter()
        .any(|s| s.address == address.unwrap() && s.is_conditional())
}

pub fn edge_only_taken_to(
    instruction: &Instruction,
    address: Option<usize>,
    _: Option<usize>,
) -> bool {
    instruction
        .successors
        .iter()
        .any(|s| s.address == address.unwrap())
        && instruction.successors.len() == 1
}
