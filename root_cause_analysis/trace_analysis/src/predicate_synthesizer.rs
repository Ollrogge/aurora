use crate::config::CpuArchitecture;
use crate::predicates::*;
use crate::register::{Register64 as RegisterX86, RegisterArm, REGISTERS_ARM, REGISTERS_X86};
use crate::trace::Selector;
use crate::trace_analyzer::TraceAnalyzer;
use rayon::prelude::*;

pub struct PredicateSynthesizer {
    arch: CpuArchitecture,
}

pub fn gen_reg_val_name(
    arch: CpuArchitecture,
    reg_index: Option<usize>,
    pred_name: String,
    value: u64,
) -> String {
    match reg_index.is_some() {
        true => {
            if arch == CpuArchitecture::ARM {
                return format!(
                    "{} {} 0x{:x}",
                    REGISTERS_ARM[reg_index.unwrap()],
                    pred_name,
                    value
                );
            } else {
                return format!(
                    "{} {} 0x{:x}",
                    REGISTERS_X86[reg_index.unwrap()],
                    pred_name,
                    value
                );
            };
        }
        false => format!("{} {}", pred_name, value),
    }
}

impl PredicateSynthesizer {
    pub fn new(arch: CpuArchitecture) -> PredicateSynthesizer {
        PredicateSynthesizer { arch }
    }
    pub fn constant_predicates_at_address(
        &self,
        address: usize,
        trace_analyzer: &TraceAnalyzer,
    ) -> Vec<Predicate> {
        let mut predicates = vec![];

        predicates.extend(self.register_constant_predicates_at_address(
            address,
            trace_analyzer,
            &Selector::RegMax,
        ));
        predicates.extend(self.register_constant_predicates_at_address(
            address,
            trace_analyzer,
            &Selector::RegMin,
        ));

        predicates
    }

    // for each address, for each instruction at that address
    // get all registers for those instruction expect some special ones
    // and get min / max value depending on selector, then synthesize constants
    // for this instruction and reg. e.g. r < c to find outliers later
    // ONLY consider memory addresses outside of valid range

    // considers every value outside of checked memory ranges and finds outliers
    fn register_constant_predicates_at_address(
        &self,
        address: usize,
        trace_analyzer: &TraceAnalyzer,
        selector: &Selector,
    ) -> Vec<Predicate> {
        let regs = match self.arch {
            CpuArchitecture::ARM => &*REGISTERS_ARM,
            CpuArchitecture::X86_64 => &*REGISTERS_X86,
        };
        (0..regs.len())
            .into_par_iter()
            .filter(|reg_index| {
                trace_analyzer.any_instruction_at_address_contains_reg(address, *reg_index)
            })
            /* skip rsp */
            .filter(|reg_index| match self.arch {
                CpuArchitecture::ARM => *reg_index != RegisterArm::SP as usize,
                CpuArchitecture::X86_64 => *reg_index != RegisterX86::Rsp as usize,
            })
            // filter pc in ARM trace
            .filter(|reg_index| match self.arch {
                CpuArchitecture::ARM => *reg_index != RegisterArm::PC as usize,
                CpuArchitecture::X86_64 => true,
            })
            .filter(|reg_index| match self.arch {
                CpuArchitecture::ARM => *reg_index != RegisterArm::LR as usize,
                CpuArchitecture::X86_64 => true,
            })
            /* skip EFLAGS */
            .filter(|reg_index| match self.arch {
                CpuArchitecture::ARM => {
                    *reg_index != RegisterArm::xPSR as usize
                        && *reg_index != RegisterArm::CPSR as usize
                        && *reg_index != RegisterArm::SPSR as usize
                }
                CpuArchitecture::X86_64 => *reg_index != (RegisterX86::Eflags as usize - 1),
            })
            /* skip memory address */
            .filter(|reg_index| match self.arch {
                CpuArchitecture::ARM => *reg_index != RegisterArm::MemoryAddress as usize,
                CpuArchitecture::X86_64 => *reg_index != (RegisterX86::MemoryAddress as usize - 1),
            })
            /* skip all valid memory regions */
            /* todo: more fine grained control. e.g. read-only mem can be read */
            .filter(|reg_index| {
                !trace_analyzer
                    .values_at_address(address, selector, Some(*reg_index))
                    .into_iter()
                    .all(|v: u64| {
                        trace_analyzer
                            .memory_addresses
                            .0
                            .values()
                            .all(|range| range.start <= v as usize && v as usize <= range.end)
                    })
            })
            .flat_map(|reg_index| {
                self.synthesize_constant_predicates(
                    address,
                    trace_analyzer,
                    selector,
                    Some(reg_index),
                )
            })
            .collect()
    }

    fn synthesize_constant_predicates(
        &self,
        address: usize,
        trace_analyzer: &TraceAnalyzer,
        selector: &Selector,
        reg_index: Option<usize>,
    ) -> Vec<Predicate> {
        let values = trace_analyzer.unique_values_at_address(address, selector, reg_index);
        if values.is_empty() {
            return vec![];
        }

        let mut f: Vec<_> = values
            .par_iter()
            .map(|v| {
                (
                    v,
                    PredicateSynthesizer::evaluate_value_at_address(
                        address,
                        trace_analyzer,
                        selector,
                        reg_index,
                        *v,
                    ),
                )
            })
            .collect();

        f.sort_by(|(_, f1), (_, f2)| f1.partial_cmp(&f2).unwrap());

        self.build_constant_predicates(
            address,
            selector,
            reg_index,
            PredicateSynthesizer::arithmetic_mean(*f.first().unwrap().0, &values),
            PredicateSynthesizer::arithmetic_mean(*f.last().unwrap().0, &values),
        )
    }

    fn arithmetic_mean(v1: u64, values: &Vec<u64>) -> u64 {
        match values.iter().filter(|v| *v < &v1).max() {
            Some(v2) => ((v1 as f64 + *v2 as f64) / 2.0).round() as u64,
            None => v1,
        }
    }

    fn build_constant_predicates(
        &self,
        address: usize,
        selector: &Selector,
        reg_index: Option<usize>,
        v1: u64,
        v2: u64,
    ) -> Vec<Predicate> {
        let pred_name1 = gen_reg_val_name(
            self.arch,
            reg_index,
            selector_val_greater_or_equal_name(selector),
            v1,
        );
        let pred_name2 =
            gen_reg_val_name(self.arch, reg_index, selector_val_less_name(selector), v2);

        vec![
            Predicate::new(
                &pred_name1,
                address,
                selector_val_greater_or_equal(selector),
                reg_index,
                Some(v1 as usize),
            ),
            Predicate::new(
                &pred_name2,
                address,
                selector_val_less(selector),
                reg_index,
                Some(v2 as usize),
            ),
        ]
    }

    fn evaluate_value_at_address(
        address: usize,
        trace_analyzer: &TraceAnalyzer,
        selector: &Selector,
        reg_index: Option<usize>,
        val: u64,
    ) -> f64 {
        let pred_name = format!(
            "{:?} {} {}",
            reg_index,
            selector_val_less_name(selector),
            val
        );

        let predicate = Predicate::new(
            &pred_name,
            address,
            selector_val_less(selector),
            reg_index,
            Some(val as usize),
        );

        PredicateSynthesizer::evaluate_predicate_with_reachability(
            address,
            trace_analyzer,
            &predicate,
        )
    }

    pub fn evaluate_predicate_with_reachability(
        address: usize,
        trace_analyzer: &TraceAnalyzer,
        predicate: &Predicate,
    ) -> f64 {
        let true_positives = trace_analyzer
            .crashes
            .as_slice()
            .par_iter()
            .filter(|t| t.instructions.get(&address).is_some())
            .map(|t| t.instructions.get(&address))
            .filter(|i| predicate.execute(i))
            .count() as f64
            / trace_analyzer.crashes.len() as f64;
        let true_negatives = (trace_analyzer
            .non_crashes
            .as_slice()
            .par_iter()
            .filter(|t| t.instructions.get(&address).is_some())
            .map(|t| t.instructions.get(&address))
            .filter(|i| !predicate.execute(i))
            .count() as f64
            + trace_analyzer
                .non_crashes
                .as_slice()
                .par_iter()
                .filter(|t| t.instructions.get(&address).is_none())
                .count() as f64)
            / trace_analyzer.non_crashes.len() as f64;

        let score = (true_positives + true_negatives) / 2.0;

        score
    }
}
