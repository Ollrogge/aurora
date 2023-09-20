use crate::config::CpuArchitecture;
use crate::control_flow_graph::ControlFlowGraph;
use crate::predicate_synthesizer::{gen_reg_val_name, PredicateSynthesizer};
use crate::predicates::*;
use crate::register::{Register64 as RegisterX86, RegisterArm, REGISTERS_ARM, REGISTERS_X86};
use crate::trace::Instruction;
use crate::trace::Selector;
use crate::trace_analyzer::TraceAnalyzer;

pub struct PredicateBuilder {
    arch: CpuArchitecture,
}

impl PredicateBuilder {
    pub fn new(arch: CpuArchitecture) -> PredicateBuilder {
        PredicateBuilder { arch }
    }

    fn gen_visited(address: usize) -> Vec<Predicate> {
        vec![Predicate::new(
            "is_visited",
            address,
            is_visited,
            None,
            None,
        )]
    }
    fn gen_all_edge_from_to_predicates(
        address: usize,
        cfg: &ControlFlowGraph,
        pred_name: &str,
        func: fn(&Instruction, Option<usize>, Option<usize>) -> bool,
    ) -> Vec<Predicate> {
        cfg.get_instruction_successors(address)
            .iter()
            .map(|to| {
                let pred_name = format!("0x{:x} {} 0x{:x}", address, pred_name, to);
                Predicate::new(&pred_name, address, func, Some(*to), None)
            })
            .collect()
    }

    fn gen_all_conditional_edge_from_to_predicates(
        address: usize,
        cfg: &ControlFlowGraph,
        pred_name: &str,
        func: fn(&Instruction, Option<usize>, Option<usize>) -> bool,
    ) -> Vec<Predicate> {
        cfg.get_instruction_successors(address)
            .iter()
            .map(|to| {
                let pred_name = format!("0x{:x} {} 0x{:x}", address, pred_name, to);
                Predicate::new(&pred_name, address, func, Some(*to), None)
            })
            .collect()
    }

    fn gen_all_edge_val_predicates(
        address: usize,
        pred_name: &str,
        value: usize,
        func: fn(&Instruction, Option<usize>, Option<usize>) -> bool,
    ) -> Predicate {
        let pred_name = format!("{} {}", pred_name, value);

        Predicate::new(&pred_name, address, func, Some(value), None)
    }

    pub fn gen_flag_predicates(
        &self,
        address: usize,
        trace_analyzer: &TraceAnalyzer,
    ) -> Vec<Predicate> {
        let flags_reg_idx = match self.arch {
            CpuArchitecture::ARM => RegisterArm::xPSR as usize,
            CpuArchitecture::X86_64 => RegisterX86::Eflags as usize,
        };

        if !trace_analyzer.any_instruction_at_address_contains_reg(address, flags_reg_idx) {
            return vec![];
        }

        let mut flag_predicates = Vec::new();

        if self.arch == CpuArchitecture::ARM {
            flag_predicates.extend_from_slice(&vec![
                Predicate::new(
                    "max_saturation_flag_set",
                    address,
                    max_saturation_flag_set,
                    None,
                    None,
                ),
                Predicate::new(
                    "min_saturation_flag_set",
                    address,
                    min_saturation_flag_set,
                    None,
                    None,
                ),
            ])
        } else {
            flag_predicates.extend_from_slice(&vec![
                Predicate::new(
                    "max_parity_flag_set",
                    address,
                    max_parity_flag_set,
                    None,
                    None,
                ),
                Predicate::new(
                    "min_parity_flag_set",
                    address,
                    min_parity_flag_set,
                    None,
                    None,
                ),
                Predicate::new(
                    "max_adjust_flag_set",
                    address,
                    max_adjust_flag_set,
                    None,
                    None,
                ),
                Predicate::new(
                    "min_adjust_flag_set",
                    address,
                    min_adjust_flag_set,
                    None,
                    None,
                ),
                Predicate::new("max_trap_flag_set", address, max_trap_flag_set, None, None),
                Predicate::new("min_trap_flag_set", address, min_trap_flag_set, None, None),
                Predicate::new(
                    "max_interrupt_flag_set",
                    address,
                    max_interrupt_flag_set,
                    None,
                    None,
                ),
                Predicate::new(
                    "min_interrupt_flag_set",
                    address,
                    min_interrupt_flag_set,
                    None,
                    None,
                ),
                Predicate::new(
                    "max_direction_flag_set",
                    address,
                    max_direction_flag_set,
                    None,
                    None,
                ),
                Predicate::new(
                    "min_direction_flag_set",
                    address,
                    min_direction_flag_set,
                    None,
                    None,
                ),
                Predicate::new(
                    "max_parity_flag_set",
                    address,
                    max_parity_flag_set,
                    None,
                    None,
                ),
                Predicate::new(
                    "min_parity_flag_set",
                    address,
                    min_parity_flag_set,
                    None,
                    None,
                ),
            ])
        }

        flag_predicates.extend_from_slice(&vec![
            Predicate::new(
                "max_carry_flag_set",
                address,
                max_carry_flag_set,
                None,
                None,
            ),
            Predicate::new(
                "min_carry_flag_set",
                address,
                min_carry_flag_set,
                None,
                None,
            ),
            Predicate::new("max_zero_flag_set", address, max_zero_flag_set, None, None),
            Predicate::new("min_zero_flag_set", address, min_zero_flag_set, None, None),
            Predicate::new("max_sign_flag_set", address, max_sign_flag_set, None, None),
            Predicate::new("min_sign_flag_set", address, min_sign_flag_set, None, None),
            Predicate::new(
                "max_overflow_flag_set",
                address,
                max_overflow_flag_set,
                None,
                None,
            ),
            Predicate::new(
                "min_overflow_flag_set",
                address,
                min_overflow_flag_set,
                None,
                None,
            ),
        ]);

        flag_predicates
    }

    pub fn gen_cfg_predicates(&self, address: usize, cfg: &ControlFlowGraph) -> Vec<Predicate> {
        let mut ret = vec![];

        // check if end of basic block
        if !cfg.is_bb_end(address) {
            return ret;
        }

        // #successors > 0
        ret.push(PredicateBuilder::gen_all_edge_val_predicates(
            address,
            "num_successors_greater",
            0,
            num_successors_greater,
        ));
        // #successors > 1
        ret.push(PredicateBuilder::gen_all_edge_val_predicates(
            address,
            "num_successors_greater",
            1,
            num_successors_greater,
        ));
        // #successors > 2
        ret.push(PredicateBuilder::gen_all_edge_val_predicates(
            address,
            "num_successors_greater",
            2,
            num_successors_greater,
        ));

        // #successors == 0
        ret.push(PredicateBuilder::gen_all_edge_val_predicates(
            address,
            "num_successors_equal",
            0,
            num_successors_equal,
        ));
        // #successors == 1
        ret.push(PredicateBuilder::gen_all_edge_val_predicates(
            address,
            "num_successors_equal",
            1,
            num_successors_equal,
        ));
        // #successors == 2
        ret.push(PredicateBuilder::gen_all_edge_val_predicates(
            address,
            "num_successors_equal",
            2,
            num_successors_equal,
        ));
        // edge addr -> x cfg edges exists
        ret.extend(PredicateBuilder::gen_all_edge_from_to_predicates(
            address,
            cfg,
            "has_edge_to",
            has_edge_to,
        ));
        ret.extend(PredicateBuilder::gen_all_edge_from_to_predicates(
            address,
            cfg,
            "edge_only_taken_to",
            edge_only_taken_to,
        ));
        ret
    }

    fn gen_all_reg_val_predicates(
        &self,
        address: usize,
        trace_analyzer: &TraceAnalyzer,
        selector: &Selector,
        value: usize,
    ) -> Vec<Predicate> {
        let regs = match self.arch {
            CpuArchitecture::ARM => &*REGISTERS_ARM,
            CpuArchitecture::X86_64 => &*REGISTERS_X86,
        };
        (0..regs.len())
            .into_iter()
            .filter(|reg_index| {
                trace_analyzer.any_instruction_at_address_contains_reg(address, *reg_index)
            })
            .filter(|reg_index| {
                match self.arch {
                    /* skip RSP */
                    CpuArchitecture::X86_64 => *reg_index != RegisterX86::Rsp as usize,
                    /* skip sp */
                    CpuArchitecture::ARM => *reg_index != (RegisterArm::SP as usize),
                }
            })
            // skip ARM trace pc member
            .filter(|reg_index| match self.arch {
                CpuArchitecture::ARM => *reg_index != RegisterArm::PC as usize,
                CpuArchitecture::X86_64 => true,
            })
            .filter(|reg_index| match self.arch {
                CpuArchitecture::ARM => *reg_index != RegisterArm::LR as usize,
                CpuArchitecture::X86_64 => true,
            })
            .filter(|reg_index| {
                match self.arch {
                    /* skip EFLAGS */
                    /* -1 as x86_64 has no rip in registers */
                    CpuArchitecture::X86_64 => *reg_index != (RegisterX86::Eflags as usize - 1),
                    CpuArchitecture::ARM => {
                        *reg_index != (RegisterArm::xPSR as usize)
                            && *reg_index != (RegisterArm::CPSR as usize)
                    }
                }
            })
            /* skip memory address */
            .filter(|reg_index| match self.arch {
                CpuArchitecture::X86_64 => *reg_index != (RegisterX86::MemoryAddress as usize - 1),
                CpuArchitecture::ARM => *reg_index != RegisterArm::MemoryAddress as usize,
            })
            // ram addresses in registers are too noisy
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
            .map(|reg_index| {
                let pred_name = gen_reg_val_name(
                    self.arch,
                    Some(reg_index),
                    selector_val_less_name(selector),
                    value as u64,
                );
                Predicate::new(
                    &pred_name,
                    address,
                    selector_val_less(&selector),
                    Some(reg_index),
                    Some(value),
                )
            })
            .collect()
    }

    pub fn gen_register_predicates(
        &self,
        address: usize,
        trace_analyzer: &TraceAnalyzer,
    ) -> Vec<Predicate> {
        let mut ret = vec![];

        if self.arch != CpuArchitecture::ARM {
            ret.extend(self.gen_all_reg_val_predicates(
                address,
                trace_analyzer,
                &Selector::RegMax,
                0xffffffffffffffff,
            ));
        }
        ret.extend(self.gen_all_reg_val_predicates(
            address,
            trace_analyzer,
            &Selector::RegMax,
            0xffffffff,
        ));
        ret.extend(self.gen_all_reg_val_predicates(
            address,
            trace_analyzer,
            &Selector::RegMax,
            0xffff,
        ));
        ret.extend(self.gen_all_reg_val_predicates(
            address,
            trace_analyzer,
            &Selector::RegMax,
            0xff,
        ));

        if self.arch != CpuArchitecture::ARM {
            ret.extend(self.gen_all_reg_val_predicates(
                address,
                trace_analyzer,
                &Selector::RegMin,
                0xffffffffffffffff,
            ));
        }
        ret.extend(self.gen_all_reg_val_predicates(
            address,
            trace_analyzer,
            &Selector::RegMin,
            0xffffffff,
        ));
        ret.extend(self.gen_all_reg_val_predicates(
            address,
            trace_analyzer,
            &Selector::RegMin,
            0xffff,
        ));
        ret.extend(self.gen_all_reg_val_predicates(
            address,
            trace_analyzer,
            &Selector::RegMin,
            0xff,
        ));

        ret
    }

    pub fn gen_predicates(&self, address: usize, trace_analyzer: &TraceAnalyzer) -> Vec<Predicate> {
        let mut ret = vec![];

        let skip_register_predicates = if self.arch == CpuArchitecture::X86_64 {
            PredicateBuilder::skip_register_mnemonic(trace_analyzer.get_any_mnemonic(address))
        } else {
            false
        };

        ret.extend(PredicateBuilder::gen_visited(address));

        if !skip_register_predicates {
            let ps = PredicateSynthesizer::new(self.arch);

            ret.extend(ps.constant_predicates_at_address(address, trace_analyzer));

            ret.extend(self.gen_register_predicates(address, &trace_analyzer));
        }

        ret.extend(self.gen_cfg_predicates(address, &trace_analyzer.cfg));

        if !skip_register_predicates {
            ret.extend(self.gen_flag_predicates(address, &trace_analyzer));
        }

        ret
    }

    fn skip_register_mnemonic(mnemonic: String) -> bool {
        //println!("mmenonic: {}", mnemonic);
        match mnemonic.as_str() {
            // leave instruction
            _ if mnemonic.contains("leave") => true,
            // contains floating point register
            _ if mnemonic.contains("xmm") => true,
            // contains rsp but is no memory operation
            _ if !mnemonic.contains("[") && mnemonic.contains("rsp") => true,
            // moves a constant into register/memory
            _ if mnemonic.contains("mov") && mnemonic.contains(", 0x") => true,
            _ => false,
        }
    }
}
