mod predicate;
mod register;

use anyhow::{anyhow, Context, Result};
use capstone::arch::arm::{self, ArmInsn, ArmOperandType};
use capstone::prelude::*;
use predicate::*;
use std::collections::HashMap;
use trace_analysis::predicates::SerializedPredicate;

#[derive(Debug, Clone)]
pub struct RootCauseCandidate {
    pub address: usize,
    pub score: f64,
    pub predicate: Predicate,
}

// todo: dont hardcore register amount
pub fn rank_predicates(
    predicates: &Vec<SerializedPredicate>,
    detailed_trace: Vec<(usize, [u32; 18])>,
    binary: &Vec<u8>,
) -> Vec<usize> {
    let decoder = Capstone::new()
        .arm()
        .mode(arm::ArchMode::Thumb)
        .detail(true)
        .endian(capstone::Endian::Little)
        .build()
        .expect("failed to init capstone");

    let mut rccs = convert_predicates(&decoder, predicates, &detailed_trace, binary);
    vec![]
}

fn convert_predicates(
    cs: &Capstone,
    predicates: &Vec<SerializedPredicate>,
    detailed_trace: &Vec<(usize, [u32; 18])>,
    binary: &Vec<u8>,
) -> Result<HashMap<usize, RootCauseCandidate>> {
    let res = HashMap::new();
    for pred in predicates.iter() {
        let pc = pred.address;
        let inst = cs
            .disasm_all(&binary[pc..pc + 4], 0)
            .ok()
            .and_then(|insts| insts.iter().next())
            .context("disasm instruction")?;

        let inst_detail = cs
            .insn_detail(&inst)
            .map_err(|_| anyhow!("failed to get insn detail"))?;
    }

    res
}
