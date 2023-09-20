use crate::config::CpuArchitecture;
use crate::predicate_builder::PredicateBuilder;
use crate::predicates::Predicate;

use crate::trace_analyzer::TraceAnalyzer;
use rayon::prelude::*;

pub struct PredicateAnalyzer {}

impl PredicateAnalyzer {
    // Vec because there can be multiple best predicates for an address (same score)
    pub fn evaluate_best_predicates_at_address(
        address: usize,
        trace_analyzer: &TraceAnalyzer,
        arch: CpuArchitecture,
    ) -> Vec<Predicate> {
        let pb = PredicateBuilder::new(arch);
        let predicates = pb.gen_predicates(address, trace_analyzer);

        if predicates.is_empty() {
            return vec![Predicate::gen_empty(address)];
        }

        if address == 0x200fd4 {
            for p in predicates.iter() {
                println!("TEST: {}", p.name);
            }
        }

        let mut ret: Vec<Predicate> = predicates
            .into_par_iter()
            .map(|p| PredicateAnalyzer::evaluate_predicate(trace_analyzer, p))
            .collect();

        ret.sort_by(|p1, p2| p1.score.partial_cmp(&p2.score).unwrap());
        let highest_score = ret.last().unwrap().score;

        /*
        We're using (item.score - highest_score).abs() < std::f64::EPSILON to compare floating point numbers for equality because directly comparing them might lead to inaccuracies due to floating point precision issues.
         */
        ret.into_iter()
            .filter(|p| (p.score - highest_score).abs() < std::f64::EPSILON)
            .collect()
    }

    fn evaluate_predicate(trace_analyzer: &TraceAnalyzer, mut predicate: Predicate) -> Predicate {
        let true_positives = trace_analyzer
            .crashes
            .as_slice()
            .par_iter()
            .map(|t| t.instructions.get(&predicate.address))
            .filter(|i| predicate.execute(i))
            .count() as f64
            / trace_analyzer.crashes.len() as f64;

        let true_negatives = trace_analyzer
            .non_crashes
            .as_slice()
            .par_iter()
            .map(|t| t.instructions.get(&predicate.address))
            .filter(|i| !predicate.execute(i))
            .count() as f64
            / trace_analyzer.non_crashes.len() as f64;

        predicate.score = (true_positives + true_negatives) / 2.0;

        predicate
    }
}
