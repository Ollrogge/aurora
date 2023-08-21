use crate::config::CpuArchitecture;
use crate::predicate_builder::PredicateBuilder;
use crate::predicates::Predicate;

use crate::trace_analyzer::TraceAnalyzer;
use rayon::prelude::*;

pub struct PredicateAnalyzer {}

impl PredicateAnalyzer {
    pub fn evaluate_best_predicate_at_address(
        address: usize,
        trace_analyzer: &TraceAnalyzer,
        arch: CpuArchitecture,
    ) -> Predicate {
        let pb = PredicateBuilder::new(arch);
        let predicates = pb.gen_predicates(address, trace_analyzer);

        if predicates.is_empty() {
            return Predicate::gen_empty(address);
        }

        let mut ret: Vec<Predicate> = predicates
            .into_par_iter()
            .map(|p| PredicateAnalyzer::evaluate_predicate2(trace_analyzer, p))
            .collect();

        ret.sort_by(|p1, p2| p1.score.partial_cmp(&p2.score).unwrap());
        ret.pop().unwrap()
    }

    fn evaluate_predicate2(trace_analyzer: &TraceAnalyzer, mut predicate: Predicate) -> Predicate {
        // False Negatives: Crashes that the predicate failed to predict
        let cf = trace_analyzer
            .crashes
            .as_slice()
            .par_iter()
            .map(|t| t.instructions.get(&predicate.address))
            .filter(|i| !predicate.execute(i))
            .count() as f64;

        // True Positives: Crashes correctly predicted by the predicate
        let ct = trace_analyzer
            .crashes
            .as_slice()
            .par_iter()
            .map(|t| t.instructions.get(&predicate.address))
            .filter(|i| predicate.execute(i))
            .count() as f64;

        // False Positives: Non-crashes that the predicate mistakenly predicted as crashes
        let nf = trace_analyzer
            .non_crashes
            .as_slice()
            .par_iter()
            .map(|t| t.instructions.get(&predicate.address))
            .filter(|i| predicate.execute(i))
            .count() as f64;

        // True Negatives: Non-crashes correctly identified by the predicate
        let nt = trace_analyzer
            .non_crashes
            .as_slice()
            .par_iter()
            .map(|t| t.instructions.get(&predicate.address))
            .filter(|i| !predicate.execute(i))
            .count() as f64;

        let theta = 0.5 * (cf / (cf + nf) + nf / (nf + nt));
        predicate.score = 2.0 * (theta - 0.5).abs();
        if predicate.score.is_nan() {
            println!("NaN ? {}", predicate.score);
            predicate.score = 0.0;
        }
        //println!("Score: {}", predicate.score);
        predicate
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
