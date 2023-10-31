use crate::config::CpuArchitecture;
use crate::predicate_builder::PredicateBuilder;
use crate::predicates::{Predicate, SimplePredicate};
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use crate::trace_analyzer::TraceAnalyzer;
use rayon::prelude::*;

pub struct PredicateAnalyzer {}

impl PredicateAnalyzer {
    /*
    // same meaning
    0x000000000020e12a -- r4 max_reg_val_greater_or_equal 0x0 -- 0.9979423868312758 -- mov r4, r2 (path rank: 0.8720885577887211) //0x0020e12a: _forward_rfrag at gnrc_sixlowpan_frag_sfr.c:1664
    0x000000000020e12a -- r4 min_reg_val_greater_or_equal 0x0 -- 0.9979423868312758 -- mov r4, r2 (path rank: 0.8729085029311009) //0x0020e12a: _forward_rfrag at gnrc_sixlowpan_frag_sfr.c:1664

    // reg_val less 0xfff is sufficient
    0x000000000020e12a -- r4 max_reg_val_less 0xffffffff -- 0.9979423868312758 -- mov r4, r2 (path rank: 0.8737284480734812) //0x0020e12a: _forward_rfrag at gnrc_sixlowpan_frag_sfr.c:1664
    0x000000000020e12a -- r4 max_reg_val_less 0xffff -- 0.9979423868312758 -- mov r4, r2 (path rank: 0.874548393215861) //0x0020e12a: _forward_rfrag at gnrc_sixlowpan_frag_sfr.c:1664
    0x000000000020e12a -- r4 min_reg_val_less 0xffffffff -- 0.9979423868312758 -- mov r4, r2 (path rank: 0.875368338358241) //0x0020e12a: _forward_rfrag at gnrc_sixlowpan_frag_sfr.c:1664
    0x000000000020e12a -- r4 min_reg_val_less 0xffff -- 0.9979423868312758 -- mov r4, r2 (path rank: 0.8761882835006211) //0x0020e12a: _forward_rfrag at gnrc_sixlowpan_frag_sfr.c:1664
    */
    // all preds are guaranteed to have the same score
    pub fn filter_preds_at_same_address(preds: Vec<Predicate>) -> Vec<Predicate> {
        let mut filtered: HashMap<String, &Predicate> = HashMap::new();

        /* first we filter the single predicates */
        for pred in preds.iter() {
            //println!("test: {} {}", pred.get_name(), pred.get_score());
            if let Predicate::Composite(_) = pred {
                continue;
            }
            if pred.get_name().contains("flag") {
                // parse which flag
                let sub = pred.get_name().split("_").collect::<Vec<&str>>()[1];
                filtered.entry(sub.to_string()).or_insert(pred);
            } else if pred.get_name().contains("less_or_equal") {
                let key = format!(
                    "{}less_or_equal{}",
                    pred.get_p1().unwrap(),
                    pred.get_p2().unwrap()
                );
                filtered.insert(key, pred);
            } else if pred.get_name().contains("greater_or_equal") {
                let key = format!(
                    "{}greater_or_equal{}",
                    pred.get_p1().unwrap(),
                    pred.get_p2().unwrap()
                );
                filtered.insert(key, pred);
            } else if pred.get_name().contains("reg_val_less") {
                // when we have 0xff 0xffffff and 0xffffffff all with the same score
                // we just want to keep 0xff
                match filtered.entry("reg_val_less".to_string()) {
                    Entry::Occupied(mut entry) => {
                        if pred.get_p2() < entry.get().get_p2() {
                            entry.insert(pred);
                        }
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(pred);
                    }
                }
            } else {
                filtered.insert(pred.get_name().clone(), pred);
            }
        }

        let mut res: Vec<Predicate> = filtered.values().map(|&x| x.clone()).collect();
        for pred in preds {
            if let Predicate::Composite(comp) = &pred {
                let found_pred = res.iter().find(|&x| *x == *comp.get_inner());
                if let Some(other) = found_pred {
                    if comp.score > other.get_score() {
                        res.push(pred.clone());
                    }
                } else {
                    res.push(pred.clone());
                }
            }
        }

        res
    }
    // Vec because there can be multiple best predicates for an address (same score)
    pub fn evaluate_best_predicates_at_address(
        address: usize,
        trace_analyzer: &TraceAnalyzer,
        arch: CpuArchitecture,
    ) -> Vec<Predicate> {
        let pb = PredicateBuilder::new(arch);
        let predicates = pb.gen_predicates(address, trace_analyzer);

        if predicates.is_empty() {
            return vec![SimplePredicate::gen_empty(address)];
        }

        let mut ret: Vec<Predicate> = predicates
            .into_par_iter()
            .map(|p| PredicateAnalyzer::evaluate_predicate(trace_analyzer, p))
            .collect();

        ret.sort_by(|p1, p2| p1.get_score().partial_cmp(&p2.get_score()).unwrap());
        let highest_score = ret.last().unwrap().get_score();

        /*
        We're using (item.score - highest_score).abs() < std::f64::EPSILON to compare floating point numbers for equality because directly comparing them might lead to inaccuracies due to floating point precision issues.
         */
        // consider multiple predicates per address if same score
        let best_preds = ret
            .into_iter()
            .filter(|p| (p.get_score() - highest_score).abs() < std::f64::EPSILON)
            .collect();

        PredicateAnalyzer::filter_preds_at_same_address(best_preds)
    }

    /*
    fn evaluate_predicate2(
        trace_analyzer: &TraceAnalyzer,
        mut predicates: Vec<SimplePredicate>,
    ) -> Vec<SimplePredicate> {
        let mut scores = Vec::new();

        for predicate in predicates.iter() {
            let true_and_crash = trace_analyzer
                .crashes
                .as_slice()
                .par_iter()
                .map(|t| t.instructions.get(&predicate.address))
                .filter(|i| predicate.execute(i))
                .count() as f64;

            let true_and_both = trace_analyzer
                .iter_all_traces()
                .map(|t| t.instructions.get(&predicate.address))
                .filter(|i| predicate.execute(i))
                .count() as f64;

            let necessity_score = {
                let score = true_and_crash / trace_analyzer.crashes.len() as f64;
                if score.is_nan() {
                    0.0
                } else {
                    score
                }
            };

            let sufficiency_score = {
                let score = true_and_crash / true_and_both;
                if score.is_nan() {
                    0.0
                } else {
                    score
                }
            };

            /*
            println!(
                "Necessity: {}, sufficiency: {}, true_and_both: {}, true_and_crash: {}",
                necessity_score, sufficiency_score, true_and_both, true_and_crash
            );
            */

            scores.push((necessity_score, sufficiency_score));
        }

        let min_n = scores
            .iter()
            .map(|x| x.0)
            .min_by(|a, b| a.partial_cmp(&b).unwrap())
            .unwrap();
        let max_n = scores
            .iter()
            .map(|x| x.0)
            .max_by(|a, b| a.partial_cmp(&b).unwrap())
            .unwrap();

        let min_s = scores
            .iter()
            .map(|x| x.1)
            .min_by(|a, b| a.partial_cmp(&b).unwrap())
            .unwrap();
        let max_s = scores
            .iter()
            .map(|x| x.1)
            .max_by(|a, b| a.partial_cmp(&b).unwrap())
            .unwrap();

        for (i, p) in predicates.iter_mut().enumerate() {
            let norm_necessity = (scores[i].0 - min_n) / (max_n - min_n);
            let norm_sufficiency = (scores[i].1 - min_s) / (max_s - min_s);

            let mut res = (norm_necessity.powf(2.0) + norm_sufficiency.powf(2.0)).sqrt();
            // normalize L2-norm to [0, 1]
            res /= 2.0_f64.sqrt();

            //p.score = if res.is_nan() { 0.0 } else { res };
            p.score = (scores[i].0 + scores[i].1) / 2.0;

            //p.score = res;
            //println!("Score: {}", p.score);
        }

        predicates
    }
    */

    fn evaluate_predicate(trace_analyzer: &TraceAnalyzer, mut predicate: Predicate) -> Predicate {
        let true_positives = trace_analyzer
            .crashes
            .as_slice()
            .par_iter()
            .map(|t| t.instructions.get(&predicate.get_address()))
            .filter(|i| predicate.execute(i))
            .count() as f64
            / trace_analyzer.crashes.len() as f64;

        let true_negatives = trace_analyzer
            .non_crashes
            .as_slice()
            .par_iter()
            .map(|t| t.instructions.get(&predicate.get_address()))
            .filter(|i| !predicate.execute(i))
            .count() as f64
            / trace_analyzer.non_crashes.len() as f64;

        let score = (true_positives + true_negatives) / 2.0;
        predicate.set_score(score);

        predicate
    }
}
