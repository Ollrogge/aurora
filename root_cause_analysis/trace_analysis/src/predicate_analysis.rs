use crate::config::Config;
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
                if comp.score > comp.get_best_score() {
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
        config: &Config,
    ) -> Vec<Predicate> {
        let pb = PredicateBuilder::new(config);
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

        // 24820 = 0x20fc70
        // 24817 = 0x20c9b8
        // 24821 = 0x20d6f
        // 24818 = 0x20a6bc
        if predicate.get_address() == 0x20a6bc {
            let mut avg = 0x0;
            for t in trace_analyzer.non_crashes.iter() {
                //let test = t.instructions.get(&0x20fc78);
                let inst = t.instructions.get(&predicate.get_address());
                if let Some(inst) = inst {
                    // xpsr = 16
                    if let Some(reg) = inst.registers_min.get(16) {
                        let val = (reg.value() >> 30) & 0x1;
                        //let val = reg.value();
                        avg += val;
                        //println!("reg: {:x} {:x}", val, t.last_address,);
                    }
                    //let val = 0;
                }
            }
            avg /= trace_analyzer.non_crashes.len() as u64;
            println!(
                "Tp: {}, Tn: {}, Score: {}, name: {}, avg: {:x}",
                true_positives,
                true_negatives,
                predicate.get_score(),
                predicate.get_name(),
                avg
            );
        }

        predicate
    }
}
