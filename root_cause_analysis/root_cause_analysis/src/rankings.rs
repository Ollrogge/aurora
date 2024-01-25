use crate::addr2line_lib::addr2line;
use crate::config::Config;
use crate::traces::{deserialize_mnemonics, deserialize_predicates};
use crate::utils::{glob_paths, read_file, write_file};
use anyhow::{anyhow, Context, Result};
use itertools::{Itertools, MultiProduct};
use rayon::prelude::*;
use regex::Regex;
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fs::{self, read, File};
use std::sync::Mutex;
use trace_analysis::addr2line_lib::addr2func;
use trace_analysis::predicates::SerializedPredicate;
use trace_analysis::register::{user_regs_struct_arm, RegisterArm};

pub fn trunc_score(score: f64) -> f64 {
    (score * 100.0).trunc() as f64
}

fn predicate_order(
    p1: &SerializedPredicate,
    p2: &SerializedPredicate,
    rankings: &Vec<Vec<usize>>,
) -> Ordering {
    p2.score.partial_cmp(&p1.score).unwrap().then(
        path_rank(p1.address, rankings)
            .partial_cmp(&path_rank(p2.address, rankings))
            .unwrap(),
    )
}

fn predicate_order_id(
    p1: &SerializedPredicate,
    p2: &SerializedPredicate,
    rankings: &Vec<Vec<usize>>,
) -> Ordering {
    p2.score.partial_cmp(&p1.score).unwrap().then(
        path_rank(p1.id, rankings)
            .partial_cmp(&path_rank(p2.id, rankings))
            .unwrap(),
    )
}

pub fn rank_predicates(config: &Config) {
    let rankings = deserialize_rankings(config);
    let mnemonics = deserialize_mnemonics(config);
    let mut predicates = deserialize_predicates(config);

    predicates.par_sort_by(|p1, p2| predicate_order_id(p1, p2, &rankings));

    dump_ranked_predicates(config, &predicates, &mnemonics, &rankings);
}

fn path_rank(val: usize, rankings: &Vec<Vec<usize>>) -> f64 {
    rankings
        .par_iter()
        .map(|r| rank_path_level(val, r))
        .sum::<f64>()
        / rankings.len() as f64
}

fn rank_path_level(val: usize, rank: &Vec<usize>) -> f64 {
    match rank.iter().position(|id| val == *id) {
        Some(pos) => pos as f64 / rank.len() as f64,
        None => 2.0,
    }
}

type Function = String;

struct CompoundPredicate {
    pub data: Vec<(Function, Vec<SerializedPredicate>)>,
    pub crash_loc: usize,
}

impl CompoundPredicate {
    pub fn new() -> CompoundPredicate {
        CompoundPredicate {
            data: Vec::new(),
            crash_loc: 0,
        }
    }

    pub fn add_entry(&mut self, function: Function, predicates: Vec<SerializedPredicate>) {
        self.data.push((function, predicates));
    }

    pub fn set_crash_loc(&mut self, crash_loc: usize) {
        self.crash_loc = crash_loc;
    }

    pub fn filter_data(&mut self, config: &Config) {
        let best_score = self
            .data
            .iter()
            .flat_map(|v| &v.1)
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
            .unwrap()
            .score;

        for (_, preds) in self.data.iter_mut() {
            //preds.retain(|pred| pred.score >= best_score * 0.92);

            // heuristic: .h files only contain very small utility funcs. Less likely to contain bug
            /*
            preds.retain(|pred| {
                let mnemonic = addr2line(config, pred.address);
                !mnemonic.contains(".h:")
            })
            */
        }

        self.data.retain(|(_, pred)| pred.len() >= 1);
    }

    // create the original output presentation but filter to only contain functions
    // that are on our determined crash path
    pub fn dumb_data_original(&self, config: &Config, path_ranks: &HashMap<usize, f64>) {
        let mut content = Vec::new();
        let mnemonics = deserialize_mnemonics(config);

        let mut preds: Vec<&SerializedPredicate> = self.data.iter().flat_map(|x| &x.1).collect();

        preds.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap()
                .then(path_ranks[&a.id].partial_cmp(&path_ranks[&b.id]).unwrap())
        });

        for pred in preds.iter() {
            let pred_info = pred.to_string();
            let line_info = &pred.addr2line_info;
            let mnemonic = &mnemonics[&pred.address];
            let path_rank = path_ranks[&pred.id];

            content.push(format!(
                "{} -- {} (path rank: {}) //{}\n",
                pred_info, mnemonic, path_rank, line_info
            ));
        }

        let fp = format!("{}/ranked_predicates_verbose_filtered.txt", config.eval_dir);
        write_file(&fp, content.into_iter().collect());
    }

    pub fn dumb_data(&self, config: &Config, ranking_number: usize) {
        let mut content = Vec::new();
        let mnemonics = deserialize_mnemonics(config);
        let re = Regex::new(r": (.+?) at (.+?):(.+)").unwrap();
        let mut num = 0x0;
        for (func, preds) in self.data.iter() {
            //let info = addr2line(config, preds[0].address);
            let info = &preds[0].addr2line_info;
            //println!("Info: {}", info);

            let caps = match re.captures(&info) {
                Some(caps) => caps,
                None => {
                    println!("dumb data: info capture failed for: {}", info);
                    continue;
                }
            };

            let function_name = caps.get(1).unwrap().as_str();
            let file_name = caps.get(2).unwrap().as_str();

            content.push(format!("\n#{}. {} in  {}\n", num, function_name, file_name));
            content.push(format!("{}\n", "-".repeat(0x20)));

            num += 1;

            for (i, pred) in preds.iter().take(3).enumerate() {
                let info = &pred.addr2line_info;
                let caps = re.captures(&info).unwrap();

                let file = caps.get(2).unwrap().as_str();
                let offset = caps.get(3).unwrap().as_str();
                content.push(format!(
                    "#{}. {} -- {} -- {}:{}\n",
                    i,
                    pred.to_string(),
                    mnemonics[&pred.address],
                    file,
                    offset
                ));
            }
        }

        let info = addr2line(config, self.crash_loc);

        let caps = re.captures(&info).unwrap();

        let function_name = caps.get(1).unwrap().as_str();
        let file_name = caps.get(2).unwrap().as_str();

        content.push(format!(
            "\n#{}. 0x{:x} in {} in {} (most often occurring crash loc) \n",
            num, self.crash_loc, function_name, file_name
        ));

        let fp = format!(
            "{}/ranked_compound_predicates{}.txt",
            config.eval_dir, ranking_number
        );
        write_file(&fp, content.into_iter().collect());
    }
}

fn get_most_often_occuring_crash_loc(config: &Config) -> Result<usize> {
    let crash_locs: Mutex<HashMap<u32, u32>> = Mutex::new(HashMap::new());
    let paths = glob_paths(format!("{}/crashes/*-full*", config.trace_dir));

    paths.par_iter().for_each(|path| {
        let f = File::open(path).context("open monitor file").unwrap();

        // all register values throughout the whole exeuction of the program
        let detailed_trace: Vec<Vec<u32>> = bincode::deserialize_from(f)
            .context("bincode deserialize")
            .unwrap();

        let last_reg_state =
            user_regs_struct_arm::try_from(detailed_trace[detailed_trace.len() - 1].clone())
                .map_err(|_| anyhow!("unable to get user_regs_struct_arm"))
                .unwrap();

        *crash_locs
            .lock()
            .unwrap()
            .entry(last_reg_state.pc)
            .or_insert(0) += 1;
    });

    let crash_locs = crash_locs.into_inner()?;

    let crash_loc = crash_locs.iter().max_by(|a, b| a.1.cmp(b.1)).unwrap();

    Ok(*crash_loc.0 as usize)
}

pub fn create_compound_rankings(config: &Config) -> Result<()> {
    let rankings = deserialize_rankings(config);
    let mut preds = deserialize_predicates(config);
    let evaluation_info = deserialize_evaluation_info(config);

    // Filter predicates to only contain predicates with a true positive score of
    // 1 if they have been evaluated. We consider if a predicate is evaluated because
    // there can be multiple paths to a crash, which would cause all predicates on
    // the diverging paths to not have a true positive score of 1
    preds.retain(|p| {
        evaluation_info.iter().all(|info| match info.get(&p.id) {
            Some(val) => *val,
            // predicate was not evaluated for the given trace
            _ => true,
        })
    });
    //preds.retain(|p| rankings.iter().all(|r| r.contains(&p.id)));

    let predicates: HashMap<usize, SerializedPredicate> =
        preds.into_iter().map(|p| (p.id, p)).collect();

    let path_ranks: HashMap<usize, f64> = predicates
        .keys()
        .map(|&id| (id, path_rank(id, &rankings)))
        .collect();

    let mut paths: HashMap<Vec<Function>, u64> = HashMap::new();
    //let (_, cond_probs) = calc_conditional_probs(&rankings);

    for ranking in rankings {
        let mut funcs = ranking.iter().rev().fold(Vec::new(), |mut acc, pred_id| {
            if predicates.contains_key(pred_id) {
                let function = &predicates[pred_id].get_func_name();

                /*
                if let Some(last) = acc.last() {
                    if function != last {
                        acc.push(function.clone());
                    }
                } else {
                    acc.push(function.clone());
                }
                */
                if !acc.contains(function) {
                    acc.push(function.clone());
                }
            }
            acc
        });

        //remove_longest_repeating_subvec(&mut funcs);

        funcs.reverse();

        *paths.entry(funcs).or_insert(0) += 1;
    }

    let paths: Vec<(Vec<Function>, u64)> =
        paths.into_iter().sorted_by(|a, b| b.1.cmp(&a.1)).collect();

    //paths.iter_mut().for_each(|(path, _)| path.reverse());

    //let best_score = paths[0].1;
    let scores: Vec<u64> = paths.iter().map(|path| path.1).collect();
    let best_score = scores[0];

    let paths: Vec<&Vec<Function>> = paths
        .iter()
        .filter(|(_, score)| *score == best_score)
        .map(|(path, _)| path)
        .collect();

    println!(
        "Amount of best paths found: {}, best score: {}, crashes amount: {}, all scores: {:?}",
        paths.len(),
        best_score,
        scores.iter().map(|&x| x).sum::<u64>(),
        scores
    );

    for (i, &best_path) in paths.iter().enumerate() {
        let best_path = best_path.clone();

        let mut compound_predicate = CompoundPredicate::new();

        for func in best_path.iter() {
            let mut preds: Vec<&SerializedPredicate> = predicates
                .values()
                .filter(|pred| pred.get_func_name() == *func)
                .collect();

            preds.sort_by(|a, b| {
                // sort score descending, path_rank ascending
                b.score
                    .partial_cmp(&a.score)
                    .unwrap()
                    .then(path_ranks[&a.id].partial_cmp(&path_ranks[&b.id]).unwrap())
            });

            compound_predicate.add_entry(
                func.clone(),
                preds.iter().map(|&pred| pred.clone()).collect(),
            );
        }

        let most_often_crash_loc =
            get_most_often_occuring_crash_loc(config).context("Unable to obtain crash loc")?;

        compound_predicate.set_crash_loc(most_often_crash_loc);

        compound_predicate.filter_data(config);
        compound_predicate.dumb_data(config, i);
        compound_predicate.dumb_data_original(config, &path_ranks);
    }

    Ok(())
}

pub fn serialize_rankings(config: &Config, rankings: &Vec<Vec<usize>>) {
    let content = serde_json::to_string(rankings).expect("Could not serialize rankings");
    write_file(&format!("{}/rankings.json", config.eval_dir), content);
}

pub fn serialize_evaluation_info(config: &Config, rankings: &Vec<HashMap<usize, bool>>) {
    let content = serde_json::to_string(rankings).expect("Could not serialize rankings");
    write_file(
        &format!("{}/evaluation_info.json", config.eval_dir),
        content,
    );
}

pub fn serialize_compound_rankings(config: &Config, rankings: &Vec<Vec<usize>>) {
    let content = serde_json::to_string(rankings).expect("Could not serialize compound ranking");
    write_file(
        &format!("{}/compound_rankings.json", config.eval_dir),
        content,
    );
}

pub fn serialize_rankings_ids(config: &Config, rankings: &Vec<Vec<(usize, usize)>>) {
    let content = serde_json::to_string(rankings).expect("Could not serialize rankings");
    write_file(&format!("{}/rankings.json", config.eval_dir), content);
}

fn deserialize_rankings(config: &Config) -> Vec<Vec<usize>> {
    let content = read_file(&format!("{}/rankings.json", config.eval_dir));
    serde_json::from_str(&content).expect("Could not deserialize rankings")
}

fn deserialize_evaluation_info(config: &Config) -> Vec<HashMap<usize, bool>> {
    let content = read_file(&format!("{}/evaluation_info.json", config.eval_dir));
    serde_json::from_str(&content).expect("Could not deserialize rankings")
}

pub fn deserialize_compound_rankings(config: &Config) -> Vec<Vec<usize>> {
    let content = read_file(&format!("{}/compound_rankings.json", config.eval_dir));
    serde_json::from_str(&content).expect("Could not deserialize compound ranking")
}

fn dump_ranked_predicates(
    config: &Config,
    predicates: &Vec<SerializedPredicate>,
    mnemonics: &HashMap<usize, String>,
    rankings: &Vec<Vec<usize>>,
) {
    let content: String = predicates
        .iter()
        .map(|p| {
            format!(
                "{} -- {} (path rank: {})\n",
                p.to_string(),
                mnemonics[&p.address],
                path_rank(p.id, rankings)
            )
        })
        .collect();
    write_file(
        &format!("{}/ranked_predicates.txt", config.eval_dir),
        content,
    );
}
