use crate::addr2line_lib::addr2line;
use crate::config::Config;
use crate::traces::{deserialize_mnemonics, deserialize_predicates};
use crate::utils::{glob_paths, read_file, write_file};
use anyhow::{anyhow, Context, Result};
use goblin::elf::Elf;
use itertools::{Itertools, MultiProduct};
use rayon::prelude::*;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::{self, read, File};
use std::hash::Hash;
use std::sync::Mutex;
use trace_analysis::predicates::SerializedPredicate;
use trace_analysis::register::user_regs_struct_arm;

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

// create a ranking which splits up predicates different ids but same addresses into individual rankings
// additionally filter ranking to have function granularity
fn deduplicate_ranking(
    ranking: &Vec<usize>,
    predicates: &HashMap<usize, SerializedPredicate>,
    functions: &Vec<usize>,
) -> Vec<Vec<usize>> {
    // filter ranking to only include best predicates per function, if multiple predicates
    // with same score, then all are included
    let mut func_map: HashMap<usize, &SerializedPredicate> = HashMap::new();
    for id in ranking.iter() {
        let pred = predicates.get(id).unwrap();

        // find closest function to address
        let func_addr = find_func_for_addr(functions, pred.address).unwrap();

        // update entry if predicate with better score found inside function
        let current_pred = func_map.entry(func_addr).or_insert_with(|| pred);
        if pred.score > current_pred.score {
            *current_pred = pred;
        }
    }

    // now find all other predicates with same score and address as best found predicate per function
    let ranking: Vec<usize> = ranking
        .iter()
        .filter(|&id| {
            let pred = &predicates[id];
            func_map
                .values()
                .find(|p| p.address == pred.address && p.score == pred.score)
                .is_some()
        })
        .map(|&id| id)
        .collect();

    // Create a HashMap to gather all ids per address.
    let mut address_map: HashMap<usize, Vec<usize>> = HashMap::new();
    for id in ranking.iter() {
        let address = predicates[id].address;
        address_map
            .entry(address)
            .or_insert_with(Vec::new)
            .push(*id);
    }

    // Get order of appearance of predicates by address
    let order = ranking.iter().fold(Vec::new(), |mut acc, id| {
        let address = predicates.get(id).unwrap().address;
        if !acc.contains(&address) {
            acc.push(address);
        }
        acc
    });

    // Create the product of all possible combinations of individual predicates
    // per address while keeping the order of their occurence
    let res: Vec<Vec<usize>> = order
        .iter()
        .map(|&addr| {
            address_map
                .get(&addr)
                .unwrap()
                .iter()
                .map(|&id| id)
                .collect::<Vec<_>>()
        })
        .multi_cartesian_product()
        .collect();

    res
}

// crash path has function granularity
fn find_most_likely_crash_path(config: &Config, functions: &Vec<usize>) -> Vec<usize> {
    let paths: HashMap<Vec<usize>, u64> =
        glob_paths(format!("{}/crashes/*-full*", config.eval_dir))
            .into_par_iter()
            .filter_map(|path| match get_taken_path(path, functions) {
                Ok(valid_path) => Some(valid_path),
                Err(e) => None,
            })
            .fold(
                || HashMap::new(),
                |mut acc, path| {
                    *acc.entry(path).or_insert(0) += 1;
                    acc
                },
            )
            .reduce(
                || HashMap::new(),
                |mut acc, other_map| {
                    for (path, count) in other_map {
                        *acc.entry(path).or_insert(0) += count;
                    }
                    acc
                },
            );

    let mut paths: Vec<_> = paths.into_iter().collect();

    // sort descending
    paths.sort_by(|a, b| b.1.cmp(&a.1));
    let top_score = paths[0].1;

    let paths: Vec<(Vec<usize>, u64)> = paths
        .into_iter()
        .filter(|(_, score)| *score == top_score)
        .collect();

    println!("Amount of pairs with same score: {} \n", paths.len());

    // todo: this will probably not hold for all datasets
    assert!(paths.len() == 1);

    paths[0].0.clone()

    //paths.into_iter().map(|(key, _value)| key).collect()
}

fn get_taken_path(input_path: String, functions: &Vec<usize>) -> Result<Vec<usize>> {
    let f = File::open(input_path).context("open monitor file")?;

    // all register values throughout the whole exeuction of the program
    let detailed_trace: Vec<Vec<u32>> =
        bincode::deserialize_from(f).context("bincode deserialize")?;

    let regs_arr: Result<Vec<_>, _> = detailed_trace
        .into_iter()
        .map(|trace| {
            user_regs_struct_arm::try_from(trace)
                .map_err(|_| anyhow!("unable to get user_regs_struct_arm"))
        })
        .collect();

    let mut regs_arr = regs_arr?;

    // reverse the trace since we are interested in functions executed right before crash
    regs_arr.reverse();

    let mut path = Vec::new();
    // this approach does not consider recursion, but ig it doesn't matter
    for regs in regs_arr.iter() {
        let func_addr = find_func_for_addr(functions, regs.pc as usize);

        if let Some(func_addr) = func_addr {
            // naive way to prevent loops from being on path
            // this just makes the path smaller and therefore calculation faster
            // the filtering step of predicates having to be on path, and only
            // considering unique predicates would also take care of removing
            // loops and stuff
            if !path.contains(&func_addr) {
                path.push(func_addr);
            }
        }
    }

    // reverse again to show first executed -> last executed
    path.reverse();

    Ok(path)
}

fn find_func_for_addr(functions: &Vec<usize>, addr: usize) -> Option<usize> {
    match functions.binary_search_by(|func_addr| func_addr.cmp(&addr)) {
        Ok(index) => Some(functions[index]), // The address is a function start
        Err(0) => None,                      // The address is before the first function
        Err(index) => Some(functions[index - 1]),
    }
}

fn calc_conditional_probs(
    rankings: &Vec<Vec<usize>>,
) -> (HashMap<usize, f64>, HashMap<(usize, usize), f64>) {
    // calculate individual probability for each predicate
    let mut prob = HashMap::new();
    for ranking in rankings.iter() {
        for pred in ranking.iter() {
            *prob.entry(*pred).or_insert(0.0) += 1.0;
        }
    }

    for p in prob.values_mut() {
        *p /= rankings.len() as f64;
    }

    let cond_prob: Mutex<HashMap<(usize, usize), f64>> = Mutex::new(HashMap::new());
    // calculate conditional probability matrix
    let keys: Vec<_> = prob.keys().collect();
    keys.par_iter().for_each(|&&a| {
        for &b in prob.keys() {
            let key = (a, b);
            let mut tmp = 0.0;
            if a == b {
                tmp = prob[&a];
                //cond_prob.insert(key, prob[&a]);
            } else {
                let joint_cnt = rankings
                    .iter()
                    .filter(|&ranking| ranking.contains(&a) && ranking.contains(&b))
                    .count() as f64;

                // todo: does deduplication create problems here ?
                let p_a_b = joint_cnt / rankings.len() as f64;

                if prob[&b] == 0.0 {
                    tmp = 0.0;
                } else {
                    tmp = p_a_b / prob[&b];
                }
            }
            // Ensure that the shared state is updated in a thread-safe manner.
            let mut cond_prob = cond_prob.lock().unwrap();
            cond_prob.insert(key, tmp);
        }
    });
    (prob, cond_prob.into_inner().unwrap())
}

pub fn create_compound_rankings(config: &Config) -> Result<()> {
    let binary_path = glob_paths(format!("{}/*_trace", config.eval_dir))
        .pop()
        .expect("Unable to find binary for compound ranking");

    let binary = fs::read(binary_path)?;
    let elf = Elf::parse(&binary).expect("Failed to parse elf");

    let mut functions: Vec<usize> = elf
        .syms
        .iter()
        .filter(|sym| sym.st_type() == goblin::elf::sym::STT_FUNC)
        // mask out the thumb bit.
        // readelf will say function is at e.g. address 0x200fdd but when executing,
        // it will actually be at 0x200fdc
        .map(|sym| (sym.st_value & !1) as usize)
        .collect();

    functions.sort();

    let predicates: HashMap<usize, SerializedPredicate> = deserialize_predicates(config)
        .into_iter()
        .map(|p| (p.id, p))
        .collect();

    let rankings = deserialize_rankings(config);

    let path = find_most_likely_crash_path(config, &functions);
    let compound_predicates: Mutex<HashMap<Vec<usize>, u64>> = Mutex::new(HashMap::new());

    let mut deduplicated_rankings = Vec::new();
    for full_ranking in rankings.iter() {
        for ranking in deduplicate_ranking(full_ranking, &predicates, &functions) {
            deduplicated_rankings.push(ranking);
        }
    }

    println!(
        "Calc conditional probs, ranking len: 0x{:x}, deduplicated ranking len: 0x{:x}",
        rankings.len(),
        deduplicated_rankings.len()
    );
    let (_, cond_probs) = calc_conditional_probs(&deduplicated_rankings);

    println!("Done calculating conditional probs. Creating ranking");
    deduplicated_rankings.par_iter().for_each(|ranking| {
        if ranking.len() < 2 {
            return;
            //continue;
        }

        let mut preds_on_path: Vec<usize> = ranking
            .iter()
            .filter(|&id| {
                let addr = predicates.get(id).unwrap().address;
                if let Some(func) = find_func_for_addr(&functions, addr) {
                    path.contains(&func)
                } else {
                    false
                }
            })
            .map(|&x| x)
            .collect();

        // identify outliers by iteratively removing the element with the
        // smallest average conditional probability until all elements have the
        // same average conditional prob (1 or close to 1) meaning all elements
        // have a perfect co-occurence
        loop {
            // calculate average conditional probability of each predicate on path
            // to all other predicates on path
            let avg_cond_prob_per_predicate: HashMap<usize, f64> = preds_on_path
                .iter()
                .map(|&p| {
                    (
                        p,
                        preds_on_path
                            .iter()
                            .map(|&p2| cond_probs.get(&(p, p2)).unwrap())
                            .sum::<f64>()
                            / preds_on_path.len() as f64,
                    )
                })
                .collect();

            // calculate average conditional prob of all predicates to each other
            let avg_cond_prob: f64 = avg_cond_prob_per_predicate.values().sum::<f64>()
                / avg_cond_prob_per_predicate.len() as f64;

            // find the predicate with the lowest average conditional prob to other
            // predicates on path
            let (min_key, min_value) = avg_cond_prob_per_predicate
                .iter()
                .min_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                .map(|(k, v)| (*k, *v))
                .unwrap();

            // if avg conditional prob of predicate is lower than average, remove
            // e.g. we consider 99.9999 = 99.9998
            if (avg_cond_prob - min_value).abs() > 0.0001 {
                preds_on_path.retain(|&x| x != min_key);
            } else {
                break;
            }
        }

        // score rankings based on how many of the predicates are on the most likely
        // crash path
        // todo: think about the method of scoring based on how many predicates
        // are on path, does this introduce bias ? should you just increase by 1 ?
        let mut compound_predicates = compound_predicates.lock().unwrap();
        *compound_predicates
            .entry(preds_on_path.iter().map(|&val| val).collect())
            .or_insert(0) += preds_on_path.len() as u64;
        //.or_insert(0) += 1 as u64;
    });

    // sorts high -> low
    // first count occurence score, then sum of predicate scores
    let compare_compound = |a: &(&Vec<usize>, &u64), b: &(&Vec<usize>, &u64)| {
        b.1.partial_cmp(a.1).unwrap().then_with(|| {
            let avg_a =
                a.0.iter()
                    .map(|id| predicates.get(id).unwrap().score)
                    .sum::<f64>()
                    / a.0.len() as f64;

            let avg_b =
                b.0.iter()
                    .map(|id| predicates.get(id).unwrap().score)
                    .sum::<f64>()
                    / b.0.len() as f64;
            avg_b.partial_cmp(&avg_a).unwrap()
        })
    };

    let compound_predicates = compound_predicates.into_inner().unwrap();
    let mut sorted_entries: Vec<_> = compound_predicates.iter().collect();
    assert!(sorted_entries.len() > 0);
    sorted_entries.sort_by(|a, b| compare_compound(a, b));

    let top_score = sorted_entries[0].1;
    let amt_with_top_score = sorted_entries.iter().filter(|x| x.1 == top_score).count();

    // todo: remove. only here for debugging
    let top_ten: Vec<(u64, f64, Vec<usize>)> = sorted_entries
        .iter()
        .take(10)
        .map(|(compound, &score)| (compound.clone(), score))
        .map(|(compound, score)| {
            // avg score of all predicates in compound
            let avg = compound
                .iter()
                .map(|id| predicates.get(id).unwrap().score)
                .sum::<f64>();

            // addresses of predicates in compound
            let mut ranking_addresses = compound
                .iter()
                .map(|id| predicates.get(&id).unwrap().address)
                .collect::<Vec<usize>>();

            ranking_addresses.sort();

            (score, avg / compound.len() as f64, ranking_addresses)
        })
        .collect();

    println!(
        "Compound predicates len: {}, top score amount: {}, top values: {:?}",
        compound_predicates.len(),
        amt_with_top_score,
        top_ten,
    );

    let ret = sorted_entries
        .into_iter()
        .filter(|x| x.1 == top_score)
        .map(|x| x.0.clone())
        .collect();

    //let ret = vec![sorted_entries[0].0.clone()];

    dumb_compound_rankings(config, ret, path[path.len() - 1], predicates);

    Ok(())
}

pub fn serialize_rankings(config: &Config, rankings: &Vec<Vec<usize>>) {
    let content = serde_json::to_string(rankings).expect("Could not serialize rankings");
    write_file(&format!("{}/rankings.json", config.eval_dir), content);
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

pub fn deserialize_compound_rankings(config: &Config) -> Vec<Vec<usize>> {
    let content = read_file(&format!("{}/compound_rankings.json", config.eval_dir));
    serde_json::from_str(&content).expect("Could not deserialize compound ranking")
}

fn dumb_compound_rankings(
    config: &Config,
    rankings: Vec<Vec<usize>>,
    crash_addr: usize,
    predicates: HashMap<usize, SerializedPredicate>,
) {
    let mnemonics = deserialize_mnemonics(config);
    let mut content = Vec::new();
    for ranking in rankings.iter() {
        for (idx, pred_id) in ranking.iter().enumerate() {
            let pred = &predicates[pred_id];
            //let func_addr = find_func_for_addr(&functions, pred.address).unwrap();
            let mnemonic = &mnemonics[&pred.address];
            let output = addr2line(config, pred.address);
            let line = output.splitn(2, ' ').nth(1).unwrap_or("");

            content.push(format!(
                "#{} -- {} -- {} -- {}\n",
                idx,
                pred.to_string(),
                mnemonic,
                line
            ));

            /*
            println!(
                "#{} -- {} -- {} -- {}",
                idx,
                pred.to_string(),
                mnemonic,
                line
            );
            */
        }

        let output = addr2line(config, crash_addr);
        let line = output.splitn(2, ' ').nth(1).unwrap_or("");
        content.push(format!(
            "#{} CRASH LOCATION: {:#018x} -- {}\n",
            ranking.len(),
            crash_addr,
            line
        ));

        /*
        println!(
            "#{} CRASH LOCATION: {:#018x} -- {}",
            ranking.len(),
            crash_addr,
            line
        );
        */
        content.push(format!("{}\n", "-".repeat(0x20)));
        // println!("{}", "-".repeat(0x20));
        //break;
    }

    write_file(
        &format!("{}/ranked_compound_predicates.txt", config.eval_dir),
        content.into_iter().collect(),
    );
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

// powerset
fn gen_subsets(ranking: &Vec<usize>) -> Vec<Vec<usize>> {
    let n = ranking.len();
    let subset_amt = 2_usize.pow(n as u32);

    let mut result = Vec::new();

    /*
        2^n possible subsetsets. Each subset can be thought of as a binary string of length n.
        Build subsets simply by looping from 0..2^n and including element if bit is set.
    */
    for i in 0..subset_amt {
        let mut subset = Vec::new();
        for j in 0..n {
            if (i & (1 << j)) != 0 {
                subset.push(ranking[j]);
            }
        }

        if subset.len() > 1 {
            result.push(subset);
        }
    }

    result
}
