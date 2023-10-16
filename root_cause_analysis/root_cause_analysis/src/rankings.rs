use crate::addr2line_lib::addr2line;
use crate::config::Config;
use crate::traces::{deserialize_mnemonics, deserialize_predicates};
use crate::utils::{glob_paths, read_file, write_file};
use anyhow::{anyhow, Context, Result};
use gimli::{DebuggingInformationEntry, EndianSlice, EntriesTree, LittleEndian, UnitOffset};
use goblin::elf::Elf;
use itertools::{Itertools, MultiProduct};
use object::{Object, ObjectSection};
use rayon::prelude::*;
use std::borrow;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::{self, read, File};
use std::hash::Hash;
use std::sync::Mutex;
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

// create a ranking which splits up predicates with different ids but same addresses
// into individual rankings. additionally filter ranking to have function granularity
fn deduplicate_ranking(
    ranking: &Vec<usize>,
    predicates: &HashMap<usize, SerializedPredicate>,
    functions: &Vec<usize>,
    path_ranks: &HashMap<usize, f64>,
) -> Vec<Vec<usize>> {
    // filter ranking to only include best predicates per function, if multiple predicates
    // with same score, then all are included
    let mut func_map: HashMap<usize, &SerializedPredicate> = HashMap::new();
    // order of predicates executed by address
    for id in ranking.iter() {
        let pred = predicates.get(id).unwrap();
        // find closest function to address
        let func_addr = find_func_for_addr(functions, pred.address).unwrap();

        // update entry if predicate with better score found inside function
        let current_pred = func_map.entry(func_addr).or_insert_with(|| pred);
        if pred.score > current_pred.score && path_ranks[&pred.id] > path_ranks[&current_pred.id] {
            *current_pred = pred;
        }
    }

    // now find all other predicates in function with same score and path rank
    // as best found predicate per function
    let ranking: Vec<usize> = ranking
        .iter()
        .filter(|&id| {
            let pred = &predicates[id];
            let func_addr = find_func_for_addr(functions, pred.address).unwrap();
            let path_rank = path_ranks[&pred.id];
            func_map.iter().any(|(&top_func_addr, top_pred)| {
                top_func_addr == func_addr
                    && pred.score == top_pred.score
                    && path_rank == path_ranks[&top_pred.id]
            })
        })
        .map(|&id| id)
        .collect();

    // Get order of appearance of predicates by address
    let pred_order = ranking.iter().fold(Vec::new(), |mut acc, id| {
        let address = predicates.get(id).unwrap().address;
        if !acc.contains(&address) {
            acc.push(address);
        }
        acc
    });

    // Create a HashMap to gather ids of top predicates per address
    let mut address_map: HashMap<usize, Vec<usize>> = HashMap::new();
    for id in ranking.iter() {
        let address = predicates[id].address;
        address_map
            .entry(address)
            .or_insert_with(Vec::new)
            .push(*id);
    }

    // Create the product of all possible combinations of individual predicates
    // per address while keeping the order of their occurence
    let res: Vec<Vec<usize>> = pred_order
        .iter()
        .map(|&addr| address_map[&addr].iter().map(|&id| id).collect::<Vec<_>>())
        .multi_cartesian_product()
        .collect();

    res
}

fn get_crash_loc(config: &Config) -> Result<usize> {
    let all_paths = glob_paths(format!("{}/crashes/*-full*", config.eval_dir));
    let path = all_paths.first().unwrap();

    let f = File::open(path).context("open monitor file")?;

    // all register values throughout the whole exeuction of the program
    let detailed_trace: Vec<Vec<u32>> =
        bincode::deserialize_from(f).context("bincode deserialize")?;

    let last_reg_state =
        user_regs_struct_arm::try_from(detailed_trace[detailed_trace.len() - 1].clone())
            .map_err(|_| anyhow!("unable to get user_regs_struct_arm"))?;

    Ok(last_reg_state.pc as usize)
}

// crash path has function granularity
fn find_most_likely_crash_paths(config: &Config, functions: &Vec<usize>) -> Vec<Vec<usize>> {
    let paths: HashMap<Vec<usize>, u64> =
        glob_paths(format!("{}/crashes/*-full*", config.eval_dir))
            .into_par_iter()
            .filter_map(|path| match get_taken_path(path, functions) {
                Ok(valid_path) => Some(valid_path),
                Err(_) => None,
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

    println!(
        "top score: {}, Amount of pairs with same score: {} \n",
        top_score,
        paths.len()
    );
    // todo: this will probably not hold for all datasets
    // assert!(paths.len() == 1);

    paths.into_iter().map(|(path, _)| path).collect()
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
        // to make the path more deterministic we ignore any functions when in
        // handler mode (exception is being handled)
        if regs.xpsr & 0xff != 0 {
            continue;
        }

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
            let tmp;
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

    /* parse DWARF debug information to find inlined functions and add them to vec */
    let object = object::File::parse(&*binary)?;
    let endian = gimli::RunTimeEndian::Little; // Assuming little endian; adjust as needed

    let load_section = |id: gimli::SectionId| -> Result<borrow::Cow<[u8]>, gimli::Error> {
        match object.section_by_name(id.name()) {
            Some(ref section) => Ok(section
                .uncompressed_data()
                .unwrap_or(borrow::Cow::Borrowed(&[][..]))),
            None => Ok(borrow::Cow::Borrowed(&[][..])),
        }
    };

    // Load all of the sections.
    let dwarf_cow = gimli::Dwarf::load(&load_section)?;

    // Borrow a `Cow<[u8]>` to create an `EndianSlice`.
    let borrow_section: &dyn for<'a> Fn(
        &'a borrow::Cow<[u8]>,
    ) -> gimli::EndianSlice<'a, gimli::RunTimeEndian> =
        &|section| gimli::EndianSlice::new(&*section, endian);

    let dwarf = dwarf_cow.borrow(&borrow_section);

    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs()? {
            if entry.tag() == gimli::DW_TAG_subprogram
                || entry.tag() == gimli::DW_TAG_inlined_subroutine
            {
                if let Some(low_pc) = entry.attr_value(gimli::DW_AT_low_pc)? {
                    match low_pc {
                        gimli::AttributeValue::Addr(addr) => {
                            functions.push(addr as usize);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    functions.sort();

    let predicates: HashMap<usize, SerializedPredicate> = deserialize_predicates(config)
        .into_iter()
        .map(|p| (p.id, p))
        .collect();

    let rankings = deserialize_rankings(config);

    let paths = find_most_likely_crash_paths(config, &functions);
    let compound_predicates: Mutex<HashMap<Vec<usize>, u64>> = Mutex::new(HashMap::new());

    /*
    for x in paths[0].iter() {
        println!("{:x}", x);
    }
    */

    let path_ranks: HashMap<usize, f64> = predicates
        .keys()
        .map(|&id| (id, path_rank(id, &rankings)))
        .collect();

    let mut deduplicated_rankings = Vec::new();
    for full_ranking in rankings.iter() {
        for ranking in deduplicate_ranking(full_ranking, &predicates, &functions, &path_ranks) {
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
    for path in paths.iter() {
        deduplicated_rankings.par_iter().for_each(|ranking| {
            if ranking.len() < 2 {
                return;
                //continue;
            }

            let mut preds_on_path: Vec<usize> = ranking
                .iter()
                .filter(|&id| {
                    let addr = predicates[id].address;
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

                // find the predicate with the lowest average conditional prob compared to
                // other predicates on path
                let (min_key, min_value) = avg_cond_prob_per_predicate
                    .iter()
                    .min_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                    .map(|(k, v)| (*k, *v))
                    .unwrap();

                // if avg conditional prob of predicate is lower than average, remove
                // e.g. we consider 99.9999 == 99.9998
                if (avg_cond_prob - min_value).abs() > 0.0001 {
                    preds_on_path.retain(|&x| x != min_key);
                } else {
                    assert!((avg_cond_prob - 1.0).abs() < 0.0001);
                    //println!("Avg conditional prob: {}", avg_cond_prob);
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
    }

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

    println!(
        "Compound predicates len: {}, top score amount: {}",
        compound_predicates.len(),
        amt_with_top_score,
    );

    for (k, v) in compound_predicates.iter() {
        println!("Score: {}", v);
        for id in k.iter() {
            print!("{:x} ", predicates[id].address);
        }

        println!("")
    }

    let mut compound_predicates: Vec<Vec<usize>> = sorted_entries
        .into_iter()
        .filter(|x| x.1 == top_score)
        .map(|x| x.0.clone())
        .collect();

    // filter compound_predicates to only include predicates within 5% of the top score
    for ranking in &mut compound_predicates {
        let best_score = ranking
            .iter()
            .map(|pred_id| predicates[pred_id].score)
            .max_by(|a, b| a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap();

        let to_retain: Vec<usize> = ranking
            .iter()
            .filter(|&id| predicates[id].score >= best_score * 0.95)
            .cloned()
            .collect();

        ranking.retain(|id| to_retain.contains(&id));
    }

    //let ret = vec![sorted_entries[0].0.clone()];

    // crash location should be the same no matter how many paths we have found
    let crashing_loc = get_crash_loc(config)?;

    dumb_compound_rankings(config, compound_predicates, crashing_loc, predicates);

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
    for (rank_idx, ranking) in rankings.iter().enumerate() {
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
        /*
        content.push(format!(
            "#{} CRASH FUNCTION: {:#018x} -- {}\n",
            ranking.len(),
            crash_addr,
            line
        ));
        */

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
