use crate::config::Config;
use crate::rankings::serialize_rankings;
use crate::utils::{glob_paths, read_file};
use anyhow::{anyhow, Context, Result};
use capstone::arch::arm::{self, ArmInsn, ArmOperandType};
use capstone::prelude::*;
use goblin::elf::Elf;
use itertools::{Itertools, MultiProduct};
use predicate_monitoring::{rank_predicates, rank_predicates_arm};
use rayon::prelude::*;
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::convert::TryFrom;
use std::fs::File;
use std::fs::{self, read, read_to_string, remove_file};
use std::process::{Child, Command, Stdio};
use std::time::Instant;
use trace_analysis::control_flow_graph::{BasicBlock, ControlFlowGraph};
use trace_analysis::predicates::SerializedPredicate;
use trace_analysis::register::user_regs_struct_arm;
use trace_analysis::trace_analyzer::{blacklist_path, read_crash_blacklist};

pub fn monitor_predicates(config: &Config) -> Result<()> {
    let blacklist_paths =
        read_crash_blacklist(config.blacklist_crashes(), &config.crash_blacklist_path);

    #[cfg(not(feature = "arm"))]
    {
        let cmd_line = cmd_line(&config);

        let rankings = glob_paths(format!("{}/inputs/crashes/*", config.eval_dir))
            .into_par_iter()
            .enumerate()
            .filter(|(_, p)| !blacklist_path(&p, &blacklist_paths))
            .map(|(index, i)| monitor(config, index, &replace_input(&cmd_line, &i)))
            .filter(|r| !r.is_empty())
            .collect();
        serialize_rankings(config, &rankings);
    }
    #[cfg(feature = "arm")]
    {
        // todo: different way than depending on the fact that the binary is in the parent dir
        let pattern = format!("{}/*_trace", config.eval_dir);
        let binary_path = glob_paths(pattern)
            .pop()
            .expect("No binary found for monitoring");

        let binary = fs::read(binary_path)?;

        let rankings = if config.compound_predicates {
            log::info!("Analyzing compound predicates");
            //let predicate_file = &format!("{}/{}", config.eval_dir, "all_predicates.json");
            let predicate_file = &format!("{}/{}", config.eval_dir, predicate_file_name());
            let rankings = monitor_predicates_arm(config, &binary, predicate_file)?;

            let elf = Elf::parse(&binary).expect("Failed to parse elf");

            let mut funcs: Vec<usize> = elf
                .syms
                .into_iter()
                .filter(|sym| sym.st_type() == goblin::elf::sym::STT_FUNC)
                .map(|sym| sym.st_value as usize)
                .collect();

            funcs.sort();

            create_compound_rankings(config, &rankings, &funcs, &predicate_file);

            rankings
        } else {
            let predicate_file = &format!("{}/{}", config.eval_dir, predicate_file_name());
            monitor_predicates_arm(config, &binary, &predicate_file)?
        };

        serialize_rankings(config, &rankings);
    }

    Ok(())
}

// n! / k!(n-k)! = n * (n-1)* ...*(n-k+1) / k!
fn combinations(n: usize, k: usize) -> usize {
    let mut result = 1;
    for i in 0..k {
        result *= n - i;
        result /= i + 1;
    }
    result
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

// create a ranking which splits up predicates with same addresses into individual rankings
fn deduplicate_ranking<'a>(
    ranking: &'a Vec<usize>,
    predicates: &'a HashMap<usize, SerializedPredicate>,
    functions: &Vec<usize>,
) -> Vec<Vec<&'a usize>> {
    // filter ranking to only include best predicates per function, if multiple predicates
    // with same score, then all are included
    let mut func_map: HashMap<usize, &SerializedPredicate> = HashMap::new();
    for id in ranking.iter() {
        let pred = predicates.get(id).unwrap();

        // find closest function to address
        let func_addr =
            match functions.binary_search_by(|func_addr| func_addr.cmp(&pred.address)) {
                Ok(index) => Some(functions[index]), // The address is a function start
                Err(0) => None,                      // The address is before the first function
                Err(index) => Some(functions[index - 1]),
            }
            .unwrap();

        // update entry if predicate with better score found inside function
        let current_pred = func_map.entry(func_addr).or_insert_with(|| pred);
        if pred.score > current_pred.score {
            *current_pred = pred;
        }
    }

    // now filter based on best found predicate per function
    let ranking: Vec<&usize> = ranking
        .iter()
        .filter(|id| {
            let pred = predicates.get(id).unwrap();
            func_map
                .values()
                .find(|p| p.address == pred.address && p.score == pred.score)
                .is_some()
        })
        .collect();

    println!("Ranking after {}", ranking.len());

    // deduplicate ranking
    // if we have multiple predicates that have the same address
    // e.g. [2,3,3,4] create two arrays from this [2,3,4], [2,3,4] in order to
    // handle both predicates but still only consider one per function

    // 1. Create a HashMap to gather all ids per address.
    let mut address_map: HashMap<usize, Vec<&'a usize>> = HashMap::new();
    for id in ranking.iter() {
        let address = predicates.get(&id).unwrap().address;
        address_map
            .entry(address)
            .or_insert_with(Vec::new)
            .push(&id);
    }

    let order = ranking.iter().fold(Vec::new(), |mut acc, id| {
        let address = predicates.get(id).unwrap().address;
        if !acc.contains(&address) {
            acc.push(address);
        }
        acc
    });

    // 2. Create the product of all possible combinations from these groups.
    let mut res: Vec<Vec<&usize>> = address_map
        .values()
        .map(|ids| ids.iter().cloned().collect_vec())
        .multi_cartesian_product()
        .collect();

    let res: Vec<Vec<&usize>> = order
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

    // todo: i dont think sorting by functions makes any sense.
    // does not reflect cfg flow at all
    /*
    for inner_vec in res.iter_mut() {
        inner_vec.sort_by(|a, b|
            predicates
                .get(a)
                .unwrap()
                .address
                .cmp(&predicates.get(b).unwrap().address)
        });
    }
    */

    /*
    println!(
        "Before: {:?} after: {:?}",
        ranking
            .iter()
            .map(|a| predicates.get(a).unwrap().address)
            .collect::<Vec<usize>>(),
        res.iter()
            .map(|inner_vec| {
                inner_vec
                    .iter()
                    .map(|&a| predicates.get(a).unwrap().address)
                    .collect::<Vec<usize>>()
            })
            .collect::<Vec<Vec<usize>>>()
    );
    */
    res
}

fn create_compound_rankings(
    config: &Config,
    rankings: &Vec<Vec<usize>>,
    functions: &Vec<usize>,
    file_path: &String,
) {
    let predicates: HashMap<usize, SerializedPredicate> = deserialize_predicates(file_path)
        .into_iter()
        .map(|p| (p.id, p))
        .collect();
    let mut compound_predicates: HashMap<Vec<usize>, u64> = HashMap::new();

    //let cfg = ControlFlowGraph::load(&config.eval_dir);

    //let mut already_computed = HashMap::new();

    for full_ranking in rankings.iter() {
        println!("Ranking size: {}", full_ranking.len());

        //println!("Ranking: {:?}, deduplicated: {:?}", ranking, deduplicated);
        if rankings.len() < 2 {
            continue;
        }

        /*
        if !already_computed.contains_key(full_ranking) {
            let deduplicated = deduplicate_ranking(full_ranking, &predicates, functions);

            already_computed
                .entry(full_ranking)
                .or_insert(deduplicated.clone());
        }
        */

        for ranking in deduplicate_ranking(full_ranking, &predicates, functions) {
            // using combinations func preserves order so we know that for a pair
            // [a, b], b is a successor of a in CFG
            for subset in (2..=4).flat_map(|i| ranking.iter().combinations(i)) {
                *compound_predicates
                    .entry(subset.iter().map(|&&&id| id).collect::<Vec<usize>>())
                    .or_insert(0) += 1;
            }
        }
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

    let mut sorted_entries: Vec<_> = compound_predicates.iter().collect();
    sorted_entries.sort_by(|a, b| compare_compound(a, b));

    let top_score = sorted_entries[0].1;
    let amt_with_top_score = sorted_entries.iter().filter(|x| x.1 == top_score).count();

    let top_ten: Vec<(u64, f64, Vec<usize>)> = sorted_entries
        .into_iter()
        .take(10)
        .map(|(compound, &score)| (compound.clone(), score))
        .map(|(compound, score)| {
            let avg = compound
                .iter()
                .map(|id| predicates.get(id).unwrap().score)
                .sum::<f64>();
            let mut ranking_addresses = compound
                .iter()
                .map(|id| predicates.get(&id).unwrap().address)
                .collect::<Vec<usize>>();

            ranking_addresses.sort();

            (score, avg / compound.len() as f64, ranking_addresses)
        })
        .collect();

    println!(
        "Compound size: {}, top score amount: {}, top values: {:?}",
        compound_predicates.len(),
        amt_with_top_score,
        top_ten,
    );
}

fn monitor_predicates_arm(
    config: &Config,
    binary: &Vec<u8>,
    file_path: &String,
) -> Result<Vec<Vec<usize>>> {
    let predicates = deserialize_predicates(file_path);

    println!("Amount of predicates: {}", predicates.len());

    // go through the detailed trace of every crashing input and check
    // predicate fulfillment, returns a ranking vector for each binary
    glob_paths(format!("{}/crashes/*-full*", config.eval_dir))
        .into_par_iter()
        .enumerate()
        .map(|(_, path)| monitor_arm(path, &binary, &predicates))
        .filter(|r| match r {
            Ok(val) => !val.is_empty(),
            Err(_) => true,
        })
        .collect::<Result<Vec<_>, _>>()
}

fn deserialize_predicates(predicate_file: &String) -> Vec<SerializedPredicate> {
    let content = read_to_string(predicate_file).expect("Could not read predicates.json");

    serde_json::from_str(&content).expect("Could not deserialize predicates.")
}

fn serialize_ranking(out_file: &String, ranking: &Vec<usize>) {
    let content = serde_json::to_string(&ranking).expect("Could not serialize ranking");
    fs::write(out_file, content).expect(&format!("Could not write {}", out_file));
}

pub fn monitor_arm(
    input_path: String,
    binary: &Vec<u8>,
    predicates: &Vec<SerializedPredicate>,
) -> Result<Vec<usize>> {
    let f = File::open(input_path).context("open monitor file")?;

    // all register values throughout the whole exeuction of the program
    let detailed_trace: Vec<Vec<u32>> =
        bincode::deserialize_from(f).context("bincode deserialize")?;

    let regs: Result<Vec<_>, _> = detailed_trace
        .into_iter()
        .map(|trace| {
            user_regs_struct_arm::try_from(trace)
                .map_err(|_| anyhow!("unable to get user_regs_struct_arm"))
        })
        .collect();

    let regs = regs?;

    let cs = Capstone::new()
        .arm()
        .mode(arm::ArchMode::Thumb)
        .extra_mode([arch::arm::ArchExtraMode::MClass].iter().copied())
        .detail(true)
        //.endian(capstone::Endian::Little)
        .build()
        .expect("failed to init capstone");

    rank_predicates_arm(cs, predicates, regs, binary)
}

pub fn monitor(
    config: &Config,
    index: usize,
    (cmd_line, file_path): &(String, Option<String>),
) -> Vec<usize> {
    let predicate_order_file = format!("out_{}", index);
    let predicate_file = &format!("{}/{}", config.eval_dir, predicate_file_name());
    let timeout = format!("{}", config.monitor_timeout);

    let args: Vec<_> = cmd_line.split_whitespace().map(|s| s.to_string()).collect();

    let mut child = if let Some(p) = file_path {
        Command::new("./target/release/monitor")
            .arg(&predicate_order_file)
            .arg(&predicate_file)
            .arg(&timeout)
            .args(args)
            .stdin(Stdio::from(File::open(p).unwrap()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Could not spawn child")
    } else {
        Command::new("./target/release/monitor")
            .arg(&predicate_order_file)
            .arg(&predicate_file)
            .arg(&timeout)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Could not spawn child")
    };

    wait_and_kill_child(&mut child, config.monitor_timeout);

    deserialize_predicate_order_file(&predicate_order_file)
}

fn wait_and_kill_child(child: &mut Child, timeout: u64) {
    let start_time = Instant::now();

    while start_time.elapsed().as_secs() < timeout + 10 {
        match child.try_wait() {
            Ok(Some(_)) => break,
            _ => {}
        }
    }

    match child.kill() {
        _ => {}
    }
}

fn predicate_file_name() -> String {
    "predicates.json".to_string()
}

fn deserialize_predicate_order_file(file_path: &String) -> Vec<usize> {
    let content = read_to_string(file_path);

    if !content.is_ok() {
        return vec![];
    }

    let ret: Vec<usize> = serde_json::from_str(&content.unwrap())
        .expect(&format!("Could not deserialize {}", file_path));
    remove_file(file_path).expect(&format!("Could not remove {}", file_path));

    ret
}

pub fn cmd_line(config: &Config) -> String {
    let executable = executable(config);
    let arguments = parse_args(config);

    format!("{} {}", executable, arguments)
}

fn parse_args(config: &Config) -> String {
    let file_name = format!("{}/arguments.txt", config.eval_dir);
    read_file(&file_name)
}

pub fn executable(config: &Config) -> String {
    let pattern = format!("{}/*_trace", config.eval_dir);
    let mut results = glob_paths(pattern);
    assert_eq!(results.len(), 1);

    results.pop().expect("No trace executable found")
}

pub fn replace_input(cmd_line: &String, replacement: &String) -> (String, Option<String>) {
    match cmd_line.contains("@@") {
        true => (cmd_line.replace("@@", replacement), None),
        false => (cmd_line.to_string(), Some(replacement.to_string())),
    }
}
