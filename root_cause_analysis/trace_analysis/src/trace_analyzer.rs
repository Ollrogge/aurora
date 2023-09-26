use crate::config::{Config, CpuArchitecture, TraceFormat};
use crate::control_flow_graph::{CFGCollector, ControlFlowGraph};
use crate::predicate_analysis::PredicateAnalyzer;
use crate::predicates::{Predicate, SerializedPredicate};
use crate::trace::{Instruction, Selector, Trace, TraceVec};
use crate::trace_integrity::TraceIntegrityChecker;
use glob::glob;
use nix::libc::PR_FP_EXC_NONRECOV;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::{read_to_string, File};
use std::io::Write;
use std::ops::Range;
use std::process::exit;

pub struct TraceAnalyzer {
    pub crashes: TraceVec,
    pub non_crashes: TraceVec,
    pub address_scores: Vec<(usize, Predicate)>,
    pub cfg: ControlFlowGraph,
    pub memory_addresses: MemoryAddresses,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MemoryAddresses(pub HashMap<String, Range<usize>>);

impl MemoryAddresses {
    pub fn read_from_file(config: &Config) -> MemoryAddresses {
        let file_path = format!("{}/addresses.json", config.output_directory);
        let content =
            fs::read_to_string(&file_path).expect(&format!("File {} not found!", &file_path));
        serde_json::from_str(&content).expect(&format!("Could not deserialize file {}", &file_path))
    }
}

fn store_trace(trace: &Trace, must_have: &Option<HashSet<usize>>) -> bool {
    match must_have {
        Some(addresses) => addresses.iter().any(|k| trace.instructions.contains_key(k)),
        None => true,
    }
}

pub fn read_crash_blacklist(
    blacklist_crashes: bool,
    crash_blacklist_path: &String,
) -> Option<Vec<String>> {
    if blacklist_crashes {
        Some(
            read_to_string(crash_blacklist_path)
                .expect("Could not read crash blacklist")
                .split("\n")
                .map(|s| {
                    s.split("/")
                        .last()
                        .expect(&format!("Could not split string {}", s))
                        .to_string()
                })
                .filter(|s| !s.is_empty())
                .collect(),
        )
    } else {
        None
    }
}

pub fn blacklist_path(path: &String, blacklist: &Option<Vec<String>>) -> bool {
    blacklist
        .as_ref()
        .unwrap_or(&vec![])
        .iter()
        .any(|p| path.contains(p))
}

fn parse_traces(
    path: &String,
    config: &Config,
    must_include: Option<HashSet<usize>>,
    blacklist_paths: Option<Vec<String>>,
) -> TraceVec {
    let pattern = match config.trace_format {
        TraceFormat::JSON => format!("{}/*trace", path),
        TraceFormat::ZIP => format!("{}/*.zip", path),
        TraceFormat::BIN => format!("{}/*summary.bin", path),
    };

    let mut paths: Vec<String> = glob(&pattern)
        .unwrap()
        .map(|p| p.unwrap().to_str().unwrap().to_string())
        .filter(|p| !blacklist_path(&p, &blacklist_paths))
        .collect();

    if config.random_traces() {
        paths.shuffle(&mut thread_rng());
    }

    match config.trace_format {
        TraceFormat::JSON => TraceVec::from_vec(
            paths
                .into_par_iter()
                .map(|s| Trace::from_trace_file(s, config.cpu_architecture))
                .take(if config.random_traces() {
                    config.random_traces
                } else {
                    0xffff_ffff_ffff_ffff
                })
                .filter(|t| store_trace(&t, &must_include))
                .collect(),
        ),
        TraceFormat::ZIP => TraceVec::from_vec(
            paths
                .into_par_iter()
                .map(|s| Trace::from_zip_file(s, config.cpu_architecture))
                .take(if config.random_traces() {
                    config.random_traces
                } else {
                    0xffff_ffff_ffff_ffff
                })
                .filter(|t| store_trace(&t, &must_include))
                .collect(),
        ),
        TraceFormat::BIN => TraceVec::from_vec(
            paths
                .into_par_iter()
                .map(|s| Trace::from_bin_file(s, config.cpu_architecture))
                .take(if config.random_traces() {
                    config.random_traces
                } else {
                    0xffff_ffff_ffff_ffff
                })
                .filter(|t| store_trace(&t, &must_include))
                .collect(),
        ),
    }
}

impl TraceAnalyzer {
    pub fn new(config: &Config) -> TraceAnalyzer {
        let crash_blacklist =
            read_crash_blacklist(config.blacklist_crashes(), &config.crash_blacklist_path);
        let crashes = parse_traces(&config.path_to_crashes, config, None, crash_blacklist);
        let crashing_addresses: Option<HashSet<usize>> = match config.filter_non_crashes {
            true => Some(crashes.iter().map(|t| t.last_address).collect()),
            false => None,
        };

        let non_crashes = parse_traces(
            &config.path_to_non_crashes,
            config,
            crashing_addresses,
            None,
        );

        println!(
            "{} crashes and {} non-crashes",
            crashes.len(),
            non_crashes.len()
        );

        let mut trace_analyzer = TraceAnalyzer {
            crashes,
            non_crashes,
            address_scores: Vec::new(),
            cfg: ControlFlowGraph::new(),
            memory_addresses: MemoryAddresses::read_from_file(config),
        };

        if config.check_traces || config.dump_scores || config.debug_predicate() {
            let mut cfg_collector = CFGCollector::new();
            println!("filling cfg");
            trace_analyzer.fill_cfg(&mut cfg_collector);
            trace_analyzer.save_cfg(&config);
        }

        if config.check_traces {
            println!("checking traces");
            let ti = TraceIntegrityChecker::new(config.cpu_architecture);
            ti.check_traces(&trace_analyzer);
            exit(0);
        }

        if config.dump_scores {
            println!("calculating scores");
            trace_analyzer.fill_address_scores(config.cpu_architecture);
        }

        trace_analyzer
    }

    fn fill_cfg(&mut self, cfg_collector: &mut CFGCollector) {
        for instruction in self
            .crashes
            .iter_all_instructions()
            .chain(self.non_crashes.iter_all_instructions())
        {
            for succ in &instruction.successors {
                cfg_collector.add_edge(instruction.address, succ.address);
            }
        }

        self.cfg = cfg_collector.construct_graph();
    }

    fn fill_address_scores(&mut self, arch: CpuArchitecture) {
        let addresses = self.crash_non_crash_intersection();
        self.address_scores = addresses
            .into_par_iter()
            .flat_map(|address| {
                PredicateAnalyzer::evaluate_best_predicates_at_address(address, self, arch)
                    .into_iter()
                    .map(|p| (address, p))
                    .collect::<Vec<(usize, Predicate)>>()
            })
            .collect();
    }

    pub fn address_union(&self) -> HashSet<usize> {
        let crash_union = TraceAnalyzer::trace_union(&self.crashes);
        let non_crash_union = TraceAnalyzer::trace_union(&self.non_crashes);
        crash_union.union(&non_crash_union).map(|x| *x).collect()
    }

    pub fn crash_address_union(&self) -> HashSet<usize> {
        TraceAnalyzer::trace_union(&self.crashes)
    }

    fn trace_union(traces: &TraceVec) -> HashSet<usize> {
        let mut res = HashSet::new();
        for trace in traces.iter() {
            res = res.union(&trace.visited_addresses()).map(|x| *x).collect();
        }

        res
    }

    pub fn iter_all_instructions<'a>(
        crashes: &'a TraceVec,
        non_crashes: &'a TraceVec,
    ) -> impl Iterator<Item = &'a Instruction> {
        crashes
            .iter_all_instructions()
            .chain(non_crashes.iter_all_instructions())
    }

    pub fn iter_all_traces(&self) -> impl Iterator<Item = &Trace> {
        self.crashes.iter().chain(self.non_crashes.iter())
    }

    pub fn iter_all_instructions_at_address(
        &self,
        address: usize,
    ) -> impl Iterator<Item = &Instruction> {
        self.crashes
            .iter_instructions_at_address(address)
            .chain(self.non_crashes.iter_instructions_at_address(address))
    }

    // intersection based on trace address
    pub fn crash_non_crash_intersection(&self) -> HashSet<usize> {
        let crash_union = TraceAnalyzer::trace_union(&self.crashes);
        let non_crash_union = TraceAnalyzer::trace_union(&self.non_crashes);
        crash_union
            .intersection(&non_crash_union)
            .map(|x| *x)
            .collect()
    }

    // for all instructions at address get min and max val of a specific register index
    pub fn values_at_address(
        &self,
        address: usize,
        selector: &Selector,
        reg_index: Option<usize>,
    ) -> Vec<u64> {
        let ret: Vec<_> = match selector {
            Selector::RegMin => self
                .iter_all_instructions_at_address(address)
                .filter_map(|i| i.registers_min.get(reg_index?).map(|reg| reg.value()))
                .collect(),
            Selector::RegMax => self
                .iter_all_instructions_at_address(address)
                .filter_map(|i| i.registers_max.get(reg_index?).map(|reg| reg.value()))
                .collect(),
            _ => unreachable!(),
        };

        ret
    }

    pub fn unique_values_at_address(
        &self,
        address: usize,
        selector: &Selector,
        reg_index: Option<usize>,
    ) -> Vec<u64> {
        let mut ret: Vec<_> = self
            .values_at_address(address, selector, reg_index)
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        ret.sort();

        ret
    }

    pub fn sort_scores(&self) -> Vec<Predicate> {
        let mut ret: Vec<Predicate> = self
            .address_scores
            .iter()
            .map(|(_, p)| (p.clone()))
            .collect();

        ret.par_sort_by(|p1, p2| p1.score.partial_cmp(&p2.score).unwrap());

        ret
    }

    pub fn save_cfg(&self, config: &Config) {
        self.cfg.save(&config.output_directory);
    }

    pub fn dump_scores(&self, config: &Config, filter_scores: bool, print_scores: bool) {
        let (file_name, scores) = (
            format!("{}/scores_linear.csv", config.output_directory),
            self.sort_scores(),
        );

        let mut file = File::create(file_name).unwrap();

        for predicate in scores.iter() {
            if filter_scores && predicate.score <= 0.5 {
                continue;
            }

            write!(
                &mut file,
                "{:#x};{} ({}) -- {}\n",
                predicate.address,
                predicate.score,
                predicate.to_string(),
                self.get_any_mnemonic(predicate.address),
            )
            .unwrap();
        }

        if print_scores {
            TraceAnalyzer::print_scores(&scores, filter_scores);
        }

        TraceAnalyzer::dump_for_serialization(config, &scores)
    }

    fn dump_for_serialization(config: &Config, scores: &Vec<Predicate>) {
        let scores: Vec<_> = scores.iter().map(|p| p.to_serialzed()).collect();
        let serialized_string = serde_json::to_string(&scores).unwrap();

        let file_path = format!("{}/scores_linear_serialized.json", config.output_directory);

        fs::write(&file_path, serialized_string)
            .expect(&format!("Could not write file {}", file_path));
    }

    pub fn get_predicates_better_than(&self, min_score: f64) -> Vec<SerializedPredicate> {
        self.address_scores
            .iter()
            .filter(|(_, p)| p.score > min_score)
            .map(|(_, p)| p.to_serialzed())
            .collect()
    }

    pub fn get_predicates_better_than_filter(&self, min_score: f64) -> Vec<SerializedPredicate> {
        let mut predicates_map = self
            .address_scores
            .iter()
            .filter(|(_, p)| p.score > min_score)
            .fold(HashMap::new(), |mut acc, (addr, p)| {
                acc.entry(addr).or_insert_with(Vec::new).push(p);
                acc
            });

        /*
        // same meaning
        0x000000000020e12a -- r4 max_reg_val_greater_or_equal 0x0 -- 0.9979423868312758 -- mov r4, r2 (path rank: 0.8720885577887211) //0x0020e12a: _forward_rfrag at gnrc_sixlowpan_frag_sfr.c:1664
        0x000000000020e12a -- r4 min_reg_val_greater_or_equal 0x0 -- 0.9979423868312758 -- mov r4, r2 (path rank: 0.8729085029311009) //0x0020e12a: _forward_rfrag at gnrc_sixlowpan_frag_sfr.c:1664

        // reg_val less 0xfff is sufficient
        0x000000000020e12a -- r4 max_reg_val_less 0xffffffff -- 0.9979423868312758 -- mov r4, r2 (path rank: 0.8737284480734812) //0x0020e12a: _forward_rfrag at gnrc_sixlowpan_frag_sfr.c:1664
        0x000000000020e12a -- r4 max_reg_val_less 0xffff -- 0.9979423868312758 -- mov r4, r2 (path rank: 0.874548393215861) //0x0020e12a: _forward_rfrag at gnrc_sixlowpan_frag_sfr.c:1664
        0x000000000020e12a -- r4 min_reg_val_less 0xffffffff -- 0.9979423868312758 -- mov r4, r2 (path rank: 0.875368338358241) //0x0020e12a: _forward_rfrag at gnrc_sixlowpan_frag_sfr.c:1664
        0x000000000020e12a -- r4 min_reg_val_less 0xffff -- 0.9979423868312758 -- mov r4, r2 (path rank: 0.8761882835006211) //0x0020e12a: _forward_rfrag at gnrc_sixlowpan_frag_sfr.c:1664

        TODO: move this filtering outside, otherwise pathrank is fucked
        or todo: do the filtering before even saving the predicates !!
        */

        let mut filtered_predicates: Vec<SerializedPredicate> = Vec::new();
        for preds in predicates_map.values_mut() {
            let mut filtered: HashMap<String, &Predicate> = HashMap::new();
            for pred in preds.iter() {
                if pred.name.contains("flag") {
                    let sub = pred.name.split("_").collect::<Vec<&str>>()[1];
                    filtered.entry(sub.to_string()).or_insert(pred);
                } else if pred.name.contains("less_or_equal") {
                    let key = format!("{}less_or_equal{}", pred.p1.unwrap(), pred.p2.unwrap());
                    filtered.insert(key, pred);
                } else if pred.name.contains("greater_or_equal") {
                    let key = format!("{}greater_or_equal{}", pred.p1.unwrap(), pred.p2.unwrap());
                    filtered.insert(key, pred);
                } else if pred.name.contains("reg_val_less") {
                    match filtered.entry("reg_val_less".to_string()) {
                        Entry::Occupied(mut entry) => {
                            if pred.p2 < entry.get().p2 {
                                entry.insert(pred);
                            }
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(pred);
                        }
                    }
                } else {
                    filtered.insert(pred.name.clone(), pred);
                }
            }
            filtered_predicates.extend(filtered.values().map(|p| p.to_serialzed()))
        }

        filtered_predicates
    }

    pub fn get_predicates(&self) -> Vec<SerializedPredicate> {
        self.address_scores
            .iter()
            .map(|(_, p)| p.to_serialzed())
            .collect()
    }

    fn print_scores(scores: &Vec<Predicate>, filter_scores: bool) {
        for predicate in scores.iter() {
            if filter_scores && predicate.score <= 0.5 {
                continue;
            }
            println!(
                "{:#x};{} ({})",
                predicate.address,
                predicate.score,
                predicate.to_string()
            );
        }
    }

    pub fn any_instruction_at_address_contains_reg(
        &self,
        address: usize,
        reg_index: usize,
    ) -> bool {
        self.crashes
            .0
            .par_iter()
            .chain(self.non_crashes.0.par_iter())
            .any(|t| match t.instructions.get(&address) {
                Some(instruction) => instruction.registers_min.get(reg_index).is_some(),
                _ => false,
            })
    }

    pub fn get_any_mnemonic(&self, address: usize) -> String {
        self.iter_all_instructions_at_address(address)
            .nth(0)
            .unwrap()
            .mnemonic
            .to_string()
    }
}
