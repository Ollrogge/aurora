use crate::config::Config;
use crate::rankings::trunc_score;
use crate::utils::{read_file, write_file};
use std::collections::HashMap;
use trace_analysis::predicates::SerializedPredicate;
use trace_analysis::trace_analyzer::TraceAnalyzer;

pub fn analyze_traces(config: &Config) {
    let trace_analysis_output_dir = Some(config.eval_dir.to_string());
    let crash_blacklist_path = if config.blacklist_crashes() {
        Some(config.crash_blacklist_path.to_string())
    } else {
        None
    };
    let trace_analysis_config = trace_analysis::config::Config::default(
        &config.trace_dir,
        &trace_analysis_output_dir,
        &crash_blacklist_path,
    );
    let trace_analyzer = TraceAnalyzer::new(&trace_analysis_config);

    println!("dumping linear scores");
    trace_analyzer.dump_scores(&trace_analysis_config, false, false);

    let predicates = trace_analyzer.get_predicates_better_than(0.9);

    serialize_mnemonics(config, "mnemonics.json", &predicates, &trace_analyzer);
    serialize_predicates(config, "predicates.json", &predicates);

    let predicates = trace_analyzer.get_predicates();
    serialize_mnemonics(config, "all_mnemonics.json", &predicates, &trace_analyzer);
    serialize_predicates(config, "all_predicates.json", &predicates);
}

fn serialize_predicates(
    config: &Config,
    filename: &'static str,
    predicates: &Vec<SerializedPredicate>,
) {
    let content = serde_json::to_string(predicates).expect("Could not serialize predicates");
    write_file(&format!("{}/{}", config.eval_dir, filename), content);
}

pub fn deserialize_predicates(config: &Config) -> Vec<SerializedPredicate> {
    let file_name = format!("{}/predicates.json", config.eval_dir);

    let content = read_file(&file_name);
    serde_json::from_str(&content).expect("Could not deserialize predicates")
}

fn serialize_mnemonics(
    config: &Config,
    filename: &'static str,
    predicates: &Vec<SerializedPredicate>,
    trace_analyzer: &TraceAnalyzer,
) {
    let map: HashMap<_, _> = predicates
        .iter()
        .map(|p| (p.address, trace_analyzer.get_any_mnemonic(p.address)))
        .collect();
    let content = serde_json::to_string(&map).expect("Could not serialize mnemonics");
    write_file(&format!("{}/{}", config.eval_dir, filename), content);
}

pub fn deserialize_mnemonics(config: &Config) -> HashMap<usize, String> {
    let content = read_file(&format!("{}/mnemonics.json", config.eval_dir));
    serde_json::from_str(&content).expect("Could not deserialize mnemonics")
}
