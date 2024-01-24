use crate::config::Config;
use crate::rankings::{serialize_compound_rankings, serialize_evaluation_info, serialize_rankings};
use crate::utils::{glob_paths, read_file};
use anyhow::{anyhow, Context, Result};
use capstone::arch::arm::{self, ArmInsn, ArmOperandType};
use capstone::prelude::*;
use goblin::elf::{program_header, Elf};
use predicate_monitoring::{rank_predicates, rank_predicates_arm};
use rayon::prelude::*;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::File;
use std::fs::{self, read, read_to_string, remove_file};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Instant;
use trace_analysis::config::CpuArchitecture;
use trace_analysis::predicates::SerializedPredicate;
use trace_analysis::register::user_regs_struct_arm;
use trace_analysis::trace_analyzer::{blacklist_path, read_crash_blacklist};

pub fn monitor_predicates(config: &Config) -> Result<()> {
    if config.cpu_architecture == CpuArchitecture::X86 {
        let blacklist_paths =
            read_crash_blacklist(config.blacklist_crashes(), &config.crash_blacklist_path);
        let cmd_line = cmd_line(&config);

        let rankings = glob_paths(format!("{}/inputs/crashes/*", config.eval_dir))
            .into_par_iter()
            .enumerate()
            .filter(|(_, p)| !blacklist_path(&p, &blacklist_paths))
            .map(|(index, i)| monitor(config, index, &replace_input(&cmd_line, &i)))
            .filter(|r| !r.is_empty())
            .collect();
        serialize_rankings(config, &rankings);
        Ok(())
    } else {
        // todo: different way than depending on the fact that the binary is in the parent dir
        let pattern = format!("{}/*_trace", config.eval_dir);
        let binary_path = glob_paths(pattern)
            .pop()
            .expect("No binary found for monitoring");

        let binary = fs::read(binary_path)?;
        let elf = Elf::parse(&binary)?;

        let text_info = {
            let mut res = Err(anyhow::anyhow!("Unable to find text section"));
            for section in &elf.section_headers {
                if let Some(section_name) = elf.shdr_strtab.get_at(section.sh_name) {
                    if section_name == ".text" {
                        res = Ok((section.sh_addr, section.sh_offset));
                        break;
                    }
                }
            }

            res?
        };

        let predicate_file = &format!("{}/{}", config.eval_dir, predicate_file_name());
        let (rankings, evaluation_info) =
            monitor_predicates_arm(config, &binary, text_info, predicate_file);

        serialize_evaluation_info(config, &evaluation_info);
        serialize_rankings(config, &rankings);

        Ok(())
    }
}

fn monitor_predicates_arm(
    config: &Config,
    binary: &Vec<u8>,
    text_info: (u64, u64),
    file_path: &String,
) -> (Vec<Vec<usize>>, Vec<HashMap<usize, bool>>) {
    let predicates = deserialize_predicates(file_path);

    println!("Amount of predicates: {}", predicates.len());

    // go through the detailed trace of every crashing input and check
    // predicate fulfillment, returns a ranking vector for each binary
    let (rankings, evaluation_info): (Vec<Vec<usize>>, Vec<HashMap<usize, bool>>) =
        glob_paths(format!("{}/crashes/*-full*", config.eval_dir))
            .into_par_iter()
            .enumerate()
            .filter_map(
                |(_, path)| match monitor_arm(path, &binary, text_info, &predicates) {
                    Ok(result) => Some(result),
                    Err(_) => None,
                },
            )
            .unzip();

    (rankings, evaluation_info)
}

fn deserialize_predicates(predicate_file: &String) -> Vec<SerializedPredicate> {
    let content = read_to_string(predicate_file).expect("Could not read predicates.json");

    serde_json::from_str(&content).expect("Could not deserialize predicates.")
}

pub fn monitor_arm(
    input_path: String,
    binary: &Vec<u8>,
    text_info: (u64, u64),
    predicates: &Vec<SerializedPredicate>,
) -> Result<(Vec<usize>, HashMap<usize, bool>)> {
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

    rank_predicates_arm(cs, predicates, regs, binary, text_info)
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
    // /<target>/corpus/traces
    let dir = PathBuf::from(&config.trace_dir);
    let dir = dir.parent().unwrap().parent().unwrap();

    let patterns = [
        format!("{}/*.elf", dir.display().to_string()),
        format!("{}/*.bin", dir.display().to_string()),
    ];

    for pattern in &patterns {
        let result = glob::glob(pattern)
            .expect("Failed to read glob pattern")
            .filter_map(Result::ok)
            .map(|path| path.to_string_lossy().into_owned())
            .next();

        if let Some(path) = result {
            return path;
        }
    }

    panic!("No trace executable found in {:?}", config.eval_dir);
}

pub fn replace_input(cmd_line: &String, replacement: &String) -> (String, Option<String>) {
    match cmd_line.contains("@@") {
        true => (cmd_line.replace("@@", replacement), None),
        false => (cmd_line.to_string(), Some(replacement.to_string())),
    }
}
