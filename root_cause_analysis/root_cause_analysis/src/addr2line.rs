use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::read_to_string;

use std::process::Command;
use structopt::StructOpt;

use crate::config::Config;
use crate::monitor::executable;
use crate::utils::{parse_hex, write_file};

use trace_analysis::config::CpuArchitecture;

fn addr2line_args(config: &Config, address: usize) -> Vec<String> {
    format!(
        "-e {} -a 0x{:x} -f -C -s -i -p",
        executable(config),
        address - config.load_offset
    )
    .split_whitespace()
    .map(|s| s.to_string())
    .collect()
}

pub fn addr2line(config: &Config, address: usize) -> String {
    let args = addr2line_args(config, address);

    let command = match config.cpu_architecture {
        CpuArchitecture::X86_64 => "addr2line",
        CpuArchitecture::ARM => "arm-none-eabi-addr2line",
    };

    // TODO: arm-none-eabi-addr2line -e ./tests_usbus_hid.elf -a 0x576
    let output = Command::new(command)
        .args(args)
        .output()
        .expect("Could not execute addr2line");

    String::from_utf8_lossy(&output.stdout)[..]
        .trim()
        .to_string()
}

fn read_trace_file(config: &Config) -> String {
    match config.debug_trace {
        true => format!("{}/seed_dump.txt", config.eval_dir),
        false => format!("{}/ranked_predicates.txt", config.eval_dir),
    }
}

fn out_file_path(config: &Config) -> String {
    match config.debug_trace {
        true => format!("{}/seed_dump_verbose.txt", config.eval_dir),
        false => format!("{}/ranked_predicates_verbose.txt", config.eval_dir),
    }
}

fn lines_as_vec(config: &Config) -> Vec<String> {
    read_to_string(&read_trace_file(config))
        .expect("Could not read")
        .split("\n")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn line2addr(line: &String) -> usize {
    parse_hex(line.split_whitespace().nth(0).unwrap()).unwrap()
}

fn unique_addresses(lines: &Vec<String>) -> HashSet<usize> {
    lines.par_iter().map(|line| line2addr(line)).collect()
}

fn map_address_to_src(config: &Config, addresses: &HashSet<usize>) -> HashMap<usize, String> {
    addresses
        .par_iter()
        .map(|address| (*address, addr2line(&config, *address)))
        .collect()
}

fn merge(lines: &Vec<String>, map: &HashMap<usize, String>) -> String {
    lines
        .par_iter()
        .map(|line| format!("{} //{}\n", line, map[&line2addr(&line)]))
        .collect()
}

fn main() {
    let config = Config::from_args();

    let output_vec = lines_as_vec(&config);
    let addresses = unique_addresses(&output_vec);
    let address_src_map = map_address_to_src(&config, &addresses);
    let output: String = merge(&output_vec, &address_src_map);

    write_file(&out_file_path(&config), output);
    println!("All done. Line info written to file");
}
