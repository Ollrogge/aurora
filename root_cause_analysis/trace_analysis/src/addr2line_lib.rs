use crate::config::Config;
use crate::config::CpuArchitecture;
use glob::glob;
use std::process::Command;

pub fn glob_paths(pattern: String) -> Vec<String> {
    glob(&pattern)
        .unwrap()
        .map(|p| p.unwrap().to_str().unwrap().to_string())
        .collect()
}

pub fn executable(config: &Config) -> String {
    let pattern = format!("{}/*_trace", config.eval_dir);
    let mut results = glob_paths(pattern);
    assert_eq!(results.len(), 1);

    results.pop().expect("No trace executable found")
}

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
        CpuArchitecture::X86 => "addr2line",
        CpuArchitecture::ARM => "arm-none-eabi-addr2line",
    };

    let output = Command::new(command)
        .args(args)
        .output()
        .expect("Could not execute addr2line");

    String::from_utf8_lossy(&output.stdout)[..]
        .trim()
        .to_string()
}

pub fn addr2func(config: &Config, address: usize) -> String {
    let args = addr2line_args(config, address);

    let command = match config.cpu_architecture {
        CpuArchitecture::X86 => "addr2line",
        CpuArchitecture::ARM => "arm-none-eabi-addr2line",
    };

    let output = Command::new(command)
        .args(args)
        .output()
        .expect("Could not execute addr2line");

    let ret = String::from_utf8_lossy(&output.stdout)[..]
        .trim()
        .to_string();

    let parts: Vec<&str> = ret.split(" ").collect();

    let mut func_name = parts[1].to_string();
    func_name.retain(|c| !c.is_whitespace());

    func_name
}
