use crate::config::Config;
use crate::monitor::executable;
use std::process::Command;
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
        CpuArchitecture::X86 => "addr2line",
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
