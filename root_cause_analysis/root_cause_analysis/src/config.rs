use std::error::Error;
use std::num::ParseIntError;
use std::str::FromStr;
use structopt::clap::AppSettings;
use structopt::StructOpt;
use trace_analysis::config::CpuArchitecture;

fn parse_hex(src: &str) -> Result<usize, ParseIntError> {
    usize::from_str_radix(&src.replace("0x", ""), 16)
}

#[derive(Debug, StructOpt)]
#[structopt(
name = "root_cause_analysis",
global_settings = &[AppSettings::DisableVersion]
)]

pub enum TraceFormat {
    JSON,
    ZIP,
    BIN,
}

impl FromStr for TraceFormat {
    // dyn cuz it is a trait
    type Err = Box<dyn Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "JSON" => Ok(TraceFormat::JSON),
            "ZIP" => Ok(TraceFormat::ZIP),
            "BIN" => Ok(TraceFormat::BIN),
            _ => Err(format!("Invalid trace format: {}", s).into()),
        }
    }
}

#[derive(StructOpt)]
pub struct Config {
    #[structopt(
        long = "trace_format",
        default_value = "zip",
        case_insensitive = true,
        help = "Trace format of file"
    )]
    pub trace_format: TraceFormat,
    #[structopt(long = "trace-dir", default_value = "", help = "Path to traces")]
    pub trace_dir: String,
    #[structopt(long = "eval-dir", help = "Path to evaluation folder")]
    pub eval_dir: String,
    #[structopt(long = "rank-predicates", help = "Rank predicates")]
    pub rank_predicates: bool,
    #[structopt(long = "monitor", help = "Monitor predicates")]
    pub monitor_predicates: bool,
    #[structopt(
        long = "monitor-from-file",
        help = "Load monitoring data from a file instead of using ptrace"
    )]
    #[structopt(long = "compound-predicates", help = "Consider compound predicates")]
    pub compound_predicates: bool,
    #[structopt(
        long = "--monitor-timeout",
        default_value = "60",
        help = "Timeout for monitoring"
    )]
    pub monitor_timeout: u64,
    #[structopt(
        long = "cpu_architecture",
        default_value = "arm",
        case_insensitive = true,
        help = "Trace format of file"
    )]
    pub cpu_architecture: CpuArchitecture,
    #[structopt(
        long = "blacklist-crashes",
        default_value = "",
        help = "Path for crash blacklist"
    )]
    pub crash_blacklist_path: String,
    #[structopt(long = "debug-trace", help = "Debug trace")]
    pub debug_trace: bool,
    #[structopt(
        long = "load-offset",
        //default_value = "0x0000555555554000",
        default_value = "0x0",
        parse(try_from_str = parse_hex),
        help = "Load offset of the target"
    )]
    pub load_offset: usize,
}

impl Config {
    pub fn analyze_traces(&self) -> bool {
        !self.trace_dir.is_empty()
    }

    pub fn monitor_predicates(&self) -> bool {
        !self.eval_dir.is_empty()
    }

    pub fn blacklist_crashes(&self) -> bool {
        self.crash_blacklist_path != ""
    }
}
