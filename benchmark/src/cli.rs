// SPDX-FileCopyrightText: © 2024 Merqury Cybersecurity Ltd <info@merqury.eu>
use std::f64;
use std::str::FromStr;
use std::usize;

use clap::Parser;

#[derive(Parser)]
#[command(arg_required_else_help = true)]
#[command(name = "benchmark")]
#[command(about="Run efficiency benchmarking for Error Correction", long_about = None)]
pub struct CliArgs {
    /// Length of key
    pub frame_length: usize,
    /// Maximum number of sample frames to draw per channel error
    #[arg(short, long, default_value = "1000000")]
    pub max_num_frames: usize,
    /// Filename of benchmark output
    #[arg(short, long, default_value = "output.csv")]
    pub output_file: String,
    /// Channel error range.
    ///
    /// Either a float to run the benchmark for a specific channel error
    /// or string of the form START:STOP:NUMBER_OF_STEPS to simulate a range of channel erros
    /// from START to STOP (inclusive) in NUMBER_OF_STEPS.
    #[arg(value_parser=clap::value_parser!(ErrorRange))]
    pub error: ErrorRange,

    /// Generate frames until this number of frame errors or `max_num_frames` is reached
    #[arg(short, long, default_value = "100")]
    pub until_frame_errors: u64,

    /// Number of CPU threads to use
    #[arg(short, long, default_value = "1")]
    pub num_threads: usize,
}

#[derive(Clone)]
pub struct ErrorRange {
    start: f64,
    stop: f64,
    num_steps: usize,
}

impl ErrorRange {
    pub fn iter(&self) -> impl Iterator<Item = f64> {
        let step_size = (self.stop - self.start) / (self.num_steps - 1) as f64;
        let num_steps = self.num_steps;
        let start = self.start;
        (0..num_steps)
            .step_by(1)
            .map(move |x| start + step_size * (x as f64))
    }
}

impl FromStr for ErrorRange {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(val) = f64::from_str(s) {
            return Ok(ErrorRange {
                start: val,
                stop: val,
                num_steps: 1,
            });
        };
        let [start, stop, num_steps]: [&str; 3] =
            match s.split(':').collect::<Vec<&str>>().try_into() {
                Ok(v) => v,
                Err(_) => {
                    return Err(format!(
                        "Must be of form start:stop:num_steps, got: '{}'",
                        s
                    ))
                }
            };

        let start = f64::from_str(start)
            .map_err(|e| format!("{}. Expected a float, got '{}'", e, start))?;
        let stop =
            f64::from_str(stop).map_err(|e| format!("{}. Expected a float, got '{}'", e, stop))?;
        let num_steps = usize::from_str(num_steps)
            .map_err(|e| format!("{}. Expected a positive integer, got '{}'", e, num_steps))?;
        Ok(ErrorRange {
            start,
            stop,
            num_steps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_single_error() {
        match CliArgs::try_parse_from(vec!["benchmark", "100", "5", "0.05"]) {
            Ok(r) => assert_eq!(r.error.iter().collect::<Vec<f64>>(), vec![0.05]),
            Err(e) => println!("{}", e),
        }
    }

    #[test]
    fn test_parser_range() {
        match CliArgs::try_parse_from(vec!["benchmark", "100", "5", "0.01:0.05:5"]) {
            Ok(r) => assert_eq!(
                r.error.iter().collect::<Vec<f64>>(),
                vec![0.01, 0.02, 0.03, 0.04, 0.05]
            ),
            Err(e) => println!("{}", e),
        }
    }

    #[test]
    fn test_parser_wrong_range() {
        match CliArgs::try_parse_from(vec!["benchmark", "100", "5", "0.01:ab:5"]) {
            Ok(_) => panic!("Should have failed!"),
            Err(e) => println!("{}", e),
        }
    }
}
