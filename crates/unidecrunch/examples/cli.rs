//! Command-line front end for the library. Run with
//! `cargo run -p unidecrunch --example cli --`.
//!
//!     cli <input.prg> <output.prg>          detect, unpack, save
//!     cli info <input.prg>                  detect and report, don't write
//!     cli scan <dir> [--out <dir>]          try every .prg in a directory
//!
//! Options:
//!     --configs <dir>   load cruncher definitions from a directory instead of
//!                       the embedded set
//!     --verbose / -v    print the engine log

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use unidecrunch::{Decrunched, UniDecrunch};

struct Options {
    configs: Option<PathBuf>,
    verbose: bool,
    args: Vec<String>,
}

fn usage() -> ExitCode {
    eprintln!("Usage: cli [options] <input.prg> <output.prg>");
    eprintln!("       cli [options] info <input.prg>");
    eprintln!("       cli [options] scan <dir> [--out <dir>]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --configs <dir>   load cruncher definitions from a directory");
    eprintln!("  --verbose, -v     print the engine log");
    ExitCode::FAILURE
}

fn parse_options() -> Result<Options, String> {
    let mut o = Options {
        configs: None,
        verbose: false,
        args: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--configs" => {
                let dir = it.next().ok_or("--configs needs a directory")?;
                o.configs = Some(PathBuf::from(dir));
            }
            "--verbose" | "-v" => o.verbose = true,
            _ => o.args.push(a),
        }
    }
    Ok(o)
}

fn build(o: &Options) -> Result<UniDecrunch, String> {
    match &o.configs {
        Some(dir) => UniDecrunch::with_config_dir(dir),
        None => UniDecrunch::with_embedded_configs(),
    }
}

fn main() -> ExitCode {
    let o = match parse_options() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: {e}");
            return usage();
        }
    };
    let ud = match build(&o) {
        Ok(ud) => ud,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match o.args.first().map(String::as_str) {
        Some("scan") if o.args.len() >= 2 => {
            let out = o
                .args
                .iter()
                .position(|a| a == "--out")
                .and_then(|i| o.args.get(i + 1))
                .map(PathBuf::from);
            scan(&ud, Path::new(&o.args[1]), out.as_deref(), o.verbose)
        }
        Some("info") if o.args.len() == 2 => info(&ud, Path::new(&o.args[1]), o.verbose),
        Some(_) if o.args.len() == 2 => {
            decrunch_file(&ud, Path::new(&o.args[0]), Path::new(&o.args[1]), o.verbose)
        }
        _ => usage(),
    }
}

fn report(d: &Decrunched, verbose: bool) {
    if verbose {
        for line in &d.log {
            println!("  | {}", line.replace('\n', "\n  | "));
        }
    }
    println!(
        "{}: ${:04x}-${:04x} ({} bytes), run address ${:04x}{}",
        d.cruncher,
        d.start,
        d.end,
        d.end as u32 - d.start as u32 + 1,
        d.jump_start,
        if d.real_start != d.start {
            format!(" (raw start ${:04x})", d.real_start)
        } else {
            String::new()
        }
    );
}

fn decrunch_file(ud: &UniDecrunch, input: &Path, output: &Path, verbose: bool) -> ExitCode {
    match ud.decrunch_file(input) {
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
        Ok(None) => {
            eprintln!("No known cruncher detected.");
            ExitCode::FAILURE
        }
        Ok(Some(d)) => {
            report(&d, verbose);
            if let Err(e) = d.save_prg_file(output) {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
            println!("Saved {}", output.display());
            ExitCode::SUCCESS
        }
    }
}

fn info(ud: &UniDecrunch, input: &Path, verbose: bool) -> ExitCode {
    match ud.decrunch_file(input) {
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
        Ok(None) => {
            // Show WHY the first matching definition's engine gave up.
            if let Ok(Some(det)) = ud.detect_file(input) {
                eprintln!("Detected as {} but no engine finished.", det.name());
                if verbose {
                    if let Err(e) = det.decrunch() {
                        eprintln!("  | {}", e.replace('\n', "\n  | "));
                    }
                }
            } else {
                eprintln!("No known cruncher detected.");
            }
            ExitCode::FAILURE
        }
        Ok(Some(d)) => {
            report(&d, verbose);
            ExitCode::SUCCESS
        }
    }
}

/// Try every .prg in a directory; print a per-file verdict and a summary table.
fn scan(ud: &UniDecrunch, dir: &Path, out_dir: Option<&Path>, verbose: bool) -> ExitCode {
    let mut files: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Err(e) => {
            eprintln!("Error: {}: {e}", dir.display());
            return ExitCode::FAILURE;
        }
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.extension()
                        .is_some_and(|x| x.to_string_lossy().eq_ignore_ascii_case("prg"))
            })
            .collect(),
    };
    files.sort();

    if let Some(out) = out_dir {
        if let Err(e) = std::fs::create_dir_all(out) {
            eprintln!("Error: {}: {e}", out.display());
            return ExitCode::FAILURE;
        }
    }

    let mut recognized = 0usize;
    let mut unpacked = 0usize;
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut by_cruncher: Vec<(String, usize)> = Vec::new();
    let total = files.len();

    for path in &files {
        let short = path.file_name().unwrap().to_string_lossy().into_owned();
        match ud.decrunch_file(path) {
            Err(e) => {
                println!("{short:<44} ERROR   {e}");
                failed.push((short, e));
            }
            Ok(None) => {
                // Distinguish "no signature at all" from "matched but no engine finished".
                match ud.detect_file(path) {
                    Ok(Some(det)) => {
                        recognized += 1;
                        let name = det.name().to_string();
                        println!("{short:<44} {name:<28} DEPACK FAILED");
                        failed.push((short, format!("detected as {name}, depack failed")));
                    }
                    _ => println!("{short:<44} -"),
                }
            }
            Ok(Some(d)) => {
                recognized += 1;
                unpacked += 1;
                println!(
                    "{short:<44} {:<28} ${:04x}-${:04x} run ${:04x}",
                    d.cruncher, d.start, d.end, d.jump_start
                );
                if verbose {
                    for line in &d.log {
                        println!("  | {}", line.replace('\n', "\n  | "));
                    }
                }
                match by_cruncher.iter_mut().find(|(n, _)| *n == d.cruncher) {
                    Some((_, c)) => *c += 1,
                    None => by_cruncher.push((d.cruncher.clone(), 1)),
                }
                if let Some(out) = out_dir {
                    // Start/end and run address in the file name for inspection.
                    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                    let target = out.join(format!(
                        "{stem}__{:04X}-{:04X}__run{:04X}.prg",
                        d.start, d.end, d.jump_start
                    ));
                    if let Err(e) = d.save_prg_file(&target) {
                        eprintln!("  write failed: {e}");
                    }
                }
            }
        }
    }

    println!();
    println!("Scanned {total} files: {recognized} recognized, {unpacked} unpacked, {} failed after detection", failed.len());
    by_cruncher.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    for (name, count) in &by_cruncher {
        println!("  {count:>4}  {name}");
    }
    ExitCode::SUCCESS
}
