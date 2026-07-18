//! CrunchAB engine.
//!
//! Detection already ran the cruncher up to its relocated depack loop at $0340
//! (the `[probe]` section) and captured the end address from $040E/$040F into
//! `probe_end`. The machine arrives with that execution state intact; we run the
//! depacker to completion (PC = $040A) and read:
//!
//! * $040B/$040C: the address the depacker jumps to (run address)
//! * $040E/$040F: one below the start of the unpacked data (+1 = start)

use crate::config::CruncherConfig;
use crate::machine::Machine;

use super::EngineResult;

pub fn run(
    cfg: &CruncherConfig,
    probe_end: Option<u16>,
    m: &mut Machine,
    log: &mut Vec<String>,
) -> EngineResult {
    let Some(end) = probe_end else {
        log.push("internal error: crunchab engine without probe result".into());
        return EngineResult::failed();
    };
    if !m.run_until(&[0x040A], cfg.cap) {
        log.push(format!("never reached $040a (pc=${:04x})", m.cpu.pc));
        return EngineResult::failed();
    }
    let jump = m.mem.read_word(0x040B);
    let start = m.mem.read_word(0x040E).wrapping_add(1);
    log.push(format!(
        "done: start=${start:04x} end=${end:04x} jump=${jump:04x}"
    ));
    EngineResult {
        ok: true,
        name: None,
        start,
        real_start: start,
        end,
        jump_start: jump,
    }
}
