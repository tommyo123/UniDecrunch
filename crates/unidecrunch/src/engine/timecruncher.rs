//! Time Cruncher 3.x / 4.2 engine.
//!
//! These crunchers keep their output pointer in zero page at $FC/$FD, so no
//! write tracing is needed. The engine runs the depacker to its known control
//! points and reads the exact boundaries:
//!
//! * PC = $0100: the depack loop starts; word[$FC]-1 is the END of the output.
//! * version 31 (3.1/3.2): PC = $0369 is the hand-off; word[$FC]+1 is the
//!   START and the run address is stored at $036A/$036B.
//! * version 42 (4.2): PC = $0374 is the hand-off; start = word[$FC]+3+Y and
//!   the run address is at $0375/$0376.

use crate::config::CruncherConfig;
use crate::machine::Machine;

use super::EngineResult;

pub fn run(cfg: &CruncherConfig, m: &mut Machine, log: &mut Vec<String>) -> EngineResult {
    if !m.run_until(&[0x0100], cfg.cap) {
        log.push(format!("never reached $0100 (pc=${:04x})", m.cpu.pc));
        return EngineResult::failed();
    }
    let end = m.mem.read_word(0xFC).wrapping_sub(1);
    log.push(format!(
        "depack loop reached; end = word[$fc]-1 = ${end:04x}"
    ));

    match cfg.version {
        31 | 32 => {
            if !m.run_until(&[0x0369], cfg.cap) {
                log.push(format!("never reached $0369 (pc=${:04x})", m.cpu.pc));
                return EngineResult::failed();
            }
            let start = m.mem.read_word(0xFC).wrapping_add(1);
            let jump = m.mem.read_word(0x036A);
            log.push(format!("done: start=${start:04x} jump=${jump:04x}"));
            EngineResult {
                ok: true,
                name: None,
                start,
                real_start: start,
                end,
                jump_start: jump,
            }
        }
        42 => {
            if !m.run_until(&[0x0374], cfg.cap) {
                log.push(format!("never reached $0374 (pc=${:04x})", m.cpu.pc));
                return EngineResult::failed();
            }
            let start = m
                .mem
                .read_word(0xFC)
                .wrapping_add(3)
                .wrapping_add(m.cpu.y as u16);
            let jump = m.mem.read_word(0x0375);
            log.push(format!("done: start=${start:04x} jump=${jump:04x}"));
            EngineResult {
                ok: true,
                name: None,
                start,
                real_start: start,
                end,
                jump_start: jump,
            }
        }
        other => {
            log.push(format!("unsupported timecruncher version {other}"));
            EngineResult::failed()
        }
    }
}
