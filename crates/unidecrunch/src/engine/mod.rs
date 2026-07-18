//! Unpack engines. The configs select which engine runs and parameterize it;
//! the engines contain the run/trace/analyze logic.

mod crunchab;
mod generic;
mod timecruncher;

use crate::config::{CruncherConfig, EngineKind, VariantCfg};
use crate::machine::Machine;

/// What an engine found out.
pub struct EngineResult {
    pub ok: bool,
    /// Refined name (behavioral classification); None keeps the config/variant name.
    pub name: Option<String>,
    /// First address of the unpacked program (what gets saved).
    pub start: u16,
    /// The start address before any $0801 snapping/adjustment.
    pub real_start: u16,
    /// Last address of the unpacked program (inclusive).
    pub end: u16,
    /// Where the decruncher jumped to start the unpacked program.
    pub jump_start: u16,
}

impl EngineResult {
    pub fn failed() -> Self {
        EngineResult {
            ok: false,
            name: None,
            start: 0,
            real_start: 0,
            end: 0,
            jump_start: 0,
        }
    }
}

pub fn run(
    cfg: &CruncherConfig,
    variant: Option<&VariantCfg>,
    probe_end: Option<u16>,
    m: &mut Machine,
    log: &mut Vec<String>,
) -> EngineResult {
    match cfg.engine {
        EngineKind::Generic => generic::run(cfg, variant, m, log),
        EngineKind::TimeCruncher => timecruncher::run(cfg, m, log),
        EngineKind::CrunchAB => crunchab::run(cfg, probe_end, m, log),
    }
}
