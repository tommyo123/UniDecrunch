//! The detector: tries every cruncher definition in order against a PRG file.
//!
//! Each candidate gets a *fresh* machine (loaded PRG, $01 = $37), so a probe
//! run for one cruncher can never contaminate the next attempt. When a config
//! matches, the machine is primed at the cruncher's entry point and handed to
//! the engine via [`Detection::decrunch`].

use crate::config::{load_str, CruncherConfig, Entry};
use crate::embedded::EMBEDDED_CONFIGS;
use crate::engine;
use crate::machine::Machine;
use crate::pattern::sys_address;

pub struct UniDecrunch {
    pub configs: Vec<CruncherConfig>,
}

/// A recognized cruncher, ready to unpack.
pub struct Detection<'a> {
    pub config: &'a CruncherConfig,
    /// Index into `config.variants` when a refinement pattern matched.
    pub variant: Option<usize>,
    machine: Machine,
    probe_end: Option<u16>,
    pub log: Vec<String>,
}

/// A finished unpack.
pub struct Decrunched {
    /// Human-readable cruncher name (config/variant/behavioral).
    pub cruncher: String,
    /// Saved range: first address...
    pub start: u16,
    /// ...and last address (inclusive).
    pub end: u16,
    /// Start before $0801 snapping/adjustments.
    pub real_start: u16,
    /// Where the decruncher jumped to launch the unpacked program.
    pub jump_start: u16,
    /// The unpacked program as a PRG image (load address + data).
    pub prg: Vec<u8>,
    pub log: Vec<String>,
}

impl UniDecrunch {
    /// The default detector with embedded cruncher definitions.
    pub fn new() -> Self {
        Self::with_embedded_configs().expect("embedded configs must parse")
    }

    pub fn with_embedded_configs() -> Result<Self, String> {
        let mut configs = Vec::new();
        for (name, text) in EMBEDDED_CONFIGS {
            configs.push(load_str(text, name)?);
        }
        Ok(UniDecrunch { configs })
    }

    /// Load all `*.toml` files from a directory (evaluated in filename order).
    pub fn with_config_dir(dir: &std::path::Path) -> Result<Self, String> {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        files.sort();
        if files.is_empty() {
            return Err(format!("{}: no .toml config files found", dir.display()));
        }
        let mut configs = Vec::new();
        for path in files {
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            configs.push(load_str(&text, &name)?);
        }
        Ok(UniDecrunch { configs })
    }

    pub fn detect_file(&self, path: &std::path::Path) -> Result<Option<Detection<'_>>, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        self.detect_bytes(&bytes)
    }

    /// Try every cruncher definition in order; the first match wins.
    /// Note: prefer [`UniDecrunch::decrunch_bytes`] when you intend to unpack,
    /// since it falls through to later definitions when a matching engine fails.
    pub fn detect_bytes(&self, prg: &[u8]) -> Result<Option<Detection<'_>>, String> {
        for cfg in &self.configs {
            if let Some(det) = self.try_config(cfg, prg)? {
                return Ok(Some(det));
            }
        }
        Ok(None)
    }

    /// Like [`detect_bytes`], but skips catch-all (`always = true`) definitions.
    /// A match therefore means a real byte signature was recognized, regardless
    /// of where catch-alls sit in config order, useful to classify "recognized
    /// but the depacker failed" against "not a crunched file at all". (The
    /// catch-all matches any program with a SYS line, so it cannot answer that
    /// question.)
    pub fn detect_signature_bytes(&self, prg: &[u8]) -> Result<Option<Detection<'_>>, String> {
        for cfg in &self.configs {
            if cfg.detect_always {
                continue;
            }
            if let Some(det) = self.try_config(cfg, prg)? {
                return Ok(Some(det));
            }
        }
        Ok(None)
    }

    /// Detect AND unpack, falling through: when a definition's signature
    /// matches but its depacker never finishes, the next definition gets a try
    /// (several families share bootstrap signatures like `JMP $0334`).
    ///
    /// Double-crunched files are peeled recursively: when the unpacked result
    /// is itself recognized by a *signature-based* definition (catch-alls are
    /// excluded, since unpacked cruncher tools contain cruncher-like code) and
    /// that layer unpacks successfully too, the layers are chained. A failed
    /// inner depack keeps the outer result.
    pub fn decrunch_bytes(&self, prg: &[u8]) -> Result<Option<Decrunched>, String> {
        let Some(mut result) = self.decrunch_once(prg, false)? else {
            return Ok(None);
        };
        let mut names = vec![result.cruncher.clone()];
        for _layer in 0..3 {
            // Peel ONLY when the result spans almost all of RAM: a depack stage
            // staged over the whole memory, never a real program (max ~$C800 for
            // $0801-$CFFF). Anything less could be an unpacked cruncher tool,
            // which inherently contains cruncher-like code and would be
            // destroyed by re-depacking it.
            if result.end.wrapping_sub(result.start) < 0xE000 {
                break;
            }
            // The outer layer's run address is the natural entry for the next
            // layer when its (rebuilt) BASIC line can't be parsed.
            match self.decrunch_once_with_entry(&result.prg.clone(), true, Some(result.jump_start))
            {
                Ok(Some(inner)) if inner.prg != result.prg => {
                    names.push(inner.cruncher.clone());
                    let mut log = result.log;
                    log.push(format!(
                        "--- output spans nearly all of RAM; peeling layer {} ---",
                        names.len()
                    ));
                    log.extend(inner.log);
                    result = Decrunched { log, ..inner };
                }
                _ => break,
            }
        }
        if names.len() > 1 {
            result.cruncher = names.join(" \u{2192} ");
        }
        Ok(Some(result))
    }

    /// One detection+unpack pass. `signatures_only` excludes `always = true`
    /// catch-all definitions (used for the recursive layers).
    fn decrunch_once(
        &self,
        prg: &[u8],
        signatures_only: bool,
    ) -> Result<Option<Decrunched>, String> {
        self.decrunch_once_with_entry(prg, signatures_only, None)
    }

    /// Unpack EXACTLY ONE cruncher layer, signature-based only (catch-all
    /// definitions are excluded so an unpacked program's cruncher-like code does
    /// not false-match). `entry_fallback` supplies the previous layer's run
    /// address as the entry when a rebuilt BASIC line can't be parsed. Returns
    /// `None` when `prg` is not a recognized crunched layer or the depacker did
    /// not finish. This is the building block for cascade / layer-by-layer
    /// unpacking, where the caller (not the conservative full-RAM heuristic in
    /// [`Self::decrunch_bytes`]) decides how deep to peel.
    pub fn decrunch_layer(
        &self,
        prg: &[u8],
        entry_fallback: Option<u16>,
    ) -> Result<Option<Decrunched>, String> {
        self.decrunch_once_with_entry(prg, true, entry_fallback)
    }

    fn decrunch_once_with_entry(
        &self,
        prg: &[u8],
        signatures_only: bool,
        entry_fallback: Option<u16>,
    ) -> Result<Option<Decrunched>, String> {
        let mut attempts: Vec<String> = Vec::new();
        for cfg in &self.configs {
            if signatures_only && cfg.detect_always {
                continue;
            }
            let Some(det) = self.try_config_with_entry(cfg, prg, entry_fallback)? else {
                continue;
            };
            match det.decrunch() {
                Ok(mut d) => {
                    if !attempts.is_empty() {
                        d.log.insert(
                            0,
                            format!("earlier attempts failed: {}", attempts.join(", ")),
                        );
                    }
                    return Ok(Some(d));
                }
                Err(_) => attempts.push(cfg.source.clone()),
            }
        }
        Ok(None)
    }

    pub fn decrunch_file(&self, path: &std::path::Path) -> Result<Option<Decrunched>, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        self.decrunch_bytes(&bytes)
    }

    fn try_config<'a>(
        &self,
        cfg: &'a CruncherConfig,
        prg: &[u8],
    ) -> Result<Option<Detection<'a>>, String> {
        self.try_config_with_entry(cfg, prg, None)
    }

    fn try_config_with_entry<'a>(
        &self,
        cfg: &'a CruncherConfig,
        prg: &[u8],
        entry_fallback: Option<u16>,
    ) -> Result<Option<Detection<'a>>, String> {
        let mut log = Vec::new();
        let mut m = Machine::new();
        m.mem.load_prg(prg)?;

        // 1. Signature match against RAM (catch-all definitions skip this).
        let base = cfg.detect_base as usize;
        if !cfg.detect_always
            && !cfg
                .detect_patterns
                .iter()
                .any(|p| p.matches(m.mem.ram.as_ref(), base))
        {
            return Ok(None);
        }
        log.push(format!("{}: signature matched at ${base:04x}", cfg.source));

        // 2. Optional probe: actually run the cruncher to a checkpoint and
        //    verify the relocated code (CrunchAB).
        let mut probe_end = None;
        if let Some(probe) = &cfg.probe {
            m.cpu.reset_at(probe.entry);
            if !m.run_until(&[probe.target], probe.cap) {
                log.push(format!("probe never reached ${:04x}", probe.target));
                return Ok(None);
            }
            let end = m.mem.read_word(probe.end_ptr);
            if !probe
                .verify_pattern
                .matches(m.mem.ram.as_ref(), probe.verify_base as usize)
            {
                log.push("probe: relocated code did not verify".into());
                return Ok(None);
            }
            log.push(format!("probe ok: end=${end:04x}"));
            probe_end = Some(end);
        }

        // 3. Entry point (skipped when a probe already positioned the CPU).
        match cfg.entry {
            Entry::At(pc) => m.cpu.reset_at(pc),
            Entry::Sys => {
                let mut sys = sys_address(m.mem.ram.as_ref());
                if sys == 0 {
                    if let Some(fb) = entry_fallback {
                        log.push(format!(
                            "no parsable SYS line; using fallback entry ${fb:04x}"
                        ));
                        sys = fb;
                    } else {
                        log.push("signature matched but no SYS address found".into());
                        return Ok(None);
                    }
                }
                log.push(format!("entry: SYS {sys} (${sys:04x})"));
                m.cpu.reset_at(sys);
            }
            Entry::None => {}
        }

        // 4. Refinement variants, checked against the pristine RAM before the
        //    engine runs. The last matching variant wins.
        let mut variant = None;
        for (i, v) in cfg.variants.iter().enumerate() {
            if v.pattern.matches(m.mem.ram.as_ref(), v.base as usize) {
                variant = Some(i);
            }
        }
        if let Some(i) = variant {
            log.push(format!("variant matched: {}", cfg.variants[i].name));
        }

        Ok(Some(Detection {
            config: cfg,
            variant,
            machine: m,
            probe_end,
            log,
        }))
    }
}

impl Default for UniDecrunch {
    fn default() -> Self {
        Self::new()
    }
}

impl Detection<'_> {
    /// Best-known name before unpacking (variant name if one matched).
    pub fn name(&self) -> &str {
        match self.variant {
            Some(i) => &self.config.variants[i].name,
            None => &self.config.name,
        }
    }

    /// Run the cruncher's depacker to completion and extract the program.
    pub fn decrunch(mut self) -> Result<Decrunched, String> {
        let variant = self.variant.map(|i| &self.config.variants[i]);
        let r = engine::run(
            self.config,
            variant,
            self.probe_end,
            &mut self.machine,
            &mut self.log,
        );
        if !r.ok {
            return Err(format!(
                "detected as \"{}\" but the depacker did not finish:\n{}",
                self.name(),
                self.log.join("\n")
            ));
        }
        let cruncher = r.name.unwrap_or_else(|| self.name().to_string());
        let prg = self.machine.mem.save_prg(r.start, r.end)?;
        Ok(Decrunched {
            cruncher,
            start: r.start,
            end: r.end,
            real_start: r.real_start,
            jump_start: r.jump_start,
            prg,
            log: self.log,
        })
    }
}

impl Decrunched {
    pub fn save_prg_file(&self, path: &std::path::Path) -> Result<(), String> {
        std::fs::write(path, &self.prg).map_err(|e| format!("{}: {e}", path.display()))
    }
}
