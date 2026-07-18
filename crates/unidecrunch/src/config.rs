//! Cruncher config files: a small, dependency-free TOML subset.
//!
//! Supported syntax (see `configs/README.md` for the user-facing description):
//!   * `# comments`, blank lines
//!   * `key = value` at top level or under a `[section]` / `[[variant]]` header
//!   * values: `"string"`, integer (decimal or `0x` hex), `true`/`false`,
//!     and arrays of strings or integers (arrays may span multiple lines)
//!
//! `load_str` parses one file into a [`CruncherConfig`] with validation errors
//! that name the file and key.

use crate::pattern::Pattern;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineKind {
    Generic,
    TimeCruncher,
    CrunchAB,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// Read the start address from the BASIC SYS line, like RUN would.
    Sys,
    /// Fixed address.
    At(u16),
    /// No entry; execution state comes from the `[probe]` run (crunchab).
    None,
}

#[derive(Clone, Debug)]
pub struct VariantCfg {
    pub name: String,
    pub base: u16,
    pub pattern: Pattern,
    pub start_adjust: i32,
}

#[derive(Clone, Debug)]
pub struct ProbeCfg {
    pub entry: u16,
    pub target: u16,
    pub cap: u64,
    /// Address of the little-endian end pointer captured when `target` is reached.
    pub end_ptr: u16,
    pub verify_base: u16,
    pub verify_pattern: Pattern,
}

#[derive(Clone, Debug)]
pub struct CruncherConfig {
    /// Source file name (for error messages and listings).
    pub source: String,
    pub name: String,
    pub engine: EngineKind,

    pub detect_base: u16,
    /// Match unconditionally (last-resort catch-all definitions).
    pub detect_always: bool,
    pub detect_patterns: Vec<Pattern>,
    pub entry: Entry,
    pub probe: Option<ProbeCfg>,

    // engine parameters ([run])
    pub stop_pc: Vec<u16>,
    /// Alternative phase-1 stop: the PC dropping below this address means the
    /// relocated stub has taken over (covers whole families of stub addresses).
    pub stop_below: Option<u16>,
    pub exit_above: u16,
    pub snap_start: Vec<u16>,
    pub snap_to: u16,
    pub analyze_0100: bool,
    /// "Depack high, page-copy down" crunchers move whole pages, so the final
    /// range overshoots by up to 255 bytes while the staging range carries the
    /// exact payload size. When set, the end is trimmed accordingly.
    pub trim_page_overshoot: bool,
    /// Stricter phase-2 exit: the PC must not only rise above `exit_above` but
    /// land on an address the depacker itself wrote, jumping into the freshly
    /// unpacked program. For crunchers whose depack code lives inside the
    /// original file area (above `exit_above`).
    pub exit_into_written: bool,
    /// Quiescence-based phase-2 completion (instructions without a new unique
    /// write). Instead of stopping at the first plausible hand-off jump, run
    /// until the writes dry up and report the first plausible jump as the run
    /// address. This is the reliable strategy for nested multi-stage depackers
    /// that jump through their own output while unpacking. 0 = off.
    pub exit_quiescent: u64,
    pub byteboozer_ptr: Option<u8>,
    pub byteboozer_end_from_ptr: bool,
    pub byteboozer_name: String,
    pub use_guess_start: bool,
    pub version: u32,
    pub cap: u64,

    pub variants: Vec<VariantCfg>,
}

// ---------------------------------------------------------------------------
// raw parsing
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    StrArr(Vec<String>),
    IntArr(Vec<i64>),
}

type Table = Vec<(String, Value)>;

struct Raw {
    top: Table,
    sections: Vec<(String, Table)>,
    variants: Vec<Table>,
}

/// Strip a `#` comment that is outside of any quoted string.
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
    }
    line
}

fn parse_scalar(tok: &str) -> Result<Value, String> {
    let tok = tok.trim();
    if let Some(rest) = tok.strip_prefix('"') {
        let Some(inner) = rest.strip_suffix('"') else {
            return Err(format!("unterminated string: {tok}"));
        };
        return Ok(Value::Str(inner.to_string()));
    }
    match tok {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        _ => {}
    }
    let parsed = if let Some(hex) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16)
    } else {
        tok.parse::<i64>()
    };
    parsed
        .map(Value::Int)
        .map_err(|_| format!("bad value: {tok}"))
}

fn parse_array(body: &str) -> Result<Value, String> {
    let mut strs = Vec::new();
    let mut ints = Vec::new();
    // split on commas outside quotes
    let mut items = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    for c in body.chars() {
        match c {
            '"' => {
                in_str = !in_str;
                cur.push(c);
            }
            ',' if !in_str => {
                items.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    items.push(cur);
    for item in items {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        match parse_scalar(item)? {
            Value::Str(s) => strs.push(s),
            Value::Int(i) => ints.push(i),
            other => return Err(format!("unsupported array element: {other:?}")),
        }
    }
    if !strs.is_empty() && !ints.is_empty() {
        return Err("array mixes strings and integers".into());
    }
    if strs.is_empty() && ints.is_empty() {
        return Err("empty array".into());
    }
    if strs.is_empty() {
        Ok(Value::IntArr(ints))
    } else {
        Ok(Value::StrArr(strs))
    }
}

fn parse_raw(text: &str, source: &str) -> Result<Raw, String> {
    let mut raw = Raw {
        top: Vec::new(),
        sections: Vec::new(),
        variants: Vec::new(),
    };
    #[derive(PartialEq)]
    enum Ctx {
        Top,
        Section(usize),
        Variant(usize),
    }
    let mut ctx = Ctx::Top;

    let mut lines = text.lines().enumerate().peekable();
    while let Some((ln, line)) = lines.next() {
        let err = |msg: String| format!("{source}:{}: {msg}", ln + 1);
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
            if name.trim() != "variant" {
                return Err(err(format!(
                    "unknown array section [[{name}]] (only [[variant]])"
                )));
            }
            raw.variants.push(Vec::new());
            ctx = Ctx::Variant(raw.variants.len() - 1);
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            raw.sections.push((name.trim().to_string(), Vec::new()));
            ctx = Ctx::Section(raw.sections.len() - 1);
            continue;
        }
        let Some(eq) = line.find('=') else {
            return Err(err(format!("expected key = value, got: {line}")));
        };
        let key = line[..eq].trim().to_string();
        let mut vtext = line[eq + 1..].trim().to_string();
        if vtext.starts_with('[') {
            // consume lines until the closing bracket (outside strings)
            while !array_closed(&vtext) {
                let Some((_, more)) = lines.next() else {
                    return Err(err(format!("unterminated array for key {key}")));
                };
                vtext.push(' ');
                vtext.push_str(strip_comment(more).trim());
            }
            let body = vtext
                .trim()
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .ok_or_else(|| err(format!("malformed array for key {key}")))?;
            let val = parse_array(body).map_err(err)?;
            push_kv(&mut raw, &ctx, key, val);
        } else {
            let val = parse_scalar(&vtext).map_err(err)?;
            push_kv(&mut raw, &ctx, key, val);
        }
    }
    return Ok(raw);

    fn array_closed(text: &str) -> bool {
        let mut in_str = false;
        let mut depth = 0i32;
        for c in text.chars() {
            match c {
                '"' => in_str = !in_str,
                '[' if !in_str => depth += 1,
                ']' if !in_str => depth -= 1,
                _ => {}
            }
        }
        depth == 0
    }

    fn push_kv(raw: &mut Raw, ctx: &Ctx, key: String, val: Value) {
        match ctx {
            Ctx::Top => raw.top.push((key, val)),
            Ctx::Section(i) => raw.sections[*i].1.push((key, val)),
            Ctx::Variant(i) => raw.variants[*i].push((key, val)),
        }
    }
}

// ---------------------------------------------------------------------------
// typed extraction
// ---------------------------------------------------------------------------

fn get<'a>(t: &'a Table, key: &str) -> Option<&'a Value> {
    t.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn get_u16(t: &Table, key: &str, ctx: &str) -> Result<Option<u16>, String> {
    match get(t, key) {
        None => Ok(None),
        Some(Value::Int(i)) if (0..=0xFFFF).contains(i) => Ok(Some(*i as u16)),
        Some(v) => Err(format!("{ctx}: {key} must be a 16-bit integer, got {v:?}")),
    }
}

fn get_u64(t: &Table, key: &str, ctx: &str) -> Result<Option<u64>, String> {
    match get(t, key) {
        None => Ok(None),
        Some(Value::Int(i)) if *i >= 0 => Ok(Some(*i as u64)),
        Some(v) => Err(format!(
            "{ctx}: {key} must be a non-negative integer, got {v:?}"
        )),
    }
}

fn get_bool(t: &Table, key: &str, ctx: &str) -> Result<bool, String> {
    match get(t, key) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(v) => Err(format!("{ctx}: {key} must be true/false, got {v:?}")),
    }
}

fn get_str(t: &Table, key: &str, ctx: &str) -> Result<Option<String>, String> {
    match get(t, key) {
        None => Ok(None),
        Some(Value::Str(s)) => Ok(Some(s.clone())),
        Some(v) => Err(format!("{ctx}: {key} must be a string, got {v:?}")),
    }
}

/// `pattern` may be a single string or an array of strings joined by spaces.
fn get_pattern(t: &Table, key: &str, ctx: &str) -> Result<Option<Pattern>, String> {
    let text = match get(t, key) {
        None => return Ok(None),
        Some(Value::Str(s)) => s.clone(),
        Some(Value::StrArr(parts)) => parts.join(" "),
        Some(v) => Err(format!(
            "{ctx}: {key} must be a pattern string or array, got {v:?}"
        ))?,
    };
    Pattern::parse(&text)
        .map(Some)
        .map_err(|e| format!("{ctx}: {key}: {e}"))
}

fn get_u16_list(t: &Table, key: &str, ctx: &str) -> Result<Vec<u16>, String> {
    match get(t, key) {
        None => Ok(Vec::new()),
        Some(Value::Int(i)) if (0..=0xFFFF).contains(i) => Ok(vec![*i as u16]),
        Some(Value::IntArr(v)) => v
            .iter()
            .map(|i| {
                if (0..=0xFFFF).contains(i) {
                    Ok(*i as u16)
                } else {
                    Err(format!("{ctx}: {key}: {i} out of 16-bit range"))
                }
            })
            .collect(),
        Some(v) => Err(format!(
            "{ctx}: {key} must be an integer or integer array, got {v:?}"
        )),
    }
}

/// Parse one config file.
pub fn load_str(text: &str, source: &str) -> Result<CruncherConfig, String> {
    let raw = parse_raw(text, source)?;
    let ctx = source;

    let name = get_str(&raw.top, "name", ctx)?
        .ok_or_else(|| format!("{ctx}: missing top-level `name`"))?;
    let engine = match get_str(&raw.top, "engine", ctx)?.as_deref() {
        Some("generic") => EngineKind::Generic,
        Some("timecruncher") => EngineKind::TimeCruncher,
        Some("crunchab") => EngineKind::CrunchAB,
        Some(other) => return Err(format!("{ctx}: unknown engine \"{other}\"")),
        None => return Err(format!("{ctx}: missing top-level `engine`")),
    };

    let empty: Table = Vec::new();
    let detect = raw
        .sections
        .iter()
        .find(|(n, _)| n == "detect")
        .map(|(_, t)| t)
        .ok_or_else(|| format!("{ctx}: missing [detect] section"))?;
    let run = raw
        .sections
        .iter()
        .find(|(n, _)| n == "run")
        .map(|(_, t)| t)
        .unwrap_or(&empty);

    let detect_base = get_u16(detect, "base", ctx)?.unwrap_or(0x0801);
    let detect_always = get_bool(detect, "always", ctx)?;
    let mut detect_patterns = Vec::new();
    if let Some(p) = get_pattern(detect, "pattern", ctx)? {
        detect_patterns.push(p);
    }
    if let Some(Value::StrArr(list)) = get(detect, "any_of") {
        for (i, text) in list.iter().enumerate() {
            detect_patterns
                .push(Pattern::parse(text).map_err(|e| format!("{ctx}: any_of[{i}]: {e}"))?);
        }
    }
    if detect_patterns.is_empty() && !detect_always {
        return Err(format!(
            "{ctx}: [detect] needs `pattern`, `any_of` or `always = true`"
        ));
    }

    let entry = match get(detect, "entry") {
        None => Entry::None,
        Some(Value::Str(s)) if s == "sys" => Entry::Sys,
        Some(Value::Int(i)) if (0..=0xFFFF).contains(i) => Entry::At(*i as u16),
        Some(v) => {
            return Err(format!(
                "{ctx}: entry must be \"sys\" or an address, got {v:?}"
            ))
        }
    };

    let probe = match raw
        .sections
        .iter()
        .find(|(n, _)| n == "probe")
        .map(|(_, t)| t)
    {
        None => None,
        Some(t) => {
            let need = |k: &str| {
                get_u16(t, k, ctx)?.ok_or_else(|| format!("{ctx}: [probe] missing `{k}`"))
            };
            Some(ProbeCfg {
                entry: need("entry")?,
                target: need("target")?,
                cap: get_u64(t, "cap", ctx)?.unwrap_or(2_000_000),
                end_ptr: need("end_ptr")?,
                verify_base: need("verify_base")?,
                verify_pattern: get_pattern(t, "verify_pattern", ctx)?
                    .ok_or_else(|| format!("{ctx}: [probe] missing `verify_pattern`"))?,
            })
        }
    };

    if engine != EngineKind::CrunchAB && entry == Entry::None {
        return Err(format!(
            "{ctx}: [detect] needs `entry` for engine != crunchab"
        ));
    }
    if engine == EngineKind::CrunchAB && probe.is_none() {
        return Err(format!("{ctx}: engine crunchab needs a [probe] section"));
    }

    let mut variants = Vec::new();
    for (i, t) in raw.variants.iter().enumerate() {
        let vctx = format!("{ctx} [[variant]] #{}", i + 1);
        variants.push(VariantCfg {
            name: get_str(t, "name", &vctx)?.ok_or_else(|| format!("{vctx}: missing `name`"))?,
            base: get_u16(t, "base", &vctx)?.ok_or_else(|| format!("{vctx}: missing `base`"))?,
            pattern: get_pattern(t, "pattern", &vctx)?
                .ok_or_else(|| format!("{vctx}: missing `pattern`"))?,
            start_adjust: match get(t, "start_adjust") {
                None => 0,
                Some(Value::Int(v)) => *v as i32,
                Some(v) => {
                    return Err(format!(
                        "{vctx}: start_adjust must be an integer, got {v:?}"
                    ))
                }
            },
        });
    }

    let byteboozer_ptr = match get_u16(run, "byteboozer_ptr", ctx)? {
        Some(v) if v <= 0xFF => Some(v as u8),
        Some(v) => {
            return Err(format!(
                "{ctx}: byteboozer_ptr must be a zero-page address, got {v:#x}"
            ))
        }
        None => None,
    };

    Ok(CruncherConfig {
        source: source.to_string(),
        name,
        engine,
        detect_base,
        detect_always,
        detect_patterns,
        entry,
        probe,
        stop_pc: get_u16_list(run, "stop_pc", ctx)?,
        stop_below: get_u16(run, "stop_below", ctx)?,
        exit_above: get_u16(run, "exit_above", ctx)?.unwrap_or(0x0800),
        snap_start: get_u16_list(run, "snap_start", ctx)?,
        snap_to: get_u16(run, "snap_to", ctx)?.unwrap_or(0x0801),
        analyze_0100: get_bool(run, "analyze_0100", ctx)?,
        trim_page_overshoot: get_bool(run, "trim_page_overshoot", ctx)?,
        exit_into_written: get_bool(run, "exit_into_written", ctx)?,
        exit_quiescent: get_u64(run, "exit_quiescent", ctx)?.unwrap_or(0),
        byteboozer_ptr,
        byteboozer_end_from_ptr: get_bool(run, "byteboozer_end_from_ptr", ctx)?,
        byteboozer_name: get_str(run, "byteboozer_name", ctx)?
            .unwrap_or_else(|| "Byte Boozer".into()),
        use_guess_start: get_bool(run, "use_guess_start", ctx)?,
        version: get_u64(run, "version", ctx)?.unwrap_or(0) as u32,
        // Slow bit-oriented depackers (Shrinkler-class arithmetic coders run
        // ~2000 cycles per output byte) need well over 20M instructions for a
        // near-full 64 KB payload; 250M keeps them inside the cap while a
        // truly stuck depacker still fails over in a couple of seconds.
        cap: get_u64(run, "cap", ctx)?.unwrap_or(250_000_000),
        variants,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let cfg = load_str(
            r#"
# a comment
name = "Test"
engine = "generic"
[detect]
base = 0x0801
pattern = "*768 4C 00 01"
entry = "sys"
[run]
stop_pc = [0x0100, 0x0101]
exit_above = 0x0800
"#,
            "test.toml",
        )
        .unwrap();
        assert_eq!(cfg.name, "Test");
        assert_eq!(cfg.engine, EngineKind::Generic);
        assert_eq!(cfg.stop_pc, vec![0x100, 0x101]);
        assert_eq!(cfg.exit_above, 0x800);
        assert_eq!(cfg.entry, Entry::Sys);
    }

    #[test]
    fn multiline_pattern_array_and_variant() {
        let cfg = load_str(
            r#"
name = "T"
engine = "generic"
[detect]
pattern = [
    "A9 01",   # first line
    "8D 86 02",
]
entry = 0x0818
[[variant]]
name = "V"
base = 0x0900
start_adjust = 10
pattern = "AA BB"
"#,
            "t.toml",
        )
        .unwrap();
        assert_eq!(cfg.detect_patterns.len(), 1);
        assert_eq!(cfg.detect_patterns[0].toks.len(), 5);
        assert_eq!(cfg.variants.len(), 1);
        assert_eq!(cfg.variants[0].start_adjust, 10);
        assert_eq!(cfg.entry, Entry::At(0x0818));
    }

    #[test]
    fn errors_name_the_file_and_line() {
        let err = load_str("name = \"x\"\nengine = \"generic\"\nbad line\n", "f.toml").unwrap_err();
        assert!(err.contains("f.toml:3"), "{err}");
    }
}
