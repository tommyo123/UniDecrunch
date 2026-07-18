//! Byte-pattern matching against emulated RAM.
//!
//! Patterns are written as whitespace-separated tokens in the cruncher config files:
//!
//! * `A9`   this exact byte must appear here
//! * `??`   any byte (wildcard)
//! * `*N`   a gap: skip up to N bytes (decimal) until the next exact byte matches;
//!   every occurrence of that anchor byte within the window is tried until the
//!   rest of the pattern matches

/// One parsed pattern token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tok {
    /// Exact byte value.
    Byte(u8),
    /// Any single byte.
    Any,
    /// Skip up to N bytes; the following token must be `Byte` (the anchor).
    Gap(usize),
}

/// A parsed pattern, ready to match.
#[derive(Clone, Debug, Default)]
pub struct Pattern {
    pub toks: Vec<Tok>,
}

impl Pattern {
    /// Parse a pattern string. Errors describe the offending token.
    pub fn parse(text: &str) -> Result<Pattern, String> {
        let mut toks = Vec::new();
        for raw in text.split_whitespace() {
            if raw == "??" {
                toks.push(Tok::Any);
            } else if let Some(n) = raw.strip_prefix('*') {
                let n: usize = n
                    .parse()
                    .map_err(|_| format!("bad gap token '{raw}' (want *N with decimal N)"))?;
                toks.push(Tok::Gap(n));
            } else if raw.len() <= 2 {
                let b = u8::from_str_radix(raw, 16)
                    .map_err(|_| format!("bad byte token '{raw}' (want two hex digits)"))?;
                toks.push(Tok::Byte(b));
            } else {
                return Err(format!("bad token '{raw}'"));
            }
        }
        // A gap must be followed by an exact byte to anchor the search.
        let mut it = toks.iter().peekable();
        while let Some(t) = it.next() {
            if matches!(t, Tok::Gap(_)) {
                match it.peek() {
                    Some(Tok::Byte(_)) => {}
                    Some(Tok::Gap(_)) => {} // consecutive gaps accumulate, checked next round
                    _ => return Err("a *N gap must be followed by an exact byte".into()),
                }
            }
        }
        Ok(Pattern { toks })
    }

    /// Match this pattern against `ram` starting at `start`.
    pub fn matches(&self, ram: &[u8], start: usize) -> bool {
        matches_from(&self.toks, ram, start)
    }
}

fn matches_from(toks: &[Tok], ram: &[u8], mut ti: usize) -> bool {
    let mut pi = 0;
    while pi < toks.len() {
        match toks[pi] {
            Tok::Byte(b) => {
                if ti >= ram.len() || ram[ti] != b {
                    return false;
                }
                ti += 1;
                pi += 1;
            }
            Tok::Any => {
                if ti >= ram.len() {
                    return false;
                }
                ti += 1;
                pi += 1;
            }
            Tok::Gap(_) => {
                // Accumulate consecutive gaps into one window.
                let mut max_skip = 0;
                while pi < toks.len() {
                    if let Tok::Gap(n) = toks[pi] {
                        max_skip += n;
                        pi += 1;
                    } else {
                        break;
                    }
                }
                let anchor = match toks.get(pi) {
                    Some(&Tok::Byte(b)) => b,
                    _ => return false, // gap with no anchor can't match
                };
                // Try every occurrence of the anchor within the window; on failure of
                // the tail, resume the search after that occurrence (backtracking).
                let limit = ti + max_skip;
                let mut search = ti;
                while search <= limit && search < ram.len() {
                    if ram[search] == anchor && matches_from(&toks[pi + 1..], ram, search + 1) {
                        return true;
                    }
                    search += 1;
                }
                return false;
            }
        }
    }
    true
}

/// Find the BASIC `SYS` start address the way the C64 would: locate the SYS token
/// ($9E) in the first BASIC line (searched at $0805-$0820), then read the decimal
/// digits that follow. Spaces and parentheses are skipped, so `SYS (2064)` (valid
/// BASIC that several crunchers emit) is handled.
pub fn sys_address(ram: &[u8]) -> u16 {
    const FIRST: usize = 0x0805;
    const LAST: usize = 0x0820;
    if ram.len() <= FIRST {
        return 0;
    }
    let end = LAST.min(ram.len() - 1);
    let Some(tok) = (FIRST..=end).find(|&i| ram[i] == 0x9E) else {
        return 0;
    };
    let mut addr: u32 = 0;
    let mut digits = 0;
    // Obfuscated form `SYS π*656`: the PETSCII π token ($FF) times a constant.
    // BASIC truncates the product (π*656 = 2060.99... -> 2060).
    let mut pi_multiplier = false;
    for &b in &ram[tok + 1..] {
        match b {
            b'0'..=b'9' => {
                addr = addr * 10 + (b - b'0') as u32;
                digits += 1;
                if addr > 0xFFFF {
                    return 0;
                }
            }
            // π token only valid as prefix (SYS π*656); anything after the
            // digits ends the expression.
            0xFF if digits == 0 && !pi_multiplier => {
                pi_multiplier = true;
            }
            0xAC | b'*' if pi_multiplier && digits == 0 => continue, // multiply
            b' ' | b'(' | b')' => continue,
            _ => break,
        }
    }
    if digits == 0 {
        0
    } else if pi_multiplier {
        (std::f64::consts::PI * addr as f64) as u16
    } else {
        addr as u16
    }
}

/// Heuristic for where a decrunched program really starts, used when the analyzed
/// write ranges begin below/around the BASIC start ($0801).
///
/// Priority: an exact $0801 hit wins; a plausible BASIC program (SYS line present,
/// or the classic `.. 08` next-line pointer at $0802) means $0801; otherwise skip
/// any zero padding and use the first non-zero byte. When the data does not hit
/// $0801, keep what the decruncher produced instead of forcing $0801.
pub fn guess_start(ram: &[u8], start: u16) -> u16 {
    if start == 0x0801 {
        return 0x0801;
    }
    if sys_address(ram) > 0x0801 {
        return 0x0801;
    }
    if ram.len() > 0x802 && ram[0x802] == 0x08 {
        return 0x0801;
    }
    let mut pos = start as usize;
    while pos < ram.len() {
        if ram[pos] != 0 {
            return pos as u16;
        }
        pos += 1;
    }
    start
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_match_exact_and_wildcard() {
        let p = Pattern::parse("A9 ?? 8D").unwrap();
        assert!(p.matches(&[0xA9, 0x42, 0x8D], 0));
        assert!(p.matches(&[0x00, 0xA9, 0xFF, 0x8D], 1));
        assert!(!p.matches(&[0xA9, 0x42, 0x8C], 0));
    }

    #[test]
    fn gap_searches_for_anchor() {
        // up to 768 filler bytes, then 4C 00 01
        let p = Pattern::parse("*8 4C 00 01").unwrap();
        let mut ram = vec![0xEAu8; 16];
        ram[5] = 0x4C;
        ram[6] = 0x00;
        ram[7] = 0x01;
        assert!(p.matches(&ram, 0));
        // anchor outside window
        let p2 = Pattern::parse("*3 4C 00 01").unwrap();
        assert!(!p2.matches(&ram, 0));
    }

    #[test]
    fn gap_backtracks_over_false_anchors() {
        // First 4C is a decoy (followed by wrong bytes); a later one matches.
        let p = Pattern::parse("*10 4C 00 01").unwrap();
        let ram = [
            0x4C, 0x12, 0x34, 0x4C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(p.matches(&ram, 0));
    }

    #[test]
    fn mid_pattern_gap() {
        // prefix, gap, then suffix
        let p = Pattern::parse("A9 01 *4 20 34 03").unwrap();
        assert!(p.matches(&[0xA9, 0x01, 0xEA, 0xEA, 0x20, 0x34, 0x03], 0));
    }

    #[test]
    fn sys_address_parses_digits_and_spaces() {
        let mut ram = vec![0u8; 0x900];
        // 0801: link ptr, line#, SYS token, " 2061", 0
        ram[0x801..0x80D].copy_from_slice(&[
            0x0B, 0x08, 0x0A, 0x00, 0x9E, b' ', b'2', b'0', b'6', b'1', 0x00, 0x00,
        ]);
        assert_eq!(sys_address(&ram), 2061);
    }

    #[test]
    fn sys_address_absent() {
        let ram = vec![0u8; 0x900];
        assert_eq!(sys_address(&ram), 0);
    }

    #[test]
    fn guess_start_prefers_0801_only_when_plausible() {
        let mut ram = vec![0u8; 0x1000];
        // no SYS, nothing at $0802: fall through to first non-zero byte
        ram[0x900] = 0x99;
        assert_eq!(guess_start(&ram, 0x8F0), 0x900);
        // classic BASIC link pointer at $0802 -> snap to $0801
        ram[0x802] = 0x08;
        assert_eq!(guess_start(&ram, 0x8F0), 0x0801);
    }
}
