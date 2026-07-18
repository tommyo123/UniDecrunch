//! C64 memory: 64 KB RAM plus BASIC/KERNAL/CHARGEN ROM and the I/O area, banked
//! through the low three bits of the processor port at $0001 (LORAM/HIRAM/CHAREN).
//!
//! Banking follows the PLA table: BASIC needs LORAM && HIRAM, KERNAL needs HIRAM,
//! and $D000 shows I/O or CHARGEN (selected by CHAREN) whenever LORAM || HIRAM.
//! Writes always land in RAM (or the I/O area when it is banked in); ROM is never
//! writable, exactly like the real machine.

use crate::cpu::Bus;

pub struct C64Mem {
    pub ram: Box<[u8; 0x10000]>,
    pub basic: Box<[u8; 0x2000]>,
    pub kernal: Box<[u8; 0x2000]>,
    pub chargen: Box<[u8; 0x1000]>,
    /// $D000-$DFFF register space when I/O is banked in. No chip behavior is
    /// emulated; reads return the last value written (initially zero). The one
    /// exception is $D012 (VIC raster line), which counts up on every CPU read
    /// so raster-wait loops terminate.
    pub io: Box<[u8; 0x1000]>,
    /// Load address of the most recent `load_prg`.
    pub prg_start: u16,
    /// Last address occupied by the most recent `load_prg`.
    pub prg_end: u16,
}

const LORAM: u8 = 0x01;
const HIRAM: u8 = 0x02;
const CHAREN: u8 = 0x04;

impl C64Mem {
    /// Memory with empty ROM areas. $01 defaults to $37.
    pub fn new() -> Self {
        let mut m = C64Mem {
            ram: vec![0u8; 0x10000].into_boxed_slice().try_into().unwrap(),
            basic: vec![0u8; 0x2000].into_boxed_slice().try_into().unwrap(),
            kernal: vec![0u8; 0x2000].into_boxed_slice().try_into().unwrap(),
            chargen: vec![0u8; 0x1000].into_boxed_slice().try_into().unwrap(),
            io: vec![0u8; 0x1000].into_boxed_slice().try_into().unwrap(),
            prg_start: 0,
            prg_end: 0,
        };
        m.ram[0x0001] = 0x37;
        m
    }

    /// Set up the RAM state a program finds on a real C64 after boot, without
    /// running the reset sequence: BASIC memory pointers, the RAM vector tables
    /// at $0300/$0314 and the screen-editor basics.
    ///
    /// The CHRGET copy at $73-$8A is left zeroed on purpose. That zero-page area
    /// is prime depacker workspace and several crunchers rely on it starting at
    /// zero, while no depack path needs the interpreter's CHRGET.
    pub fn init_basic_env(&mut self) {
        // TXTTAB $0801.
        self.ram[0x2B] = 0x01;
        self.ram[0x2C] = 0x08;
        // FRETOP/MEMSIZ = $A000 (top of BASIC RAM).
        self.ram[0x33] = 0x00;
        self.ram[0x34] = 0xA0;
        self.ram[0x37] = 0x00;
        self.ram[0x38] = 0xA0;
        // TEMPPT: temporary string descriptor stack pointer starts at $19. At 0
        // the descriptor copy would overwrite the processor port and bank out
        // the ROMs mid-print.
        self.ram[0x16] = 0x19;
        // BASIC indirect vectors $0300-$030B (IERROR..IEVAL).
        self.ram[0x0300..0x030C].copy_from_slice(&[
            0x8B, 0xE3, 0x83, 0xA4, 0x7C, 0xA5, 0x1A, 0xA7, 0xE4, 0xA7, 0x86, 0xAE,
        ]);
        // KERNAL RAM vectors $0314-$0333 (IRQ..SAVE), power-on defaults.
        self.ram[0x0314..0x0334].copy_from_slice(&[
            0x31, 0xEA, 0x66, 0xFE, 0x47, 0xFE, 0x4A, 0xF3, 0x91, 0xF2, 0x0E, 0xF2, 0x50, 0xF2,
            0x33, 0xF3, 0x57, 0xF1, 0xCA, 0xF1, 0xED, 0xF6, 0x3E, 0xF1, 0x2F, 0xF3, 0x66, 0xFE,
            0xA5, 0xF4, 0xED, 0xF5,
        ]);
        // Screen editor: screen at $0400, current line pointer, lengths table.
        self.ram[0x0288] = 0x04;
        self.ram[0xD1] = 0x00;
        self.ram[0xD2] = 0x04;
        self.ram[0xD5] = 39;
        self.ram[0xC8] = 39;
    }

    /// Replace the KERNAL with RTS ($60) everywhere so any JSR into the ROM
    /// returns immediately, neutralizing KERNAL calls deterministically.
    ///
    /// Two entry points get real implementations so key/return prompts inside
    /// decrunchers terminate: GETIN ($FFE4) returns space (`LDA #$20 : RTS`) and
    /// CHRIN ($FFCF) returns a carriage return (`LDA #$0D : RTS`).
    pub fn stub_kernal(&mut self) {
        self.kernal.fill(0x60);
        self.kernal[0xFFE4 - 0xE000] = 0xA9; // LDA #$20
        self.kernal[0xFFE5 - 0xE000] = 0x20;
        self.kernal[0xFFE6 - 0xE000] = 0x60; // RTS
        self.kernal[0xFFCF - 0xE000] = 0xA9; // LDA #$0D
        self.kernal[0xFFD0 - 0xE000] = 0x0D;
        self.kernal[0xFFD1 - 0xE000] = 0x60; // RTS
    }

    fn ctrl(&self) -> u8 {
        self.ram[0x0001]
    }

    /// Whether a write to $D000-$DFFF goes to the I/O chips rather than the
    /// RAM underneath, given the current PLA banking (same condition as
    /// [`Bus::write`] uses to route such writes).
    pub fn io_visible(&self) -> bool {
        let c = self.ctrl();
        c & (LORAM | HIRAM) != 0 && c & CHAREN != 0
    }

    /// Read without side effects (usable while the CPU holds no borrow).
    pub fn peek(&self, addr: u16) -> u8 {
        let a = addr as usize;
        let c = self.ctrl();
        match a {
            0xA000..=0xBFFF if c & LORAM != 0 && c & HIRAM != 0 => self.basic[a - 0xA000],
            0xD000..=0xDFFF if c & (LORAM | HIRAM) != 0 => {
                if c & CHAREN != 0 {
                    self.io[a - 0xD000]
                } else {
                    self.chargen[a - 0xD000]
                }
            }
            0xE000..=0xFFFF if c & HIRAM != 0 => self.kernal[a - 0xE000],
            _ => self.ram[a],
        }
    }

    /// Banked little-endian word read (wraps at $FFFF like the CPU does).
    pub fn read_word(&self, addr: u16) -> u16 {
        let lo = self.peek(addr) as u16;
        let hi = self.peek(addr.wrapping_add(1)) as u16;
        (hi << 8) | lo
    }

    /// Load a PRG image (2-byte little-endian load address + data) into RAM.
    /// Mirrors what LOAD does on the real machine: VARTAB ($2D/$2E) and the KERNAL
    /// end-of-load pointer ($AE/$AF) are set to one past the last loaded byte.
    /// Returns (start, end): first and last occupied address.
    pub fn load_prg(&mut self, prg: &[u8]) -> Result<(u16, u16), String> {
        if prg.len() < 3 {
            return Err("file too small to be a PRG (needs load address + data)".into());
        }
        let start = u16::from_le_bytes([prg[0], prg[1]]) as usize;
        let data = &prg[2..];
        let end = start + data.len() - 1;
        if end > 0xFFFF {
            return Err(format!(
                "PRG overflows memory: start=${start:04X}, {} bytes, end=${end:X}",
                data.len()
            ));
        }
        self.ram[start..=end].copy_from_slice(data);
        self.prg_start = start as u16;
        self.prg_end = end as u16;
        // Like the KERNAL LOAD: VARTAB/ARYTAB/STREND and the end-of-load
        // pointer all point one past the last loaded byte.
        let after = (end as u16).wrapping_add(1);
        for lo in [0x2D, 0x2F, 0x31, 0xAE] {
            self.ram[lo] = after as u8;
            self.ram[lo + 1] = (after >> 8) as u8;
        }
        Ok((start as u16, end as u16))
    }

    pub fn load_prg_file(&mut self, path: &std::path::Path) -> Result<(u16, u16), String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        self.load_prg(&bytes)
    }

    /// Serialize RAM `start..=end` as a PRG image (load address + data).
    pub fn save_prg(&self, start: u16, end: u16) -> Result<Vec<u8>, String> {
        if start > end {
            return Err(format!(
                "invalid range: start ${start:04X} > end ${end:04X}"
            ));
        }
        let mut out = Vec::with_capacity((end - start) as usize + 3);
        out.extend_from_slice(&start.to_le_bytes());
        out.extend_from_slice(&self.ram[start as usize..=end as usize]);
        Ok(out)
    }

    pub fn save_prg_file(
        &self,
        path: &std::path::Path,
        start: u16,
        end: u16,
    ) -> Result<(), String> {
        let bytes = self.save_prg(start, end)?;
        std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
    }
}

impl Default for C64Mem {
    fn default() -> Self {
        Self::new()
    }
}

impl Bus for C64Mem {
    fn read(&mut self, addr: u16) -> u8 {
        // Fake raster progress: each CPU read of $D012 (with I/O banked in)
        // returns an incrementing line number, so raster waits terminate.
        if addr == 0xD012 {
            let c = self.ctrl();
            if c & (LORAM | HIRAM) != 0 && c & CHAREN != 0 {
                let v = self.io[0x012].wrapping_add(1);
                self.io[0x012] = v;
                return v;
            }
        }
        self.peek(addr)
    }

    fn write(&mut self, addr: u16, v: u8) {
        let a = addr as usize;
        let c = self.ctrl();
        // I/O registers take the write when banked in; everything else always
        // reaches the RAM underneath, even where ROM is visible.
        if (0xD000..=0xDFFF).contains(&a) && c & (LORAM | HIRAM) != 0 && c & CHAREN != 0 {
            self.io[a - 0xD000] = v;
        } else {
            self.ram[a] = v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banking_follows_pla_table() {
        let mut m = C64Mem::new();
        m.ram[0xA000] = 0x11;
        m.ram[0xD000] = 0x22;
        m.ram[0xE000] = 0x33;
        m.basic[0] = 0xA1;
        m.kernal[0] = 0xE1;
        m.chargen[0] = 0xC1;

        // $37 = LORAM+HIRAM+CHAREN: BASIC, I/O, KERNAL
        m.ram[1] = 0x37;
        assert_eq!(m.peek(0xA000), 0xA1);
        assert_eq!(m.peek(0xE000), 0xE1);
        assert_eq!(m.peek(0xD000), 0); // untouched I/O register

        // $35: RAM, I/O, RAM
        m.ram[1] = 0x35;
        assert_eq!(m.peek(0xA000), 0x11);
        assert_eq!(m.peek(0xE000), 0x33);

        // $34: all RAM
        m.ram[1] = 0x34;
        assert_eq!(m.peek(0xD000), 0x22);

        // $36: RAM, I/O, KERNAL
        m.ram[1] = 0x36;
        assert_eq!(m.peek(0xA000), 0x11);
        assert_eq!(m.peek(0xE000), 0xE1);

        // $32 (%010): RAM, CHARGEN, KERNAL
        m.ram[1] = 0x32;
        assert_eq!(m.peek(0xD000), 0xC1);
        assert_eq!(m.peek(0xE000), 0xE1);

        // $31 (%001): RAM, CHARGEN, RAM
        m.ram[1] = 0x31;
        assert_eq!(m.peek(0xD000), 0xC1);
        assert_eq!(m.peek(0xE000), 0x33);
    }

    #[test]
    fn writes_reach_ram_under_rom() {
        let mut m = C64Mem::new();
        m.kernal[0x123] = 0xE1;
        m.ram[1] = 0x37;
        m.write(0xE123, 0x99);
        assert_eq!(m.peek(0xE123), 0xE1); // ROM area is still visible
        assert_eq!(m.ram[0xE123], 0x99); // but RAM took the write
    }

    #[test]
    fn prg_roundtrip_and_vartab() {
        let mut m = C64Mem::new();
        let prg = [0x01, 0x08, 0xAA, 0xBB, 0xCC];
        let (s, e) = m.load_prg(&prg).unwrap();
        assert_eq!((s, e), (0x0801, 0x0803));
        assert_eq!(m.read_word(0x2D), 0x0804);
        assert_eq!(m.read_word(0xAE), 0x0804);
        assert_eq!(m.save_prg(0x0801, 0x0803).unwrap(), prg);
    }
}
