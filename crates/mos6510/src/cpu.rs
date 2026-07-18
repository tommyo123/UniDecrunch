//! NMOS 6502 / 6510 core.
//!
//! The core drives memory through a `Bus` trait (so it can bank C64 memory) and
//! implements:
//!   * the full opcode map: every documented opcode plus all stable undocumented
//!     opcodes (SLO RLA SRE RRA SAX LAX DCP ISC ANC ALR ARR SBX ANE LAS TAS SHA
//!     SHX SHY, LAX #imm, SBC #$EB, the multi-byte NOPs and the JAM/KIL group)
//!   * decimal (BCD) mode for ADC/SBC with NMOS flag semantics: decimal ADC/SBC
//!     set Z/N/V like the real NMOS part, and RRA/ISC honor the D flag
//!   * per-instruction memory-access tracking (`MemOp`) for write-range analysis,
//!     including the writes made by illegal RMW/store opcodes such as SAX or DCP
//!
//! Cycle counting uses correct per-opcode base cycles, +1 for indexed reads that
//! cross a page, and +1 for taken branches (+1 more across a page). RMW and store
//! forms use their fixed worst-case counts. `instructions` counts executed
//! instructions separately, which is the unit the detection heuristics use.

/// Memory bus the CPU talks to. Instruction fetches, stack and pointer reads all go
/// through the bus, so banked memory (`C64Mem`) behaves like the real machine.
pub trait Bus {
    fn read(&mut self, addr: u16) -> u8;
    fn write(&mut self, addr: u16, v: u8);
}

/// Addressing mode of a tracked memory access.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddrMode {
    ZeroPage,
    ZeroPageX,
    ZeroPageY,
    Absolute,
    AbsoluteX,
    AbsoluteY,
    /// (zp,X) pre-indexed indirect
    IndirectX,
    /// (zp),Y post-indexed indirect
    IndirectY,
}

impl AddrMode {
    /// True for the two indirect-via-zero-page modes. Decrunchers copy their output
    /// through these, which is why write-range analysis treats them specially.
    pub fn is_indirect(self) -> bool {
        matches!(self, AddrMode::IndirectX | AddrMode::IndirectY)
    }

    pub fn name(self) -> &'static str {
        match self {
            AddrMode::ZeroPage => "zp",
            AddrMode::ZeroPageX => "zp,x",
            AddrMode::ZeroPageY => "zp,y",
            AddrMode::Absolute => "abs",
            AddrMode::AbsoluteX => "abs,x",
            AddrMode::AbsoluteY => "abs,y",
            AddrMode::IndirectX => "(zp,x)",
            AddrMode::IndirectY => "(zp),y",
        }
    }
}

/// One tracked memory access performed by the last executed instruction.
#[derive(Clone, Copy, Debug)]
pub struct MemOp {
    pub write: bool,
    pub mode: AddrMode,
    pub addr: u16,
    pub value: u8,
    /// For the indirect modes: the zero-page operand byte of the instruction
    /// (the pointer location, before X pre-indexing). 0 for direct modes.
    /// Write-range analysis groups indirect writes by this pointer.
    pub ptr: u8,
    /// The access came from an undocumented opcode. Analyzers may want to
    /// filter these; the write-range heuristics exclude them by default.
    pub illegal: bool,
}

/// True for every undocumented ("illegal") opcode on the NMOS 6510.
pub fn is_undocumented(op: u8) -> bool {
    match op {
        // SLO RLA SRE RRA SAX LAX DCP ISC families (low nibble 3/7, plus B/F rows)
        0x03 | 0x07 | 0x0F | 0x13 | 0x17 | 0x1B | 0x1F | // SLO
        0x23 | 0x27 | 0x2F | 0x33 | 0x37 | 0x3B | 0x3F | // RLA
        0x43 | 0x47 | 0x4F | 0x53 | 0x57 | 0x5B | 0x5F | // SRE
        0x63 | 0x67 | 0x6F | 0x73 | 0x77 | 0x7B | 0x7F | // RRA
        0x83 | 0x87 | 0x8F | 0x97 |                       // SAX
        0xA3 | 0xA7 | 0xAB | 0xAF | 0xB3 | 0xB7 | 0xBF | // LAX
        0xC3 | 0xC7 | 0xCF | 0xD3 | 0xD7 | 0xDB | 0xDF | // DCP
        0xE3 | 0xE7 | 0xEB | 0xEF | 0xF3 | 0xF7 | 0xFB | 0xFF | // ISC (+SBC $EB)
        0x0B | 0x2B | 0x4B | 0x6B | 0x8B | 0xCB |         // ANC ALR ARR ANE SBX
        0x93 | 0x9B | 0x9C | 0x9E | 0x9F | 0xBB |         // SHA TAS SHY SHX LAS
        0x80 | 0x82 | 0x89 | 0xC2 | 0xE2 |                // NOP #imm
        0x04 | 0x44 | 0x64 |                              // NOP zp
        0x14 | 0x34 | 0x54 | 0x74 | 0xD4 | 0xF4 |         // NOP zp,x
        0x0C | 0x1C | 0x3C | 0x5C | 0x7C | 0xDC | 0xFC |  // NOP abs / abs,x
        0x1A | 0x3A | 0x5A | 0x7A | 0xDA | 0xFA |         // NOP implied
        0x02 | 0x12 | 0x22 | 0x32 | 0x42 | 0x52 | 0x62 | 0x72 |
        0x92 | 0xB2 | 0xD2 | 0xF2                         // JAM
        => true,
        _ => false,
    }
}

// Status flag bit masks.
const C: u8 = 0x01;
const Z: u8 = 0x02;
const I: u8 = 0x04;
const D: u8 = 0x08;
const B: u8 = 0x10;
const U: u8 = 0x20; // unused, always 1
const V: u8 = 0x40;
const N: u8 = 0x80;

pub struct Cpu {
    pub a: u8,
    pub x: u8,
    pub y: u8,
    pub sp: u8,
    pub pc: u16,
    pub p: u8, // NV-BDIZC
    /// Real 6502 cycles, including page-cross and branch penalties.
    pub cycles: u64,
    /// Executed instruction count (the unit UniDecrunch heuristics are calibrated in).
    pub instructions: u64,
    /// A JAM/KIL opcode was executed; the CPU is halted for good.
    pub jammed: bool,
    /// BRK was executed while `brk_stops` is true.
    pub brk_hit: bool,
    /// When true (default), BRK halts execution, treating it as a program that
    /// ran off the rails. When false, BRK vectors through $FFFE like real hardware.
    pub brk_stops: bool,
    /// Enable memory-access tracking (`last_op`). Off by default; it costs a little.
    pub tracked: bool,
    /// The memory access performed by the last `step()`, if tracking is on and the
    /// instruction touched memory through an addressing mode. For read-modify-write
    /// instructions the *write* is recorded.
    pub last_op: Option<MemOp>,
    /// Zero-page operand of the most recent indirect effective-address resolution.
    zp_operand: u8,
    /// Opcode currently being executed (for MemOp::illegal classification).
    current_opcode: u8,
}

impl Cpu {
    pub fn new() -> Self {
        Cpu {
            a: 0,
            x: 0,
            y: 0,
            sp: 0xFF,
            pc: 0,
            p: U,
            cycles: 0,
            instructions: 0,
            jammed: false,
            brk_hit: false,
            brk_stops: true,
            tracked: false,
            last_op: None,
            zp_operand: 0,
            current_opcode: 0,
        }
    }

    /// Prepare the CPU to run code at `pc`: SP=$FF, P=%00100000, A=X=Y=0,
    /// counters cleared.
    pub fn reset_at(&mut self, pc: u16) {
        self.pc = pc;
        self.sp = 0xFF;
        self.p = U;
        self.a = 0;
        self.x = 0;
        self.y = 0;
        self.cycles = 0;
        self.instructions = 0;
        self.jammed = false;
        self.brk_hit = false;
        self.last_op = None;
    }

    /// True while the CPU can keep executing (not jammed, no stopping BRK executed).
    pub fn running(&self) -> bool {
        !self.jammed && !self.brk_hit
    }

    #[inline]
    fn set_zn(&mut self, v: u8) {
        if v == 0 {
            self.p |= Z
        } else {
            self.p &= !Z
        }
        if v & 0x80 != 0 {
            self.p |= N
        } else {
            self.p &= !N
        }
    }
    #[inline]
    fn flag(&self, m: u8) -> bool {
        self.p & m != 0
    }
    #[inline]
    fn setf(&mut self, m: u8, on: bool) {
        if on {
            self.p |= m
        } else {
            self.p &= !m
        }
    }

    #[inline]
    fn fetch(&mut self, bus: &mut impl Bus) -> u8 {
        let v = bus.read(self.pc);
        self.pc = self.pc.wrapping_add(1);
        v
    }
    #[inline]
    fn fetch16(&mut self, bus: &mut impl Bus) -> u16 {
        let lo = self.fetch(bus) as u16;
        let hi = self.fetch(bus) as u16;
        (hi << 8) | lo
    }

    #[inline]
    fn push(&mut self, bus: &mut impl Bus, v: u8) {
        bus.write(0x0100 | self.sp as u16, v);
        self.sp = self.sp.wrapping_sub(1);
    }
    #[inline]
    fn pop(&mut self, bus: &mut impl Bus) -> u8 {
        self.sp = self.sp.wrapping_add(1);
        bus.read(0x0100 | self.sp as u16)
    }

    // Effective-address resolution. Returns (address, page_crossed); page_crossed is
    // only meaningful for AbsoluteX/AbsoluteY/IndirectY reads.
    fn ea(&mut self, bus: &mut impl Bus, m: AddrMode) -> (u16, bool) {
        match m {
            AddrMode::ZeroPage => (self.fetch(bus) as u16, false),
            AddrMode::ZeroPageX => ((self.fetch(bus).wrapping_add(self.x)) as u16, false),
            AddrMode::ZeroPageY => ((self.fetch(bus).wrapping_add(self.y)) as u16, false),
            AddrMode::Absolute => (self.fetch16(bus), false),
            AddrMode::AbsoluteX => {
                let b = self.fetch16(bus);
                let a = b.wrapping_add(self.x as u16);
                (a, (b & 0xFF00) != (a & 0xFF00))
            }
            AddrMode::AbsoluteY => {
                let b = self.fetch16(bus);
                let a = b.wrapping_add(self.y as u16);
                (a, (b & 0xFF00) != (a & 0xFF00))
            }
            AddrMode::IndirectX => {
                let operand = self.fetch(bus);
                self.zp_operand = operand;
                let zp = operand.wrapping_add(self.x);
                let lo = bus.read(zp as u16) as u16;
                let hi = bus.read(zp.wrapping_add(1) as u16) as u16;
                ((hi << 8) | lo, false)
            }
            AddrMode::IndirectY => {
                let zp = self.fetch(bus);
                self.zp_operand = zp;
                let lo = bus.read(zp as u16) as u16;
                let hi = bus.read(zp.wrapping_add(1) as u16) as u16;
                let base = (hi << 8) | lo;
                let a = base.wrapping_add(self.y as u16);
                (a, (base & 0xFF00) != (a & 0xFF00))
            }
        }
    }

    #[inline]
    fn track(&mut self, write: bool, mode: AddrMode, addr: u16, value: u8) {
        if self.tracked {
            let ptr = if mode.is_indirect() {
                self.zp_operand
            } else {
                0
            };
            let illegal = is_undocumented(self.current_opcode);
            self.last_op = Some(MemOp {
                write,
                mode,
                addr,
                value,
                ptr,
                illegal,
            });
        }
    }

    /// Read an operand through an addressing mode; tracks the read and charges cycles.
    fn load(&mut self, bus: &mut impl Bus, m: AddrMode) -> u8 {
        let (addr, crossed) = self.ea(bus, m);
        let v = bus.read(addr);
        self.track(false, m, addr, v);
        self.cycles += match m {
            AddrMode::ZeroPage => 3,
            AddrMode::ZeroPageX | AddrMode::ZeroPageY => 4,
            AddrMode::Absolute => 4,
            AddrMode::AbsoluteX | AddrMode::AbsoluteY => 4 + crossed as u64,
            AddrMode::IndirectX => 6,
            AddrMode::IndirectY => 5 + crossed as u64,
        };
        v
    }

    /// Write a value through an addressing mode; tracks the write and charges cycles.
    fn store(&mut self, bus: &mut impl Bus, m: AddrMode, v: u8) {
        let (addr, _) = self.ea(bus, m);
        bus.write(addr, v);
        self.track(true, m, addr, v);
        self.cycles += match m {
            AddrMode::ZeroPage => 3,
            AddrMode::ZeroPageX | AddrMode::ZeroPageY => 4,
            AddrMode::Absolute => 4,
            AddrMode::AbsoluteX | AddrMode::AbsoluteY => 5,
            AddrMode::IndirectX | AddrMode::IndirectY => 6,
        };
    }

    /// Read-modify-write through an addressing mode. `f` maps the old value to the new
    /// one (and may set flags). The *write* is tracked; fixed worst-case cycles.
    fn rmw(&mut self, bus: &mut impl Bus, m: AddrMode, f: impl FnOnce(&mut Self, u8) -> u8) -> u8 {
        let (addr, _) = self.ea(bus, m);
        let old = bus.read(addr);
        let new = f(self, old);
        bus.write(addr, new);
        self.track(true, m, addr, new);
        self.cycles += match m {
            AddrMode::ZeroPage => 5,
            AddrMode::ZeroPageX | AddrMode::ZeroPageY => 6,
            AddrMode::Absolute => 6,
            AddrMode::AbsoluteX | AddrMode::AbsoluteY => 7,
            AddrMode::IndirectX | AddrMode::IndirectY => 8,
        };
        new
    }

    #[inline]
    fn branch(&mut self, bus: &mut impl Bus, take: bool) {
        let off = self.fetch(bus) as i8 as i16;
        self.cycles += 2;
        if take {
            let old = self.pc;
            let new = (self.pc as i16).wrapping_add(off) as u16;
            self.pc = new;
            self.cycles += 1;
            if (old & 0xFF00) != (new & 0xFF00) {
                self.cycles += 1;
            }
        }
    }

    /// ADC with NMOS binary and decimal behavior.
    fn adc(&mut self, m: u8) {
        let c = self.flag(C) as u16;
        let a = self.a as u16;
        let mv = m as u16;
        if self.flag(D) {
            // NMOS BCD: Z from the binary sum; N/V from the intermediate high nibble.
            let bin = a + mv + c;
            self.setf(Z, bin as u8 == 0);
            let mut lo = (a & 0x0F) + (mv & 0x0F) + c;
            if lo > 9 {
                lo += 6;
            }
            let mut hi = (a >> 4) + (mv >> 4) + (lo > 0x0F) as u16;
            self.setf(N, (hi & 0x08) != 0);
            self.setf(V, ((a ^ (hi << 4)) & !(a ^ mv) & 0x80) != 0);
            if hi > 9 {
                hi += 6;
            }
            self.setf(C, hi > 0x0F);
            self.a = (((hi & 0x0F) << 4) | (lo & 0x0F)) as u8;
        } else {
            let sum = a + mv + c;
            let r = sum as u8;
            self.setf(C, sum > 0xFF);
            self.setf(V, ((a ^ r as u16) & (mv ^ r as u16) & 0x80) != 0);
            self.a = r;
            self.set_zn(r);
        }
    }

    /// SBC with NMOS binary and decimal behavior (flags always from the binary result).
    fn sbc(&mut self, m: u8) {
        let c = self.flag(C) as i16;
        let a = self.a as i16;
        let mv = m as i16;
        let bin = a - mv - (1 - c);
        let r = bin as u8;
        self.setf(C, bin >= 0);
        self.setf(V, ((a ^ mv) & (a ^ bin) & 0x80) != 0);
        if self.flag(D) {
            let mut lo = (a & 0x0F) - (mv & 0x0F) - (1 - c);
            let mut hi = (a >> 4) - (mv >> 4);
            if lo < 0 {
                lo -= 6;
                hi -= 1;
            }
            if hi < 0 {
                hi -= 6;
            }
            self.a = (((hi as u8) & 0x0F) << 4) | (lo as u8 & 0x0F);
            self.set_zn(r); // Z/N from binary result on NMOS
        } else {
            self.a = r;
            self.set_zn(r);
        }
    }

    fn cmp_reg(&mut self, reg: u8, m: u8) {
        let r = reg.wrapping_sub(m);
        self.setf(C, reg >= m);
        self.set_zn(r);
    }

    // ---- shared shift/rotate kernels (used by both legal RMW and the illegals) ----
    fn asl_val(&mut self, v: u8) -> u8 {
        self.setf(C, v & 0x80 != 0);
        let r = v << 1;
        self.set_zn(r);
        r
    }
    fn lsr_val(&mut self, v: u8) -> u8 {
        self.setf(C, v & 1 != 0);
        let r = v >> 1;
        self.set_zn(r);
        r
    }
    fn rol_val(&mut self, v: u8) -> u8 {
        let oc = self.flag(C) as u8;
        self.setf(C, v & 0x80 != 0);
        let r = (v << 1) | oc;
        self.set_zn(r);
        r
    }
    fn ror_val(&mut self, v: u8) -> u8 {
        let oc = (self.flag(C) as u8) << 7;
        self.setf(C, v & 1 != 0);
        let r = (v >> 1) | oc;
        self.set_zn(r);
        r
    }

    /// Execute one instruction. Returns `running()`: false once the CPU jammed or
    /// a stopping BRK was executed (further calls are no-ops returning false).
    pub fn step(&mut self, bus: &mut impl Bus) -> bool {
        if !self.running() {
            return false;
        }
        if self.tracked {
            self.last_op = None;
        }
        let op = self.fetch(bus);
        self.current_opcode = op;
        self.exec(bus, op);
        self.instructions += 1;
        self.running()
    }

    fn exec(&mut self, bus: &mut impl Bus, op: u8) {
        use AddrMode::*;
        match op {
            // ---- LDA ----
            0xA9 => {
                let v = self.fetch(bus);
                self.a = v;
                self.set_zn(v);
                self.cycles += 2;
            }
            0xA5 => {
                let v = self.load(bus, ZeroPage);
                self.a = v;
                self.set_zn(v);
            }
            0xB5 => {
                let v = self.load(bus, ZeroPageX);
                self.a = v;
                self.set_zn(v);
            }
            0xAD => {
                let v = self.load(bus, Absolute);
                self.a = v;
                self.set_zn(v);
            }
            0xBD => {
                let v = self.load(bus, AbsoluteX);
                self.a = v;
                self.set_zn(v);
            }
            0xB9 => {
                let v = self.load(bus, AbsoluteY);
                self.a = v;
                self.set_zn(v);
            }
            0xA1 => {
                let v = self.load(bus, IndirectX);
                self.a = v;
                self.set_zn(v);
            }
            0xB1 => {
                let v = self.load(bus, IndirectY);
                self.a = v;
                self.set_zn(v);
            }

            // ---- LDX ----
            0xA2 => {
                let v = self.fetch(bus);
                self.x = v;
                self.set_zn(v);
                self.cycles += 2;
            }
            0xA6 => {
                let v = self.load(bus, ZeroPage);
                self.x = v;
                self.set_zn(v);
            }
            0xB6 => {
                let v = self.load(bus, ZeroPageY);
                self.x = v;
                self.set_zn(v);
            }
            0xAE => {
                let v = self.load(bus, Absolute);
                self.x = v;
                self.set_zn(v);
            }
            0xBE => {
                let v = self.load(bus, AbsoluteY);
                self.x = v;
                self.set_zn(v);
            }

            // ---- LDY ----
            0xA0 => {
                let v = self.fetch(bus);
                self.y = v;
                self.set_zn(v);
                self.cycles += 2;
            }
            0xA4 => {
                let v = self.load(bus, ZeroPage);
                self.y = v;
                self.set_zn(v);
            }
            0xB4 => {
                let v = self.load(bus, ZeroPageX);
                self.y = v;
                self.set_zn(v);
            }
            0xAC => {
                let v = self.load(bus, Absolute);
                self.y = v;
                self.set_zn(v);
            }
            0xBC => {
                let v = self.load(bus, AbsoluteX);
                self.y = v;
                self.set_zn(v);
            }

            // ---- STA / STX / STY ----
            0x85 => {
                let v = self.a;
                self.store(bus, ZeroPage, v);
            }
            0x95 => {
                let v = self.a;
                self.store(bus, ZeroPageX, v);
            }
            0x8D => {
                let v = self.a;
                self.store(bus, Absolute, v);
            }
            0x9D => {
                let v = self.a;
                self.store(bus, AbsoluteX, v);
            }
            0x99 => {
                let v = self.a;
                self.store(bus, AbsoluteY, v);
            }
            0x81 => {
                let v = self.a;
                self.store(bus, IndirectX, v);
            }
            0x91 => {
                let v = self.a;
                self.store(bus, IndirectY, v);
            }
            0x86 => {
                let v = self.x;
                self.store(bus, ZeroPage, v);
            }
            0x96 => {
                let v = self.x;
                self.store(bus, ZeroPageY, v);
            }
            0x8E => {
                let v = self.x;
                self.store(bus, Absolute, v);
            }
            0x84 => {
                let v = self.y;
                self.store(bus, ZeroPage, v);
            }
            0x94 => {
                let v = self.y;
                self.store(bus, ZeroPageX, v);
            }
            0x8C => {
                let v = self.y;
                self.store(bus, Absolute, v);
            }

            // ---- Transfers ----
            0xAA => {
                self.x = self.a;
                let v = self.x;
                self.set_zn(v);
                self.cycles += 2;
            }
            0xA8 => {
                self.y = self.a;
                let v = self.y;
                self.set_zn(v);
                self.cycles += 2;
            }
            0x8A => {
                self.a = self.x;
                let v = self.a;
                self.set_zn(v);
                self.cycles += 2;
            }
            0x98 => {
                self.a = self.y;
                let v = self.a;
                self.set_zn(v);
                self.cycles += 2;
            }
            0xBA => {
                self.x = self.sp;
                let v = self.x;
                self.set_zn(v);
                self.cycles += 2;
            }
            0x9A => {
                self.sp = self.x;
                self.cycles += 2;
            }

            // ---- Stack ----
            0x48 => {
                let v = self.a;
                self.push(bus, v);
                self.cycles += 3;
            }
            0x68 => {
                let v = self.pop(bus);
                self.a = v;
                self.set_zn(v);
                self.cycles += 4;
            }
            0x08 => {
                let v = self.p | B | U;
                self.push(bus, v);
                self.cycles += 3;
            }
            0x28 => {
                let v = self.pop(bus);
                self.p = (v & !B) | U;
                self.cycles += 4;
            }

            // ---- AND ----
            0x29 => {
                let v = self.fetch(bus);
                self.a &= v;
                let r = self.a;
                self.set_zn(r);
                self.cycles += 2;
            }
            0x25 => {
                let v = self.load(bus, ZeroPage);
                self.a &= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x35 => {
                let v = self.load(bus, ZeroPageX);
                self.a &= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x2D => {
                let v = self.load(bus, Absolute);
                self.a &= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x3D => {
                let v = self.load(bus, AbsoluteX);
                self.a &= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x39 => {
                let v = self.load(bus, AbsoluteY);
                self.a &= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x21 => {
                let v = self.load(bus, IndirectX);
                self.a &= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x31 => {
                let v = self.load(bus, IndirectY);
                self.a &= v;
                let r = self.a;
                self.set_zn(r);
            }

            // ---- ORA ----
            0x09 => {
                let v = self.fetch(bus);
                self.a |= v;
                let r = self.a;
                self.set_zn(r);
                self.cycles += 2;
            }
            0x05 => {
                let v = self.load(bus, ZeroPage);
                self.a |= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x15 => {
                let v = self.load(bus, ZeroPageX);
                self.a |= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x0D => {
                let v = self.load(bus, Absolute);
                self.a |= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x1D => {
                let v = self.load(bus, AbsoluteX);
                self.a |= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x19 => {
                let v = self.load(bus, AbsoluteY);
                self.a |= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x01 => {
                let v = self.load(bus, IndirectX);
                self.a |= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x11 => {
                let v = self.load(bus, IndirectY);
                self.a |= v;
                let r = self.a;
                self.set_zn(r);
            }

            // ---- EOR ----
            0x49 => {
                let v = self.fetch(bus);
                self.a ^= v;
                let r = self.a;
                self.set_zn(r);
                self.cycles += 2;
            }
            0x45 => {
                let v = self.load(bus, ZeroPage);
                self.a ^= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x55 => {
                let v = self.load(bus, ZeroPageX);
                self.a ^= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x4D => {
                let v = self.load(bus, Absolute);
                self.a ^= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x5D => {
                let v = self.load(bus, AbsoluteX);
                self.a ^= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x59 => {
                let v = self.load(bus, AbsoluteY);
                self.a ^= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x41 => {
                let v = self.load(bus, IndirectX);
                self.a ^= v;
                let r = self.a;
                self.set_zn(r);
            }
            0x51 => {
                let v = self.load(bus, IndirectY);
                self.a ^= v;
                let r = self.a;
                self.set_zn(r);
            }

            // ---- BIT ----
            0x24 => {
                let v = self.load(bus, ZeroPage);
                let r = self.a & v;
                self.setf(Z, r == 0);
                self.setf(N, v & 0x80 != 0);
                self.setf(V, v & 0x40 != 0);
            }
            0x2C => {
                let v = self.load(bus, Absolute);
                let r = self.a & v;
                self.setf(Z, r == 0);
                self.setf(N, v & 0x80 != 0);
                self.setf(V, v & 0x40 != 0);
            }

            // ---- ADC ----
            0x69 => {
                let v = self.fetch(bus);
                self.adc(v);
                self.cycles += 2;
            }
            0x65 => {
                let v = self.load(bus, ZeroPage);
                self.adc(v);
            }
            0x75 => {
                let v = self.load(bus, ZeroPageX);
                self.adc(v);
            }
            0x6D => {
                let v = self.load(bus, Absolute);
                self.adc(v);
            }
            0x7D => {
                let v = self.load(bus, AbsoluteX);
                self.adc(v);
            }
            0x79 => {
                let v = self.load(bus, AbsoluteY);
                self.adc(v);
            }
            0x61 => {
                let v = self.load(bus, IndirectX);
                self.adc(v);
            }
            0x71 => {
                let v = self.load(bus, IndirectY);
                self.adc(v);
            }

            // ---- SBC (0xEB is the illegal immediate twin) ----
            0xE9 | 0xEB => {
                let v = self.fetch(bus);
                self.sbc(v);
                self.cycles += 2;
            }
            0xE5 => {
                let v = self.load(bus, ZeroPage);
                self.sbc(v);
            }
            0xF5 => {
                let v = self.load(bus, ZeroPageX);
                self.sbc(v);
            }
            0xED => {
                let v = self.load(bus, Absolute);
                self.sbc(v);
            }
            0xFD => {
                let v = self.load(bus, AbsoluteX);
                self.sbc(v);
            }
            0xF9 => {
                let v = self.load(bus, AbsoluteY);
                self.sbc(v);
            }
            0xE1 => {
                let v = self.load(bus, IndirectX);
                self.sbc(v);
            }
            0xF1 => {
                let v = self.load(bus, IndirectY);
                self.sbc(v);
            }

            // ---- CMP / CPX / CPY ----
            0xC9 => {
                let v = self.fetch(bus);
                let a = self.a;
                self.cmp_reg(a, v);
                self.cycles += 2;
            }
            0xC5 => {
                let v = self.load(bus, ZeroPage);
                let a = self.a;
                self.cmp_reg(a, v);
            }
            0xD5 => {
                let v = self.load(bus, ZeroPageX);
                let a = self.a;
                self.cmp_reg(a, v);
            }
            0xCD => {
                let v = self.load(bus, Absolute);
                let a = self.a;
                self.cmp_reg(a, v);
            }
            0xDD => {
                let v = self.load(bus, AbsoluteX);
                let a = self.a;
                self.cmp_reg(a, v);
            }
            0xD9 => {
                let v = self.load(bus, AbsoluteY);
                let a = self.a;
                self.cmp_reg(a, v);
            }
            0xC1 => {
                let v = self.load(bus, IndirectX);
                let a = self.a;
                self.cmp_reg(a, v);
            }
            0xD1 => {
                let v = self.load(bus, IndirectY);
                let a = self.a;
                self.cmp_reg(a, v);
            }
            0xE0 => {
                let v = self.fetch(bus);
                let x = self.x;
                self.cmp_reg(x, v);
                self.cycles += 2;
            }
            0xE4 => {
                let v = self.load(bus, ZeroPage);
                let x = self.x;
                self.cmp_reg(x, v);
            }
            0xEC => {
                let v = self.load(bus, Absolute);
                let x = self.x;
                self.cmp_reg(x, v);
            }
            0xC0 => {
                let v = self.fetch(bus);
                let y = self.y;
                self.cmp_reg(y, v);
                self.cycles += 2;
            }
            0xC4 => {
                let v = self.load(bus, ZeroPage);
                let y = self.y;
                self.cmp_reg(y, v);
            }
            0xCC => {
                let v = self.load(bus, Absolute);
                let y = self.y;
                self.cmp_reg(y, v);
            }

            // ---- INC / DEC (memory) ----
            0xE6 => {
                self.rmw(bus, ZeroPage, |c, v| {
                    let r = v.wrapping_add(1);
                    c.set_zn(r);
                    r
                });
            }
            0xF6 => {
                self.rmw(bus, ZeroPageX, |c, v| {
                    let r = v.wrapping_add(1);
                    c.set_zn(r);
                    r
                });
            }
            0xEE => {
                self.rmw(bus, Absolute, |c, v| {
                    let r = v.wrapping_add(1);
                    c.set_zn(r);
                    r
                });
            }
            0xFE => {
                self.rmw(bus, AbsoluteX, |c, v| {
                    let r = v.wrapping_add(1);
                    c.set_zn(r);
                    r
                });
            }
            0xC6 => {
                self.rmw(bus, ZeroPage, |c, v| {
                    let r = v.wrapping_sub(1);
                    c.set_zn(r);
                    r
                });
            }
            0xD6 => {
                self.rmw(bus, ZeroPageX, |c, v| {
                    let r = v.wrapping_sub(1);
                    c.set_zn(r);
                    r
                });
            }
            0xCE => {
                self.rmw(bus, Absolute, |c, v| {
                    let r = v.wrapping_sub(1);
                    c.set_zn(r);
                    r
                });
            }
            0xDE => {
                self.rmw(bus, AbsoluteX, |c, v| {
                    let r = v.wrapping_sub(1);
                    c.set_zn(r);
                    r
                });
            }

            // ---- INX / DEX / INY / DEY ----
            0xE8 => {
                self.x = self.x.wrapping_add(1);
                let v = self.x;
                self.set_zn(v);
                self.cycles += 2;
            }
            0xCA => {
                self.x = self.x.wrapping_sub(1);
                let v = self.x;
                self.set_zn(v);
                self.cycles += 2;
            }
            0xC8 => {
                self.y = self.y.wrapping_add(1);
                let v = self.y;
                self.set_zn(v);
                self.cycles += 2;
            }
            0x88 => {
                self.y = self.y.wrapping_sub(1);
                let v = self.y;
                self.set_zn(v);
                self.cycles += 2;
            }

            // ---- Shifts / rotates ----
            0x0A => {
                let v = self.a;
                self.a = self.asl_val(v);
                self.cycles += 2;
            }
            0x06 => {
                self.rmw(bus, ZeroPage, |c, v| c.asl_val(v));
            }
            0x16 => {
                self.rmw(bus, ZeroPageX, |c, v| c.asl_val(v));
            }
            0x0E => {
                self.rmw(bus, Absolute, |c, v| c.asl_val(v));
            }
            0x1E => {
                self.rmw(bus, AbsoluteX, |c, v| c.asl_val(v));
            }
            0x4A => {
                let v = self.a;
                self.a = self.lsr_val(v);
                self.cycles += 2;
            }
            0x46 => {
                self.rmw(bus, ZeroPage, |c, v| c.lsr_val(v));
            }
            0x56 => {
                self.rmw(bus, ZeroPageX, |c, v| c.lsr_val(v));
            }
            0x4E => {
                self.rmw(bus, Absolute, |c, v| c.lsr_val(v));
            }
            0x5E => {
                self.rmw(bus, AbsoluteX, |c, v| c.lsr_val(v));
            }
            0x2A => {
                let v = self.a;
                self.a = self.rol_val(v);
                self.cycles += 2;
            }
            0x26 => {
                self.rmw(bus, ZeroPage, |c, v| c.rol_val(v));
            }
            0x36 => {
                self.rmw(bus, ZeroPageX, |c, v| c.rol_val(v));
            }
            0x2E => {
                self.rmw(bus, Absolute, |c, v| c.rol_val(v));
            }
            0x3E => {
                self.rmw(bus, AbsoluteX, |c, v| c.rol_val(v));
            }
            0x6A => {
                let v = self.a;
                self.a = self.ror_val(v);
                self.cycles += 2;
            }
            0x66 => {
                self.rmw(bus, ZeroPage, |c, v| c.ror_val(v));
            }
            0x76 => {
                self.rmw(bus, ZeroPageX, |c, v| c.ror_val(v));
            }
            0x6E => {
                self.rmw(bus, Absolute, |c, v| c.ror_val(v));
            }
            0x7E => {
                self.rmw(bus, AbsoluteX, |c, v| c.ror_val(v));
            }

            // ---- Branches ----
            0x90 => {
                let t = !self.flag(C);
                self.branch(bus, t);
            }
            0xB0 => {
                let t = self.flag(C);
                self.branch(bus, t);
            }
            0xF0 => {
                let t = self.flag(Z);
                self.branch(bus, t);
            }
            0xD0 => {
                let t = !self.flag(Z);
                self.branch(bus, t);
            }
            0x30 => {
                let t = self.flag(N);
                self.branch(bus, t);
            }
            0x10 => {
                let t = !self.flag(N);
                self.branch(bus, t);
            }
            0x50 => {
                let t = !self.flag(V);
                self.branch(bus, t);
            }
            0x70 => {
                let t = self.flag(V);
                self.branch(bus, t);
            }

            // ---- Jumps / subroutines ----
            0x4C => {
                self.pc = self.fetch16(bus);
                self.cycles += 3;
            }
            0x6C => {
                // JMP (ind) with the NMOS page-wrap bug
                let ptr = self.fetch16(bus);
                let lo = bus.read(ptr) as u16;
                let hi_addr = (ptr & 0xFF00) | (ptr.wrapping_add(1) & 0x00FF);
                let hi = bus.read(hi_addr) as u16;
                self.pc = (hi << 8) | lo;
                self.cycles += 5;
            }
            0x20 => {
                let a = self.fetch16(bus);
                let ret = self.pc.wrapping_sub(1);
                self.push(bus, (ret >> 8) as u8);
                self.push(bus, ret as u8);
                self.pc = a;
                self.cycles += 6;
            }
            0x60 => {
                let lo = self.pop(bus) as u16;
                let hi = self.pop(bus) as u16;
                self.pc = ((hi << 8) | lo).wrapping_add(1);
                self.cycles += 6;
            }
            0x40 => {
                // RTI: pull P (B cleared, U forced), then PC
                let p = self.pop(bus);
                self.p = (p & !B) | U;
                let lo = self.pop(bus) as u16;
                let hi = self.pop(bus) as u16;
                self.pc = (hi << 8) | lo;
                self.cycles += 6;
            }
            0x00 => {
                self.cycles += 7;
                if self.brk_stops {
                    self.brk_hit = true;
                } else {
                    let ret = self.pc.wrapping_add(1);
                    self.push(bus, (ret >> 8) as u8);
                    self.push(bus, ret as u8);
                    let v = self.p | B | U;
                    self.push(bus, v);
                    self.setf(I, true);
                    let lo = bus.read(0xFFFE) as u16;
                    let hi = bus.read(0xFFFF) as u16;
                    self.pc = (hi << 8) | lo;
                }
            }

            // ---- Flags ----
            0x18 => {
                self.setf(C, false);
                self.cycles += 2;
            }
            0x38 => {
                self.setf(C, true);
                self.cycles += 2;
            }
            0x58 => {
                self.setf(I, false);
                self.cycles += 2;
            }
            0x78 => {
                self.setf(I, true);
                self.cycles += 2;
            }
            0xB8 => {
                self.setf(V, false);
                self.cycles += 2;
            }
            0xD8 => {
                self.setf(D, false);
                self.cycles += 2;
            }
            0xF8 => {
                self.setf(D, true);
                self.cycles += 2;
            }

            0xEA => {
                self.cycles += 2;
            }

            // ================= STABLE UNDOCUMENTED OPCODES =================
            // ---- SLO = ASL mem; ORA ----
            0x07 => {
                let m = self.rmw(bus, ZeroPage, |c, v| {
                    c.setf(C, v & 0x80 != 0);
                    v << 1
                });
                self.a |= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x17 => {
                let m = self.rmw(bus, ZeroPageX, |c, v| {
                    c.setf(C, v & 0x80 != 0);
                    v << 1
                });
                self.a |= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x0F => {
                let m = self.rmw(bus, Absolute, |c, v| {
                    c.setf(C, v & 0x80 != 0);
                    v << 1
                });
                self.a |= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x1F => {
                let m = self.rmw(bus, AbsoluteX, |c, v| {
                    c.setf(C, v & 0x80 != 0);
                    v << 1
                });
                self.a |= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x1B => {
                let m = self.rmw(bus, AbsoluteY, |c, v| {
                    c.setf(C, v & 0x80 != 0);
                    v << 1
                });
                self.a |= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x03 => {
                let m = self.rmw(bus, IndirectX, |c, v| {
                    c.setf(C, v & 0x80 != 0);
                    v << 1
                });
                self.a |= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x13 => {
                let m = self.rmw(bus, IndirectY, |c, v| {
                    c.setf(C, v & 0x80 != 0);
                    v << 1
                });
                self.a |= m;
                let r = self.a;
                self.set_zn(r);
            }

            // ---- RLA = ROL mem; AND ----
            0x27 => {
                let m = self.rmw(bus, ZeroPage, |c, v| {
                    let oc = c.flag(C) as u8;
                    c.setf(C, v & 0x80 != 0);
                    (v << 1) | oc
                });
                self.a &= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x37 => {
                let m = self.rmw(bus, ZeroPageX, |c, v| {
                    let oc = c.flag(C) as u8;
                    c.setf(C, v & 0x80 != 0);
                    (v << 1) | oc
                });
                self.a &= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x2F => {
                let m = self.rmw(bus, Absolute, |c, v| {
                    let oc = c.flag(C) as u8;
                    c.setf(C, v & 0x80 != 0);
                    (v << 1) | oc
                });
                self.a &= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x3F => {
                let m = self.rmw(bus, AbsoluteX, |c, v| {
                    let oc = c.flag(C) as u8;
                    c.setf(C, v & 0x80 != 0);
                    (v << 1) | oc
                });
                self.a &= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x3B => {
                let m = self.rmw(bus, AbsoluteY, |c, v| {
                    let oc = c.flag(C) as u8;
                    c.setf(C, v & 0x80 != 0);
                    (v << 1) | oc
                });
                self.a &= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x23 => {
                let m = self.rmw(bus, IndirectX, |c, v| {
                    let oc = c.flag(C) as u8;
                    c.setf(C, v & 0x80 != 0);
                    (v << 1) | oc
                });
                self.a &= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x33 => {
                let m = self.rmw(bus, IndirectY, |c, v| {
                    let oc = c.flag(C) as u8;
                    c.setf(C, v & 0x80 != 0);
                    (v << 1) | oc
                });
                self.a &= m;
                let r = self.a;
                self.set_zn(r);
            }

            // ---- SRE = LSR mem; EOR ----
            0x47 => {
                let m = self.rmw(bus, ZeroPage, |c, v| {
                    c.setf(C, v & 1 != 0);
                    v >> 1
                });
                self.a ^= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x57 => {
                let m = self.rmw(bus, ZeroPageX, |c, v| {
                    c.setf(C, v & 1 != 0);
                    v >> 1
                });
                self.a ^= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x4F => {
                let m = self.rmw(bus, Absolute, |c, v| {
                    c.setf(C, v & 1 != 0);
                    v >> 1
                });
                self.a ^= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x5F => {
                let m = self.rmw(bus, AbsoluteX, |c, v| {
                    c.setf(C, v & 1 != 0);
                    v >> 1
                });
                self.a ^= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x5B => {
                let m = self.rmw(bus, AbsoluteY, |c, v| {
                    c.setf(C, v & 1 != 0);
                    v >> 1
                });
                self.a ^= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x43 => {
                let m = self.rmw(bus, IndirectX, |c, v| {
                    c.setf(C, v & 1 != 0);
                    v >> 1
                });
                self.a ^= m;
                let r = self.a;
                self.set_zn(r);
            }
            0x53 => {
                let m = self.rmw(bus, IndirectY, |c, v| {
                    c.setf(C, v & 1 != 0);
                    v >> 1
                });
                self.a ^= m;
                let r = self.a;
                self.set_zn(r);
            }

            // ---- RRA = ROR mem; ADC (ADC sees the carry from the ROR) ----
            0x67 => {
                let m = self.rmw(bus, ZeroPage, |c, v| {
                    let oc = (c.flag(C) as u8) << 7;
                    c.setf(C, v & 1 != 0);
                    (v >> 1) | oc
                });
                self.adc(m);
            }
            0x77 => {
                let m = self.rmw(bus, ZeroPageX, |c, v| {
                    let oc = (c.flag(C) as u8) << 7;
                    c.setf(C, v & 1 != 0);
                    (v >> 1) | oc
                });
                self.adc(m);
            }
            0x6F => {
                let m = self.rmw(bus, Absolute, |c, v| {
                    let oc = (c.flag(C) as u8) << 7;
                    c.setf(C, v & 1 != 0);
                    (v >> 1) | oc
                });
                self.adc(m);
            }
            0x7F => {
                let m = self.rmw(bus, AbsoluteX, |c, v| {
                    let oc = (c.flag(C) as u8) << 7;
                    c.setf(C, v & 1 != 0);
                    (v >> 1) | oc
                });
                self.adc(m);
            }
            0x7B => {
                let m = self.rmw(bus, AbsoluteY, |c, v| {
                    let oc = (c.flag(C) as u8) << 7;
                    c.setf(C, v & 1 != 0);
                    (v >> 1) | oc
                });
                self.adc(m);
            }
            0x63 => {
                let m = self.rmw(bus, IndirectX, |c, v| {
                    let oc = (c.flag(C) as u8) << 7;
                    c.setf(C, v & 1 != 0);
                    (v >> 1) | oc
                });
                self.adc(m);
            }
            0x73 => {
                let m = self.rmw(bus, IndirectY, |c, v| {
                    let oc = (c.flag(C) as u8) << 7;
                    c.setf(C, v & 1 != 0);
                    (v >> 1) | oc
                });
                self.adc(m);
            }

            // ---- SAX = store A & X (no flags) ----
            0x87 => {
                let v = self.a & self.x;
                self.store(bus, ZeroPage, v);
            }
            0x97 => {
                let v = self.a & self.x;
                self.store(bus, ZeroPageY, v);
            }
            0x8F => {
                let v = self.a & self.x;
                self.store(bus, Absolute, v);
            }
            0x83 => {
                let v = self.a & self.x;
                self.store(bus, IndirectX, v);
            }

            // ---- LAX = LDA + LDX ----
            0xA7 => {
                let v = self.load(bus, ZeroPage);
                self.a = v;
                self.x = v;
                self.set_zn(v);
            }
            0xB7 => {
                let v = self.load(bus, ZeroPageY);
                self.a = v;
                self.x = v;
                self.set_zn(v);
            }
            0xAF => {
                let v = self.load(bus, Absolute);
                self.a = v;
                self.x = v;
                self.set_zn(v);
            }
            0xBF => {
                let v = self.load(bus, AbsoluteY);
                self.a = v;
                self.x = v;
                self.set_zn(v);
            }
            0xA3 => {
                let v = self.load(bus, IndirectX);
                self.a = v;
                self.x = v;
                self.set_zn(v);
            }
            0xB3 => {
                let v = self.load(bus, IndirectY);
                self.a = v;
                self.x = v;
                self.set_zn(v);
            }
            // LAX #imm ($AB) is unstable on silicon; use the common stable model A = X = imm.
            0xAB => {
                let v = self.fetch(bus);
                self.a = v;
                self.x = v;
                self.set_zn(v);
                self.cycles += 2;
            }

            // ---- DCP = DEC mem; CMP ----
            0xC7 => {
                let m = self.rmw(bus, ZeroPage, |_, v| v.wrapping_sub(1));
                let a = self.a;
                self.cmp_reg(a, m);
            }
            0xD7 => {
                let m = self.rmw(bus, ZeroPageX, |_, v| v.wrapping_sub(1));
                let a = self.a;
                self.cmp_reg(a, m);
            }
            0xCF => {
                let m = self.rmw(bus, Absolute, |_, v| v.wrapping_sub(1));
                let a = self.a;
                self.cmp_reg(a, m);
            }
            0xDF => {
                let m = self.rmw(bus, AbsoluteX, |_, v| v.wrapping_sub(1));
                let a = self.a;
                self.cmp_reg(a, m);
            }
            0xDB => {
                let m = self.rmw(bus, AbsoluteY, |_, v| v.wrapping_sub(1));
                let a = self.a;
                self.cmp_reg(a, m);
            }
            0xC3 => {
                let m = self.rmw(bus, IndirectX, |_, v| v.wrapping_sub(1));
                let a = self.a;
                self.cmp_reg(a, m);
            }
            0xD3 => {
                let m = self.rmw(bus, IndirectY, |_, v| v.wrapping_sub(1));
                let a = self.a;
                self.cmp_reg(a, m);
            }

            // ---- ISC/ISB = INC mem; SBC ----
            0xE7 => {
                let m = self.rmw(bus, ZeroPage, |_, v| v.wrapping_add(1));
                self.sbc(m);
            }
            0xF7 => {
                let m = self.rmw(bus, ZeroPageX, |_, v| v.wrapping_add(1));
                self.sbc(m);
            }
            0xEF => {
                let m = self.rmw(bus, Absolute, |_, v| v.wrapping_add(1));
                self.sbc(m);
            }
            0xFF => {
                let m = self.rmw(bus, AbsoluteX, |_, v| v.wrapping_add(1));
                self.sbc(m);
            }
            0xFB => {
                let m = self.rmw(bus, AbsoluteY, |_, v| v.wrapping_add(1));
                self.sbc(m);
            }
            0xE3 => {
                let m = self.rmw(bus, IndirectX, |_, v| v.wrapping_add(1));
                self.sbc(m);
            }
            0xF3 => {
                let m = self.rmw(bus, IndirectY, |_, v| v.wrapping_add(1));
                self.sbc(m);
            }

            // ---- Immediate combo illegals (2 cycles) ----
            // ANC: AND #imm, then C = bit 7 of the result
            0x0B | 0x2B => {
                let v = self.fetch(bus);
                self.a &= v;
                let r = self.a;
                self.set_zn(r);
                self.setf(C, r & 0x80 != 0);
                self.cycles += 2;
            }
            // ALR/ASR: AND #imm, then LSR A
            0x4B => {
                let v = self.fetch(bus);
                let t = self.a & v;
                let c = t & 1 != 0;
                self.a = t >> 1;
                let r = self.a;
                self.set_zn(r);
                self.setf(C, c);
                self.cycles += 2;
            }
            // ARR: AND #imm, then ROR A with quirky flags: C = bit 6, V = bit 6 ^ bit 5
            0x6B => {
                let v = self.fetch(bus);
                let t = self.a & v;
                let oc = self.flag(C) as u8;
                let r = (t >> 1) | (oc << 7);
                self.a = r;
                self.set_zn(r);
                self.setf(C, r & 0x40 != 0);
                self.setf(V, ((r >> 6) ^ (r >> 5)) & 1 != 0);
                self.cycles += 2;
            }
            // SBX/AXS: X = (A & X) - imm, C like CMP
            0xCB => {
                let v = self.fetch(bus);
                let t = self.a & self.x;
                let r = t.wrapping_sub(v);
                self.setf(C, t >= v);
                self.x = r;
                self.set_zn(r);
                self.cycles += 2;
            }
            // ANE/XAA: unstable; use the common model A = (A | $FF) & X & imm
            0x8B => {
                let v = self.fetch(bus);
                self.a = (self.a | 0xFF) & self.x & v;
                let r = self.a;
                self.set_zn(r);
                self.cycles += 2;
            }

            // ---- LAS: A = X = SP = mem & SP (abs,Y read; +1 on page cross) ----
            0xBB => {
                let v = self.load(bus, AbsoluteY);
                let r = v & self.sp;
                self.a = r;
                self.x = r;
                self.sp = r;
                self.set_zn(r);
            }

            // ---- TAS/SHS: SP = A & X; store SP & (base-high + 1) at abs,Y ----
            // The AND-mask uses the high byte of the base address, before Y indexing.
            0x9B => {
                let base = self.fetch16(bus);
                let addr = base.wrapping_add(self.y as u16);
                self.sp = self.a & self.x;
                let v = self.sp & ((base >> 8) as u8).wrapping_add(1);
                bus.write(addr, v);
                self.track(true, AddrMode::AbsoluteY, addr, v);
                self.cycles += 5;
            }
            // ---- SHA/AHX: store A & X & (addr-high + 1) ----
            0x9F => {
                let (addr, _) = self.ea(bus, AddrMode::AbsoluteY);
                let v = self.a & self.x & ((addr >> 8) as u8).wrapping_add(1);
                bus.write(addr, v);
                self.track(true, AddrMode::AbsoluteY, addr, v);
                self.cycles += 5;
            }
            0x93 => {
                let (addr, _) = self.ea(bus, AddrMode::IndirectY);
                let v = self.a & self.x & ((addr >> 8) as u8).wrapping_add(1);
                bus.write(addr, v);
                self.track(true, AddrMode::IndirectY, addr, v);
                self.cycles += 6;
            }
            // ---- SHX: store X & (addr-high + 1) at abs,Y ----
            0x9E => {
                let (addr, _) = self.ea(bus, AddrMode::AbsoluteY);
                let v = self.x & ((addr >> 8) as u8).wrapping_add(1);
                bus.write(addr, v);
                self.track(true, AddrMode::AbsoluteY, addr, v);
                self.cycles += 5;
            }
            // ---- SHY: store Y & (addr-high + 1) at abs,X ----
            0x9C => {
                let (addr, _) = self.ea(bus, AddrMode::AbsoluteX);
                let v = self.y & ((addr >> 8) as u8).wrapping_add(1);
                bus.write(addr, v);
                self.track(true, AddrMode::AbsoluteX, addr, v);
                self.cycles += 5;
            }

            // ---- Multi-byte NOPs (consume the operand, charge real cycles) ----
            0x80 | 0x82 | 0x89 | 0xC2 | 0xE2 => {
                self.fetch(bus);
                self.cycles += 2;
            }
            0x04 | 0x44 | 0x64 => {
                let (a, _) = self.ea(bus, ZeroPage);
                let _ = bus.read(a);
                self.cycles += 3;
            }
            0x14 | 0x34 | 0x54 | 0x74 | 0xD4 | 0xF4 => {
                let (a, _) = self.ea(bus, ZeroPageX);
                let _ = bus.read(a);
                self.cycles += 4;
            }
            0x0C => {
                let (a, _) = self.ea(bus, Absolute);
                let _ = bus.read(a);
                self.cycles += 4;
            }
            0x1C | 0x3C | 0x5C | 0x7C | 0xDC | 0xFC => {
                let (a, crossed) = self.ea(bus, AbsoluteX);
                let _ = bus.read(a);
                self.cycles += 4 + crossed as u64;
            }
            0x1A | 0x3A | 0x5A | 0x7A | 0xDA | 0xFA => {
                self.cycles += 2;
            }

            // ---- JAM/KIL: halt the CPU permanently ----
            0x02 | 0x12 | 0x22 | 0x32 | 0x42 | 0x52 | 0x62 | 0x72 | 0x92 | 0xB2 | 0xD2 | 0xF2 => {
                self.jammed = true;
                self.cycles += 1;
            }
        }
    }
}

impl Default for Cpu {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Flat(Vec<u8>);
    impl Bus for Flat {
        fn read(&mut self, a: u16) -> u8 {
            self.0[a as usize]
        }
        fn write(&mut self, a: u16, v: u8) {
            self.0[a as usize] = v;
        }
    }

    fn run(prog: &[u8], steps: usize) -> (Cpu, Flat) {
        let mut bus = Flat(vec![0; 0x10000]);
        bus.0[0x1000..0x1000 + prog.len()].copy_from_slice(prog);
        let mut cpu = Cpu::new();
        cpu.reset_at(0x1000);
        for _ in 0..steps {
            if !cpu.step(&mut bus) {
                break;
            }
        }
        (cpu, bus)
    }

    #[test]
    fn every_opcode_is_handled() {
        // Executing any single opcode must never panic and must consume cycles.
        for op in 0..=255u8 {
            let mut bus = Flat(vec![0; 0x10000]);
            bus.0[0x1000] = op;
            let mut cpu = Cpu::new();
            cpu.reset_at(0x1000);
            cpu.tracked = true;
            cpu.step(&mut bus);
            assert!(cpu.cycles > 0, "opcode {op:02X} charged no cycles");
        }
    }

    #[test]
    fn lda_sta_roundtrip() {
        let (cpu, bus) = run(&[0xA9, 0x42, 0x8D, 0x00, 0x20], 2);
        assert_eq!(bus.0[0x2000], 0x42);
        assert_eq!(cpu.a, 0x42);
        assert_eq!(cpu.instructions, 2);
    }

    #[test]
    fn tracking_records_indirect_y_write() {
        // Pointer at $FB -> $3000, Y=5, STA ($FB),Y
        let mut bus = Flat(vec![0; 0x10000]);
        bus.0[0xFB] = 0x00;
        bus.0[0xFC] = 0x30;
        bus.0[0x1000..0x1006].copy_from_slice(&[0xA0, 0x05, 0xA9, 0x99, 0x91, 0xFB]);
        let mut cpu = Cpu::new();
        cpu.reset_at(0x1000);
        cpu.tracked = true;
        for _ in 0..3 {
            cpu.step(&mut bus);
        }
        let op = cpu.last_op.expect("write not tracked");
        assert!(op.write);
        assert_eq!(op.mode, AddrMode::IndirectY);
        assert_eq!(op.addr, 0x3005);
        assert_eq!(op.value, 0x99);
        assert_eq!(bus.0[0x3005], 0x99);
    }

    #[test]
    fn illegal_sax_write_is_tracked() {
        // LDA #$F0, LDX #$0F, SAX $2000 -> stores $00
        let (cpu, bus) = run(&[0xA9, 0xF0, 0xA2, 0x0F, 0x8F, 0x00, 0x20], 3);
        let _ = cpu;
        assert_eq!(bus.0[0x2000], 0xF0 & 0x0F);
    }

    #[test]
    fn jam_halts() {
        let (cpu, _) = run(&[0x02, 0xEA], 5);
        assert!(cpu.jammed);
        assert_eq!(cpu.instructions, 1);
    }

    #[test]
    fn brk_stops_by_default() {
        let (cpu, _) = run(&[0x00, 0xEA], 5);
        assert!(cpu.brk_hit);
        assert!(!cpu.running());
    }

    #[test]
    fn dcp_sets_carry_like_cmp() {
        // mem $20 = 0x11 -> DCP makes 0x10; A=0x10 -> equal: C=1, Z=1
        let mut bus = Flat(vec![0; 0x10000]);
        bus.0[0x20] = 0x11;
        bus.0[0x1000..0x1004].copy_from_slice(&[0xA9, 0x10, 0xC7, 0x20]);
        let mut cpu = Cpu::new();
        cpu.reset_at(0x1000);
        cpu.step(&mut bus);
        cpu.step(&mut bus);
        assert_eq!(bus.0[0x20], 0x10);
        assert!(cpu.flag(C));
        assert!(cpu.flag(Z));
    }

    #[test]
    fn jmp_indirect_page_wrap_bug() {
        let mut bus = Flat(vec![0; 0x10000]);
        bus.0[0x10FF] = 0x34;
        bus.0[0x1000] = 0x12; // hi byte read from $1000, not $1100
        bus.0[0x2000..0x2003].copy_from_slice(&[0x6C, 0xFF, 0x10]);
        let mut cpu = Cpu::new();
        cpu.reset_at(0x2000);
        cpu.step(&mut bus);
        assert_eq!(cpu.pc, 0x1234);
    }

    #[test]
    fn bcd_adc() {
        // SED; LDA #$19; CLC; ADC #$01 -> $20 in BCD
        let (cpu, _) = run(&[0xF8, 0xA9, 0x19, 0x18, 0x69, 0x01], 4);
        assert_eq!(cpu.a, 0x20);
    }
}
