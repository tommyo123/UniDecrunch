//! Write-range tracing: the heart of the generic detection.
//!
//! While a decruncher runs in the emulator, every memory write is folded into
//! contiguous *ranges*, separated by addressing mode. Direct writes (abs/abs,X)
//! are grouped per originating code location; indirect writes ((zp),Y / (zp,X))
//! are grouped per zero-page pointer, since a decruncher streams its whole
//! output through one pointer, so that range *is* the unpacked program even when
//! the depacker pauses between blocks or writes backwards.
//!
//! Instruction counts are used as the time unit throughout.

use mos6510::{AddrMode, Cpu};

#[derive(Clone, Debug)]
pub struct WriteRange {
    /// First address written (for reverse ranges this is the *highest* address).
    pub start_addr: u16,
    /// Most recently extended edge (for reverse ranges the lowest address).
    pub end_addr: u16,
    /// Instruction count at the range's first write (identifies which depack
    /// stage produced it).
    pub first_write_instr: u64,
    pub last_write_instr: u64,
    pub write_count: u32,
    /// None = single write so far; Some(true) = forward; Some(false) = reverse.
    pub is_forward: Option<bool>,
    pub mode: AddrMode,
    /// For indirect modes: the zero-page pointer the writes go through.
    pub base_ptr: u8,
    /// For direct modes: PC of the writing instruction (separates different loops).
    pub instruction_pc: u16,
}

impl WriteRange {
    pub fn size(&self) -> u32 {
        (self.start_addr as i32 - self.end_addr as i32).unsigned_abs() + 1
    }
    pub fn min_addr(&self) -> u16 {
        self.start_addr.min(self.end_addr)
    }
    pub fn max_addr(&self) -> u16 {
        self.start_addr.max(self.end_addr)
    }
    pub fn is_indirect(&self) -> bool {
        self.mode.is_indirect()
    }
    pub fn direction(&self) -> &'static str {
        match self.is_forward {
            None => "single",
            Some(true) => "forward",
            Some(false) => "reverse",
        }
    }
}

pub struct WriteList {
    /// Direct writes only: max instructions between writes to still merge.
    pub max_instr_between_direct_writes: u64,
    /// Max address gap bridged when merging/extending ranges.
    pub max_gap_for_merge: i32,
    /// Direct writes: the writing instruction must be within this PC distance.
    pub max_pc_distance: i32,
    /// Also fold in writes performed by undocumented opcodes. Off by default:
    /// the classification heuristics (range counts, shapes) are calibrated for
    /// tracing only documented writes. Some crunchers poke setup registers via
    /// illegal stores, and counting those as ranges breaks their signatures.
    pub include_illegal_writes: bool,

    ranges: Vec<WriteRange>,
    /// One flag per address. A second write to the same address never extends a
    /// range (decrunchers write their output exactly once).
    written: Box<[bool; 0x10000]>,
    written_count: usize,
}

impl WriteList {
    pub fn new() -> Self {
        WriteList {
            max_instr_between_direct_writes: 50_000,
            max_gap_for_merge: 32,
            max_pc_distance: 128,
            include_illegal_writes: false,
            ranges: Vec::new(),
            written: vec![false; 0x10000].into_boxed_slice().try_into().unwrap(),
            written_count: 0,
        }
    }

    /// Fold the write performed by the last executed instruction (if any) into the
    /// range set. `pc_before` is the PC where that instruction started.
    /// `io_visible` is the machine's current PLA banking for $D000-$DFFF
    /// writes ([`mos6510::C64Mem::io_visible`]): with I/O banked in such a
    /// write hits the chips (noise); with RAM banked in it is payload. Many
    /// depackers bank all-RAM and write the program straight through the I/O
    /// window.
    pub fn track(&mut self, cpu: &Cpu, pc_before: u16, io_visible: bool) {
        if !cpu.tracked {
            return;
        }
        let Some(op) = cpu.last_op else { return };
        if !op.write {
            return;
        }
        if op.illegal && !self.include_illegal_writes {
            return;
        }
        if is_noise_write(op.addr, op.mode, io_visible) {
            return;
        }
        if self.written[op.addr as usize] {
            return;
        }
        self.written[op.addr as usize] = true;
        self.written_count += 1;

        let base_ptr = if op.mode.is_indirect() { op.ptr } else { 0 };
        let now = cpu.instructions;

        if let Some(idx) = self.find_matching_range(op.addr, now, op.mode, base_ptr, pc_before) {
            extend_range(&mut self.ranges[idx], op.addr, now);
        } else {
            self.ranges.push(WriteRange {
                start_addr: op.addr,
                end_addr: op.addr,
                first_write_instr: now,
                last_write_instr: now,
                write_count: 1,
                is_forward: None,
                mode: op.mode,
                base_ptr,
                instruction_pc: pc_before,
            });
        }

        if self.ranges.len() > 100 || self.written_count.is_multiple_of(100) {
            self.merge_ranges();
        }
    }

    /// Find a range this write belongs to. Mode must match exactly; indirect
    /// writes must share the pointer, and then always merge (same pointer means
    /// same output stream, regardless of pauses or address gaps); direct writes
    /// must come from nearby code, recently, and land close to the range.
    fn find_matching_range(
        &self,
        addr: u16,
        now: u64,
        mode: AddrMode,
        base_ptr: u8,
        pc: u16,
    ) -> Option<usize> {
        let addr_i = addr as i32;
        let indirect = mode.is_indirect();

        for (i, range) in self.ranges.iter().enumerate() {
            if range.mode != mode {
                continue;
            }
            if indirect && range.base_ptr != base_ptr {
                continue;
            }
            if !indirect {
                let pc_dist = (range.instruction_pc as i32 - pc as i32).abs();
                if pc_dist > self.max_pc_distance {
                    continue;
                }
                if now - range.last_write_instr > self.max_instr_between_direct_writes {
                    continue;
                }
            }

            let min = range.min_addr() as i32;
            let max = range.max_addr() as i32;
            if addr_i >= min && addr_i <= max {
                return Some(i);
            }
            if indirect {
                // Same pointer: any distance is fine.
                return Some(i);
            }
            let dist = (addr_i - min).abs().min((addr_i - max).abs());
            if dist <= self.max_gap_for_merge {
                return Some(i);
            }
        }
        None
    }

    /// Merge overlapping/adjacent ranges with identical mode (and pointer).
    fn merge_ranges(&mut self) {
        if self.ranges.len() < 2 {
            return;
        }
        self.ranges.sort_by_key(|r| (r.mode, r.min_addr()));
        let mut i = 0;
        while i + 1 < self.ranges.len() {
            let (cur, next) = (&self.ranges[i], &self.ranges[i + 1]);
            if cur.mode != next.mode || (cur.is_indirect() && cur.base_ptr != next.base_ptr) {
                i += 1;
                continue;
            }
            let cur_max = cur.max_addr() as i32;
            if (next.min_addr() as i32) <= cur_max + self.max_gap_for_merge {
                let new_end = cur_max.max(next.max_addr() as i32) as u16;
                let next_count = next.write_count;
                let next_first = next.first_write_instr;
                let next_instr = next.last_write_instr;
                let cur = &mut self.ranges[i];
                cur.end_addr = new_end;
                cur.write_count += next_count;
                cur.first_write_instr = cur.first_write_instr.min(next_first);
                cur.last_write_instr = cur.last_write_instr.max(next_instr);
                self.ranges.remove(i + 1);
            } else {
                i += 1;
            }
        }
    }

    /// Merge ALL indirect ranges sharing (mode, pointer) regardless of gaps:
    /// a safety net for decrunchers that pause between blocks.
    fn merge_indirect_by_pointer(&mut self) {
        let (indirect, direct): (Vec<_>, Vec<_>) =
            self.ranges.drain(..).partition(|r| r.is_indirect());
        let mut merged: Vec<WriteRange> = Vec::new();
        for r in indirect {
            if let Some(m) = merged
                .iter_mut()
                .find(|m| m.mode == r.mode && m.base_ptr == r.base_ptr)
            {
                let overall_min = m.min_addr().min(r.min_addr());
                let overall_max = m.max_addr().max(r.max_addr());
                let reverse = m.is_forward == Some(false);
                m.start_addr = if reverse { overall_max } else { overall_min };
                m.end_addr = if reverse { overall_min } else { overall_max };
                m.write_count += r.write_count;
                m.first_write_instr = m.first_write_instr.min(r.first_write_instr);
                m.last_write_instr = m.last_write_instr.max(r.last_write_instr);
            } else {
                merged.push(r);
            }
        }
        self.ranges = merged;
        self.ranges.extend(direct);
    }

    /// Final cleanup after a completed run: merge, then drop small *direct*
    /// ranges (noise from setup loops). Small indirect ranges are kept, since a
    /// BASIC line link fixup can be a legitimate 12-byte range.
    pub fn flush(&mut self) {
        self.merge_ranges();
        self.merge_indirect_by_pointer();
        self.ranges
            .retain(|r| r.is_indirect() || r.write_count >= 16);
    }

    /// Drop ALL ranges with fewer writes than `min`, then re-merge.
    pub fn clean_lists(&mut self, min: u32) {
        self.ranges.retain(|r| r.write_count >= min);
        self.merge_ranges();
    }

    /// Was this address written (and counted) during the trace?
    pub fn was_written(&self, addr: u16) -> bool {
        self.written[addr as usize]
    }

    /// Number of unique addresses written so far.
    pub fn written_count(&self) -> usize {
        self.written_count
    }

    /// All ranges, sorted by lowest address.
    pub fn sequences(&self) -> Vec<WriteRange> {
        let mut v = self.ranges.clone();
        v.sort_by_key(|r| r.min_addr());
        v
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Human-readable summary of the traced ranges.
    pub fn summary(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        let sorted = self.sequences();
        let _ = writeln!(
            s,
            "Write ranges: {} ({} unique addresses)",
            sorted.len(),
            self.written_count
        );
        for (i, r) in sorted.iter().enumerate() {
            let extra = if r.is_indirect() {
                format!("base=${:02x}", r.base_ptr)
            } else {
                format!("PC=${:04x}", r.instruction_pc)
            };
            let _ = writeln!(
                s,
                "  {}. {:7} ${:04x}-${:04x}  {} bytes ({} writes) [{}] {}",
                i + 1,
                r.mode.name(),
                r.min_addr(),
                r.max_addr(),
                r.size(),
                r.write_count,
                extra,
                r.direction(),
            );
        }
        if let Some(l) = sorted.iter().max_by_key(|r| r.size()) {
            let _ = writeln!(
                s,
                "  largest: ${:04x}-${:04x} ({} bytes) via {}",
                l.min_addr(),
                l.max_addr(),
                l.size(),
                l.mode.name()
            );
        }
        s
    }
}

impl Default for WriteList {
    fn default() -> Self {
        Self::new()
    }
}

fn extend_range(range: &mut WriteRange, addr: u16, now: u64) {
    let addr_i = addr as i32;
    let cur_start = range.start_addr as i32;
    let cur_min = range.min_addr() as i32;
    let cur_max = range.max_addr() as i32;

    if range.write_count == 1 {
        range.is_forward = Some(addr_i > cur_start);
    }
    let reverse = range.is_forward == Some(false);
    if addr_i < cur_min {
        if reverse {
            range.end_addr = addr; // reverse: end tracks the lowest address
        } else {
            range.start_addr = addr;
        }
    } else if addr_i > cur_max {
        if reverse {
            range.start_addr = addr; // reverse: start tracks the highest address
        } else {
            range.end_addr = addr;
        }
    }
    range.last_write_instr = now;
    range.write_count += 1;
}

/// Writes that never belong to unpacked output: zero-page scratch (except the
/// common $FB-$FF pointer area), the stack, and $D000-$DFFF writes that hit
/// the I/O chips. With RAM banked in ($01), a $D000-$DFFF write is payload
/// like anywhere else. Indirect writes are never noise, since their target is
/// the output stream.
fn is_noise_write(addr: u16, mode: AddrMode, io_visible: bool) -> bool {
    if mode.is_indirect() {
        return false;
    }
    let a = addr as usize;
    if a < 0x100
        && matches!(
            mode,
            AddrMode::ZeroPage | AddrMode::ZeroPageX | AddrMode::ZeroPageY
        )
    {
        return a < 0xFB;
    }
    if (0xD000..=0xDFFF).contains(&a) {
        return io_visible;
    }
    if (0x0100..=0x01FF).contains(&a) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use mos6510::{Bus, C64Mem};

    /// Drive a tiny program and return the traced ranges.
    fn trace(prog: &[u8], at: u16, steps: usize) -> WriteList {
        let mut mem = C64Mem::new();
        for (i, &b) in prog.iter().enumerate() {
            mem.write(at + i as u16, b);
        }
        let mut cpu = Cpu::new();
        cpu.reset_at(at);
        cpu.tracked = true;
        let mut wl = WriteList::new();
        for _ in 0..steps {
            let pc = cpu.pc;
            if !cpu.step(&mut mem) {
                break;
            }
            wl.track(&cpu, pc, mem.io_visible());
        }
        wl
    }

    #[test]
    fn forward_copy_loop_becomes_one_range() {
        // LDX #0; loop: LDA #$AA, STA $2000,X; INX; BNE loop
        let prog = [0xA2, 0x00, 0xA9, 0xAA, 0x9D, 0x00, 0x20, 0xE8, 0xD0, 0xFA];
        let wl = trace(&prog, 0x1000, 3000);
        let seqs = wl.sequences();
        assert_eq!(seqs.len(), 1);
        assert_eq!(seqs[0].min_addr(), 0x2000);
        assert_eq!(seqs[0].max_addr(), 0x20FF);
        assert_eq!(seqs[0].is_forward, Some(true));
        assert_eq!(seqs[0].mode, AddrMode::AbsoluteX);
    }

    #[test]
    fn indirect_ranges_bridge_large_gaps() {
        // Write via ($FB),Y at $3000, then repoint to $8000 and write again:
        // same pointer => one range spanning both.
        // LDA #$00 STA $FB, LDA #$30 STA $FC, LDA #1 LDY #0 STA ($FB),Y
        // LDA #$80 STA $FC, LDA #2 STA ($FB),Y
        let prog = [
            0xA9, 0x00, 0x85, 0xFB, 0xA9, 0x30, 0x85, 0xFC, 0xA9, 0x01, 0xA0, 0x00, 0x91, 0xFB,
            0xA9, 0x80, 0x85, 0xFC, 0xA9, 0x02, 0x91, 0xFB,
        ];
        let mut wl = trace(&prog, 0x1000, 20);
        wl.flush();
        let seqs = wl.sequences();
        let ind: Vec<_> = seqs.iter().filter(|r| r.is_indirect()).collect();
        assert_eq!(ind.len(), 1);
        assert_eq!(ind[0].min_addr(), 0x3000);
        assert_eq!(ind[0].max_addr(), 0x8000);
    }

    #[test]
    fn stack_and_io_writes_are_noise() {
        // PHA (stack) + STA $D020 (I/O, but $01=$37 -> io visible, still noise)
        let prog = [0xA9, 0x05, 0x48, 0x8D, 0x20, 0xD0];
        let wl = trace(&prog, 0x1000, 4);
        assert!(wl.is_empty());
    }

    #[test]
    fn rewrite_of_same_address_ignored() {
        // Two writes to $2000: only the first extends anything.
        let prog = [0xA9, 0x01, 0x8D, 0x00, 0x20, 0xA9, 0x02, 0x8D, 0x00, 0x20];
        let wl = trace(&prog, 0x1000, 6);
        let seqs = wl.sequences();
        assert_eq!(seqs.len(), 1);
        assert_eq!(seqs[0].write_count, 1);
    }
}
