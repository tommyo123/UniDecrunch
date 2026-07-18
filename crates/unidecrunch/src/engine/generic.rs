//! The generic engine: run the decruncher, trace its writes, and read the
//! unpacked program out of the largest written range.
//!
//! Phase 1, bootstrap: run until the PC reaches `stop_pc` (the relocated depack
//! stub in low memory).
//! Phase 2, depack: enable write tracing and run until the PC jumps above
//! `exit_above`, into the freshly unpacked program.
//!
//! Behavioral classification for the $0100 family (`analyze_0100`):
//! Time Cruncher 5.x-6.x and Cruel Cruncher both leave exactly two ranges: a
//! short *forward* abs,X/abs,Y copy (the tail the depacker relocated) directly
//! followed by a long *reverse* (zp),Y range (the real depack). They are told
//! apart by where the depack loop lives, measured as the average PC during
//! phase 2: Time Cruncher runs at $0100-$0340, Cruel Cruncher at $0400-$0770.

use crate::config::{CruncherConfig, VariantCfg};
use crate::machine::Machine;
use crate::pattern::{guess_start, Pattern};
use crate::writelist::WriteList;
use mos6510::AddrMode;

use super::EngineResult;

/// Cruel Cruncher 2.x-3.x leaves this depack loop at $0100. Checked after the
/// behavioral classification to refine the version in the name.
const CRUEL_2X_AT_0100: &str =
    "B9 ?? ?? 99 ?? ?? C8 D0 F7 20 ?? ?? F0 46 20 ?? ?? D0 30 20 ?? ?? 69 02 \
     C9 04 90 27 D0 07 20 ?? ?? 69 04 D0 ?? 20 ?? ?? 69 06 C9 ?? D0 ?? C8 20 \
     ?? ?? 69 0D C9 ?? D0 ?? A0";

pub fn run(
    cfg: &CruncherConfig,
    variant: Option<&VariantCfg>,
    m: &mut Machine,
    log: &mut Vec<String>,
) -> EngineResult {
    // ---- Phase 1: bootstrap until the relocated stub is reached ----
    let phase1_ok = if let Some(threshold) = cfg.stop_below {
        // Family-wide variant: any dive below `threshold` means the relocated
        // stub has taken over, whatever its exact address is.
        let mut n: u64 = 0;
        let mut hit = false;
        while n < cfg.cap {
            if !m.step() {
                break;
            }
            n += 1;
            if m.cpu.pc < threshold {
                hit = true;
                break;
            }
        }
        hit
    } else {
        m.run_until(&cfg.stop_pc, cfg.cap)
    };
    if !phase1_ok {
        log.push(format!(
            "phase 1: never reached stop_pc {:?}/below {:?} (pc=${:04x})",
            cfg.stop_pc, cfg.stop_below, m.cpu.pc
        ));
        return EngineResult::failed();
    }
    log.push(format!(
        "phase 1 done: pc=${:04x} after {} instructions",
        m.cpu.pc, m.cpu.instructions
    ));

    // ---- Phase 2: trace writes until the PC escapes into the unpacked program ----
    m.cpu.tracked = true;
    let mut wl = WriteList::new();
    let mut ok = false;
    let mut steps: u64 = 0;
    let mut pc_sum: u128 = 0;
    // Depackers JSR into (stubbed) ROM helpers mid-run; such excursions push a
    // return address, so the stack pointer sits below its phase-2 level. A real
    // hand-off is a JMP (stack untouched) or lands in RAM.
    let sp0 = m.cpu.sp;
    // Multi-stage depackers unpack their own next stage as part of the payload
    // and jump into it; such jumps land DEEP inside the output range, whereas a
    // real program entry sits near its start. Reject candidates in the upper
    // half of the (current) largest range; memoize per page to stay cheap.
    let mut rejected_page: Option<u16> = None;
    // Quiescence mode: note plausible hand-offs instead of stopping, and
    // finish once the writes dry up. The hand-off that matters is the LAST
    // *crossing* from the stub area up into the payload; earlier crossings are
    // inter-stage jumps, and once the program runs its own PCs stay high (no
    // crossing), so they never overwrite the recorded hand-off.
    let mut last_crossing_candidate: Option<u16> = None;
    // Instruction count (cpu.instructions units, comparable with the ranges'
    // first_write_instr) when the hand-off candidate above was first crossed.
    let mut last_crossing_step: Option<u64> = None;
    // RAM as it was at that hand-off. Quiescence mode keeps emulating while
    // the LAUNCHED PROGRAM runs, and the program may overwrite its own memory
    // (clear loops, self-modification); the payload must be lifted from the
    // hand-off state, not from whatever the program left behind.
    let mut handoff_ram: Option<Box<[u8; 0x10000]>> = None;
    // Unique-address write count at the last snapshot (skip re-snapshots when
    // nothing was written in between).
    let mut written_at_crossing = 0;
    let mut first_any_candidate: Option<u16> = None;
    let mut last_new_write_step: u64 = 0;
    let mut written_before = 0usize;
    // Quiescence can also kick in dynamically: a classic exit landing deep in
    // data territory ($8000-$9FFF / $C000-$CFFF, not a BASIC/KERNAL hand-off) is
    // usually a depacked next STAGE, so the run continues until the writes dry
    // up instead of trusting that jump.
    let mut quiescent = cfg.exit_quiescent;
    let mut switch_step: Option<u64> = None;
    while steps < cfg.cap {
        let pc_before = m.cpu.pc;
        if !m.step() {
            // A depacker that halts after finishing still counts when a
            // hand-off was already seen.
            if quiescent > 0 && (last_crossing_candidate.is_some() || first_any_candidate.is_some())
            {
                ok = true;
                wl.flush();
                wl.clean_lists(16);
            }
            break;
        }
        wl.track(&m.cpu, pc_before, m.mem.io_visible());
        steps += 1;
        pc_sum += m.cpu.pc as u128;
        if quiescent > 0 {
            let w = wl.written_count();
            if w != written_before {
                written_before = w;
                last_new_write_step = steps;
            }
        }
        let pc = m.cpu.pc;
        if pc > cfg.exit_above {
            // Smart candidate filtering applies in exit_into_written mode AND
            // whenever quiescence is active (incl. after a dynamic switch);
            // the plain immediate-exit path keeps its calibrated behavior.
            let smart = cfg.exit_into_written || quiescent > 0;
            // A PC inside a ROM region is never the unpacked program, even if
            // the RAM underneath was written (staging areas live there).
            let in_rom = smart && ((0xA000..0xC000).contains(&pc) || pc >= 0xD000);
            // Crossings from the stub area are trusted even into memory the
            // trace didn't see written (phase 1 may have placed it there);
            // same-level jumps must land in freshly written memory.
            let crossing = pc_before <= cfg.exit_above;
            // Crossings may land in memory the trace didn't see written (phase
            // 1 placed it), but only quiescence mode can afford that trust,
            // since it keeps re-evaluating; immediate exits must see the write.
            let trusted_crossing = crossing && quiescent > 0;
            // Program entries live at $0600+; anything lower is stub machinery.
            let mut into_written_ok =
                !smart || (!in_rom && pc >= 0x0600 && (trusted_crossing || wl.was_written(pc)));
            if smart && into_written_ok {
                if let Some(l) = wl.sequences().iter().max_by_key(|r| r.size()) {
                    let (min, max) = (l.min_addr() as u32, l.max_addr() as u32);
                    // "deep" = in the top quarter of the range: real entries sit
                    // in the lower part, depacked stage-2 code near the top.
                    if (pc as u32) > min && (pc as u32 - min) * 4 > (max - min) * 3 {
                        if rejected_page != Some(pc & 0xFF00) {
                            log.push(format!(
                                "ignoring jump to ${pc:04x}: deep inside ${min:04x}-${max:04x}, looks like a depacked stage-2"
                            ));
                            rejected_page = Some(pc & 0xFF00);
                        }
                        into_written_ok = false;
                    }
                }
            }
            if (!in_rom || m.cpu.sp >= sp0) && into_written_ok {
                if quiescent == 0 {
                    // $D000+ counts as data territory only when the depacker
                    // itself wrote the target: then it is staged RAM code, not a
                    // KERNAL/IO jump. $0200-$05FF (tape buffer/screen) is never a
                    // program entry either, since relocated stages live there.
                    let suspicious = (0x8000..0xA000).contains(&pc)
                        || (0xC000..0xD000).contains(&pc)
                        || (pc >= 0xD000 && wl.was_written(pc))
                        || (0x0200..0x0600).contains(&pc);
                    if suspicious {
                        log.push(format!(
                            "exit jump ${pc:04x} lands deep in data territory: likely a depacked stage, switching to quiescence"
                        ));
                        quiescent = 500_000;
                        // in cpu.instructions units, comparable with the
                        // ranges' first_write_instr
                        switch_step = Some(m.cpu.instructions);
                        last_new_write_step = steps;
                        written_before = wl.written_count();
                        // The stage jump itself is only the fallback candidate.
                        first_any_candidate = Some(pc);
                    } else {
                        ok = true;
                        wl.flush();
                        wl.clean_lists(16);
                        break;
                    }
                } else {
                    // Hand-off = a crossing from the stub area up into the
                    // unpacked program; the last one before the writes dry up
                    // is the real hand-off (earlier ones are stage jumps).
                    if crossing {
                        if last_crossing_candidate != Some(pc) {
                            log.push(format!(
                                "hand-off candidate ${pc:04x} noted; running until writes stop"
                            ));
                        }
                        last_crossing_candidate = Some(pc);
                        // The LAST crossing wins: a depacker can bounce across
                        // the boundary many times while decrunching (per-block
                        // stages, get-byte helpers above the boundary), so
                        // earlier crossings are stage jumps and the payload
                        // snapshot must come from the final one. Re-snapshot
                        // only when something was written since the previous
                        // crossing, since a launched program bouncing WITHOUT
                        // writing keeps the true hand-off state.
                        let written_now = wl.written_count();
                        if last_crossing_step.is_none() || written_now != written_at_crossing {
                            last_crossing_step = Some(m.cpu.instructions);
                            handoff_ram = Some(m.mem.ram.clone());
                            written_at_crossing = written_now;
                        }
                    }
                    if first_any_candidate.is_none() {
                        first_any_candidate = Some(pc);
                    }
                }
            }
        }
        if quiescent > 0
            && (last_crossing_candidate.is_some() || first_any_candidate.is_some())
            && steps - last_new_write_step > quiescent
        {
            ok = true;
            wl.flush();
            wl.clean_lists(16);
            break;
        }
    }
    // Interactive tools never go quiet (menus, blinking cursors): accept at
    // the instruction cap too, as long as a hand-off was seen.
    if !ok && quiescent > 0 && (last_crossing_candidate.is_some() || first_any_candidate.is_some())
    {
        log.push("instruction cap in quiescence mode: accepting the recorded hand-off".into());
        ok = true;
        wl.flush();
        wl.clean_lists(16);
    }
    let avg_pc: u32 = if steps > 0 {
        (pc_sum / steps as u128) as u32
    } else {
        0
    };
    log.push(format!(
        "phase 2: {}, jumped to ${:04x} after {} instructions (avg pc ${:x})",
        if ok { "ok" } else { "did not finish" },
        m.cpu.pc,
        steps,
        avg_pc
    ));
    log.push(wl.summary());
    if !ok {
        return EngineResult::failed();
    }

    let mut jump_start = last_crossing_candidate
        .or(first_any_candidate)
        .unwrap_or(m.cpu.pc);
    // Lift from the hand-off state: everything the machine did AFTER the
    // final hand-off was the launched program running (quiescence mode keeps
    // emulating), and it may have overwritten its own memory. Both the saved
    // bytes and every RAM-reading heuristic below (BASIC line guessing,
    // classification patterns) must see the freshly decrunched RAM.
    if let (Some(cand), Some(snap)) = (last_crossing_candidate, handoff_ram.as_ref()) {
        if jump_start == cand {
            m.mem.ram.copy_from_slice(&snap[..]);
            log.push(
                "restored RAM to the hand-off state (the launched program ran on afterwards)"
                    .into(),
            );
        }
    }
    let mut seqs = wl.sequences();
    // Ranges first written AFTER the final hand-off were written by the
    // LAUNCHED PROGRAM, not the depacker: quiescence mode keeps tracing
    // while the program runs, and a program that clears or fills memory
    // dwarfs the real payload (an SFX that launches a program which fills
    // most of RAM would otherwise make "largest range" pick that fill).
    // Drop them before choosing the payload; keep the list intact if that
    // would drop everything.
    if let Some(cross) = last_crossing_step {
        let kept: Vec<_> = seqs
            .iter()
            .filter(|r| r.first_write_instr <= cross)
            .cloned()
            .collect();
        if !kept.is_empty() && kept.len() < seqs.len() {
            log.push(format!(
                "dropped {} write range(s) first written after the hand-off (the launched program's own writes)",
                seqs.len() - kept.len()
            ));
            seqs = kept;
        }
    }
    // First maximal range on ties, not the last-max default.
    let largest = seqs.iter().min_by_key(|r| std::cmp::Reverse(r.size()));

    let mut start: u16 = 0;
    let mut end: u16 = 0;
    let mut real_start: u16 = 0;
    let mut name: Option<String> = None;
    let mut classified = false;

    if let Some(l) = largest {
        start = l.min_addr();
        end = l.max_addr();

        // The payload was written high-to-low. Many depackers decrunch in
        // reverse, so without a positive signature the honest name is the
        // generic definition that matched plus the OBSERVED behavior, letting
        // the user see that a generic algorithm (not a real identification)
        // produced the result. Real Time/Cruel Crunchers are still positively
        // identified further down (behavioral classifier and [[variant]]
        // patterns), which overrides this name.
        if cfg.analyze_0100 && l.is_forward == Some(false) {
            name = Some(format!("{} (reverse writer)", cfg.name));
        }

        // Depackers that switch copy loops halfway leave the payload as two or
        // more abutting ranges, so extend over direct neighbours (gap <= 1).
        // Always on after a late-stage switch: cascade stages scatter the
        // program across several abutting ranges, sometimes leaving the entry
        // code in a small range below the big one.
        //
        // Ranges that OVERLAP or directly ABUT the chosen one are merged
        // unconditionally. Overlap means the same output area was written
        // through a second write channel (e.g. Shrinkler's literal STA (zp,x)
        // vs match-copy STA (zp),y). Direct adjacency (gap <= 2) means the
        // payload was assembled by abutting stages: a boot whose payload move
        // runs under tracing leaves the moved packed block as a first-writer
        // range that the decoder's re-writes cannot claim (the tracker
        // records first writes only), so the real output shows up as two
        // ranges meeting exactly at the packed boundary. Scratch tables sit
        // well apart from the payload, so the tight gap keeps them out.
        let allow_adjacent = true;
        {
            let mut grown = true;
            while grown {
                grown = false;
                for r in &seqs {
                    let rmin = r.min_addr() as i32;
                    let rmax = r.max_addr() as i32;
                    if rmin >= start as i32 && rmax <= end as i32 {
                        continue; // already inside
                    }
                    let overlaps = rmin <= end as i32 && rmax >= start as i32;
                    if !(allow_adjacent || overlaps) {
                        continue;
                    }
                    if rmin - (end as i32) <= 2 && rmin > start as i32 {
                        log.push(format!(
                            "merged {} output range ${:04x}-${:04x} (end ${end:04x} -> ${:04x})",
                            if overlaps { "overlapping" } else { "adjacent" },
                            r.min_addr(),
                            r.max_addr(),
                            r.max_addr()
                        ));
                        end = r.max_addr();
                        grown = true;
                    } else if (start as i32) - rmax <= 2 && rmax < end as i32 {
                        log.push(format!(
                            "merged {} output range ${:04x}-${:04x} (start ${start:04x} -> ${:04x})",
                            if overlaps { "overlapping" } else { "adjacent" },
                            r.min_addr(), r.max_addr(), r.min_addr()
                        ));
                        start = r.min_addr();
                        grown = true;
                    }
                }
            }
        }

        // "Depack high, page-copy down": the copy-down (our largest range)
        // moves whole pages, but the staging range holds the exact payload
        // size, so trim the tail overshoot when the sizes line up.
        if cfg.trim_page_overshoot {
            if let Some(staged) = seqs
                .iter()
                .filter(|r| {
                    r.min_addr() != l.min_addr()
                        && r.size() < l.size()
                        && l.size() - r.size() <= 255
                })
                .max_by_key(|r| r.size())
            {
                let exact_end = l.min_addr() + (staged.size() - 1) as u16;
                log.push(format!(
                    "trimmed page overshoot: end ${end:04x} -> ${exact_end:04x} (staged range ${:04x}-${:04x} has the exact size)",
                    staged.min_addr(),
                    staged.max_addr()
                ));
                end = exact_end;
            }
        }
    }

    // ---- Late-stage payload ----
    // When the run switched to quiescence because a depacked final stage took
    // over, the real payload is what THAT stage wrote, not the biggest range
    // overall (usually a staging move or memory wipe from earlier phases).
    if let (Some(sw), true) = (switch_step, ok) {
        let packed_len = m.mem.prg_end as u32 - m.mem.prg_start as u32 + 1;
        if let Some(stage) = seqs
            .iter()
            .filter(|r| r.first_write_instr >= sw && r.size() >= packed_len / 2)
            .max_by_key(|r| r.size())
        {
            log.push(format!(
                "final stage wrote ${:04x}-${:04x} ({} bytes), using it as the payload",
                stage.min_addr(),
                stage.max_addr(),
                stage.size()
            ));
            real_start = stage.min_addr();
            start = stage.min_addr();
            end = stage.max_addr();
            classified = true;
        }
    }

    // ---- Reconstruction from the final BASIC environment ----
    // Multi-stage depackers rebuild a proper BASIC SYS line at $0801 (and often
    // VARTAB): that beats both the recorded jump and a written range that ends
    // in a memory wipe at $CFFF. Applied after a late-stage switch or when the
    // range shows the wipe signature (end at/near $CFFF).
    if ok && (switch_step.is_some() || end >= 0xCF00) {
        let sys = crate::pattern::sys_address(m.mem.ram.as_ref());
        // The BASIC line sits at $0801, often just BELOW the traced range
        // (the stage wrote it separately), so accept any in-memory SYS target.
        if sys >= 0x0801 && sys <= end {
            log.push(format!(
                "final memory holds a BASIC line: run address ${jump_start:04x} replaced by SYS {sys} (${sys:04x})"
            ));
            jump_start = sys;
            // A valid SYS line means a BASIC program: it starts at its line,
            // whatever range the tracer considered largest (often the wipe).
            real_start = start;
            start = 0x0801;
            // VARTAB only counts when the depacker actually set it. At load time
            // we initialize it to prg_end+1 ourselves, and trusting that
            // leftover would truncate the output at the packed file's size.
            let vartab = m.mem.read_word(0x2D);
            let loader_value = m.mem.prg_end.wrapping_add(1);
            let vartab_end = vartab.wrapping_sub(1);
            if vartab != loader_value && vartab_end > sys && vartab_end < 0xA000 && vartab_end < end
            {
                log.push(format!(
                    "VARTAB bounds the program: end ${end:04x} -> ${vartab_end:04x}"
                ));
                end = vartab_end;
            }
        }
    }

    // A run address inside the KERNAL/IO area (stubbed-ROM artifact) or the
    // tape-buffer stage zone is meaningless; the program's own BASIC line (if
    // the extraction has one) tells the truth. Metadata-only correction.
    if ok && (jump_start >= 0xD000 || (0x0200..0x0600).contains(&jump_start)) {
        let sys = crate::pattern::sys_address(m.mem.ram.as_ref());
        if sys != 0 && sys >= start && sys <= end {
            log.push(format!(
                "run address ${jump_start:04x} is in ROM/IO, using the BASIC line's SYS {sys} (${sys:04x})"
            ));
            jump_start = sys;
        } else {
            // No BASIC line: the entry hint is the first non-zero byte of the
            // extraction (machine-code programs behind zero padding).
            let ram = m.mem.ram.as_ref();
            if let Some(first) = (start..=end).find(|&a| ram[a as usize] != 0) {
                if first != start || jump_start >= 0xD000 {
                    log.push(format!(
                        "run address ${jump_start:04x} is bogus, first code byte at ${first:04x} used as entry hint"
                    ));
                    jump_start = first;
                }
            }
        }
    }

    // ---- BASIC hand-off ----
    // A jump into the BASIC interpreter ($A000-$BFFF: RUN / warm start) means
    // the unpacked program is a BASIC program, and for RUN to work the
    // decruncher must have set the BASIC pointers, so the exact bounds are
    // TXTTAB ($0801) to VARTAB-1. This beats the largest-range pick, which for
    // these crunchers is often a post-depack memory wipe.
    if (0xA000..0xC000).contains(&jump_start) {
        let vartab_end = m.mem.read_word(0x2D).wrapping_sub(1);
        if vartab_end > 0x0801 && vartab_end < 0xA000 {
            log.push(format!(
                "run address ${jump_start:04x} is the BASIC interpreter: extracting BASIC program $0801-${vartab_end:04x} (VARTAB)"
            ));
            real_start = start;
            start = 0x0801;
            end = vartab_end;
            classified = true;
        }
    }

    // ---- Behavioral classification (the $0100 family) ----
    if cfg.analyze_0100 && seqs.len() == 2 {
        let r0 = &seqs[0];
        let r1 = &seqs[1];
        let fwd_copy = r0.is_forward == Some(true)
            && matches!(r0.mode, AddrMode::AbsoluteX | AddrMode::AbsoluteY);
        let rev_depack = r1.is_forward == Some(false) && r1.mode == AddrMode::IndirectY;
        let adjacent = r1.min_addr() as i32 - r0.max_addr() as i32 == 1;
        if fwd_copy && rev_depack && adjacent && r1.max_addr() > r0.min_addr() {
            let low = r0.min_addr();
            let high = r1.max_addr();
            if (0x101..0x340).contains(&avg_pc) {
                // Time Cruncher 5.x-6.x. Its end-of-depack restore loop starts
                // 25 bytes below the program on $0801-based files (it also
                // rewrites the load-address bytes), so snap to $0801 when the
                // write region lines up with that. Otherwise keep the address
                // the decruncher actually wrote from; adding 25 unconditionally
                // would cut into non-$0801 payloads.
                real_start = low;
                start = if low == 0x0801 || low + 25 == 0x0801 {
                    0x0801
                } else {
                    log.push(format!(
                        "Time Cruncher 5.x: region starts at ${low:04x} (not $0801-aligned), keeping the real start"
                    ));
                    low
                };
                end = high;
                name = Some("Time Cruncher 5.x-6.x".into());
                classified = true;
            } else if (0x401..0x770).contains(&avg_pc) && (0x601..0x7ff).contains(&low) {
                // Cruel Cruncher. Its copy loop starts below $0801; save from
                // $0801 when the written data actually covers it, otherwise
                // keep the real start rather than forcing $0801.
                real_start = low;
                start = if low <= 0x0801 && high >= 0x0801 {
                    0x0801
                } else {
                    low
                };
                end = high;
                let cruel2x = Pattern::parse(CRUEL_2X_AT_0100).expect("builtin pattern");
                name = Some(if cruel2x.matches(m.mem.ram.as_ref(), 0x0100) {
                    "Cruel Cruncher 2.x-3.x".into()
                } else {
                    "Cruel Cruncher".into()
                });
                classified = true;
            }
        }
    }

    // ---- Byte Boozer: output streamed forward through a known zp pointer ----
    if let Some(ptr) = cfg.byteboozer_ptr {
        if let Some(r) = seqs.iter().find(|r| {
            r.mode == AddrMode::IndirectY && r.is_forward == Some(true) && r.base_ptr == ptr
        }) {
            start = r.min_addr();
            end = r.max_addr();
            if cfg.byteboozer_end_from_ptr {
                end = m.mem.read_word(ptr as u16);
            }
            name = Some(cfg.byteboozer_name.clone());
            classified = true;
        }
    }

    // ---- $0400 family: BASIC-aware start guessing ----
    // Operates on the (possibly merged) range start, not the raw largest range.
    if cfg.use_guess_start && largest.is_some() && !classified {
        let range_start = start;
        real_start = range_start;
        start = guess_start(m.mem.ram.as_ref(), range_start);
        // Evidence beats the heuristic: if the decruncher jumped INTO the
        // written data below the guessed start, that code is part of the
        // program, so keep the real range (e.g. a program that unpacks to $0500
        // and enters at $077F; snapping to $0801 would cut the entry off).
        if jump_start >= range_start && jump_start < start {
            log.push(format!(
                "run address ${jump_start:04x} lies below guessed start ${start:04x}, keeping range start ${range_start:04x}"
            ));
            start = range_start;
        }
        // The inverse also needs evidence. A $0801 guess well BELOW the traced
        // range is only real when the low BASIC line actually belongs to the
        // program. Otherwise it is the crunched file's own leftover bootstrap
        // and the payload lives elsewhere; snapping there would glue that
        // bootstrap plus unwritten memory onto the output. Evidence the low
        // line is genuine:
        //   * the depacker wrote into the gap  -- was_written survives flush(),
        //     so a line copied by a short direct loop (dropped from `seqs`)
        //     still counts;
        //   * the line's SYS target is where the depacker actually jumped
        //     (a rebuilt line restored during the untraced bootstrap phase
        //     leaves no write record, but its SYS still launches the payload);
        //   * the depacker jumped into the gap itself (it ran the low code).
        // (A few unwritten bytes are tolerated for depackers that reuse the
        // load-time line pointer at $0802.)
        if start < range_start && range_start - start > 8 {
            let gap_written = (start..range_start).any(|a| wl.was_written(a));
            let sys = crate::pattern::sys_address(m.mem.ram.as_ref());
            let sys_matches_jump = sys != 0 && sys == jump_start;
            let jumped_into_gap = jump_start >= start && jump_start < range_start;
            if !(gap_written || sys_matches_jump || jumped_into_gap) {
                log.push(format!(
                    "guessed start ${start:04x} rejected: no rebuilt line in \
                     ${start:04x}-${:04x} and its SYS target does not launch the \
                     payload; keeping range start ${range_start:04x}",
                    range_start - 1
                ));
                start = range_start;
            }
        }
    }

    // real_start reports the raw address before any snapping/adjustment below.
    if real_start == 0 {
        real_start = start;
    }

    // Sanity: a crunched file unpacks to MORE than its own size. A smaller
    // result usually means the engine exited on an intermediate jump.
    let packed_len = m.mem.prg_end as u32 - m.mem.prg_start as u32 + 1;
    let out_len = end as u32 - start as u32 + 1;
    if end >= start && out_len <= packed_len {
        log.push(format!(
            "warning: unpacked size {out_len} <= packed size {packed_len}, result is suspicious"
        ));
    }

    // Precedence: a behavioral classification stands as-is; otherwise a matched
    // variant refines name/start; otherwise plain generic gets the $0801 snap
    // for decrunchers that also rewrite the load-address bytes.
    if !classified {
        if let Some(v) = variant {
            name = Some(v.name.clone());
            if v.start_adjust != 0 {
                start = (start as i32 + v.start_adjust) as u16;
            }
        } else if cfg.snap_start.contains(&start) {
            log.push(format!(
                "start ${start:04x} snapped to ${:04x}",
                cfg.snap_to
            ));
            start = cfg.snap_to;
        }
    }

    EngineResult {
        ok: true,
        name,
        start,
        real_start,
        end,
        jump_start,
    }
}
