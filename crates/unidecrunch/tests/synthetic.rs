//! End-to-end test with a synthetic "cruncher": a hand-assembled PRG that
//! behaves like the real ones, with a BASIC SYS line, a bootstrap that
//! relocates a depack stub to $0100, a (zp),Y write loop producing the
//! "unpacked" data, and a final jump into it. Exercises detection (embedded
//! configs), the generic engine, write tracing and PRG extraction.

use unidecrunch::UniDecrunch;

/// Build the synthetic crunched PRG (load address $0801).
fn synthetic_prg() -> Vec<u8> {
    let mut prg = vec![0x01, 0x08]; // load address $0801

    // $0801: 10 SYS2061 : REM basic stub
    prg.extend_from_slice(&[
        0x0B, 0x08, // next line at $080B
        0x0A, 0x00, // line 10
        0x9E, b'2', b'0', b'6', b'1', 0x00, // SYS2061
        0x00, 0x00, // end of program
    ]);

    // $080D: bootstrap, copy the stub to $0100, then JMP $0100
    prg.extend_from_slice(&[
        0xA2, 0x00, // LDX #$00
        0xBD, 0x1D, 0x08, // LDA $081D,X   (stub source, below)
        0x9D, 0x00, 0x01, // STA $0100,X
        0xE8, // INX
        0xE0, 0x1C, // CPX #$1C
        0xD0, 0xF5, // BNE loop ($080F)
        0x4C, 0x00, 0x01, // JMP $0100
    ]);

    // $081D: the depack stub, assembled for $0100. Writes $AA over
    // $2000-$21FF through ($FB),Y and jumps to $2000.
    prg.extend_from_slice(&[
        0xA9, 0x00, // LDA #$00
        0x85, 0xFB, // STA $FB
        0xA9, 0x20, // LDA #$20
        0x85, 0xFC, // STA $FC
        0xA0, 0x00, // LDY #$00
        0xA9, 0xAA, // LDA #$AA      <- $010A
        0x91, 0xFB, // STA ($FB),Y   <- $010C
        0xC8, // INY
        0xD0, 0xFB, // BNE $010C
        0xE6, 0xFC, // INC $FC
        0xA5, 0xFC, // LDA $FC
        0xC9, 0x22, // CMP #$22
        0x90, 0xF1, // BCC $010A
        0x4C, 0x00, 0x20, // JMP $2000
    ]);
    prg
}

#[test]
fn synthetic_cruncher_is_detected_and_unpacked() {
    let ud = UniDecrunch::with_embedded_configs().expect("embedded configs parse");
    let det = ud
        .detect_bytes(&synthetic_prg())
        .expect("detection runs")
        .expect("recognized as generic $0100");
    assert_eq!(det.name(), "Generic at $0100");

    let d = det.decrunch().expect("depack succeeds");
    assert_eq!(d.start, 0x2000);
    assert_eq!(d.end, 0x21FF);
    assert_eq!(d.jump_start, 0x2000);
    // PRG image: load address + 512 bytes of $AA
    assert_eq!(d.prg.len(), 2 + 512);
    assert_eq!(&d.prg[..2], &[0x00, 0x20]);
    assert!(d.prg[2..].iter().all(|&b| b == 0xAA));
}

/// A `$0400`-family (use_guess_start) cruncher whose real program lives at
/// $0801: the bootstrap restores the BASIC SYS line at $0801-$080C *before*
/// write tracing starts (an untraced phase-1 write), the depack stub at $0400
/// streams the body $080D-$1FFF, then jumps to the SYS target $080D. The
/// guessed start ($0801) must be kept (its SYS target is where the depacker
/// jumped) even though nothing was traced in the $0801-$080C gap. Guards
/// against over-rejecting a genuine low start.
fn synthetic_0400_basic_prg() -> Vec<u8> {
    let mut prg = vec![0x01, 0x08]; // load address $0801

    // $0801: 0 SYS2061 line, already in place at load time.
    prg.extend_from_slice(&[
        0x0B, 0x08, // next line at $080B
        0x00, 0x00, // line 0
        0x9E, b'2', b'0', b'6', b'1', 0x00, // SYS2061 -> $080D
        0x00, 0x00, // end of program
    ]);

    // $080D: bootstrap. Copy the depack stub to $0400 and JMP $0400. The
    // $0801 line is already present (load time = untraced), matching a
    // depacker that restores the header before the traced depack phase.
    prg.extend_from_slice(&[
        0xA2, 0x00, // LDX #$00
        0xBD, 0x1D, 0x08, // LDA $081D,X
        0x9D, 0x00, 0x04, // STA $0400,X
        0xE8, // INX
        0xE0, 0x1D, // CPX #$1D
        0xD0, 0xF5, // BNE ($080F)
        0x4C, 0x00, 0x04, // JMP $0400
    ]);

    // $081D: depack stub assembled for $0400. Streams $EE over $080D-$1FFF
    // through ($FB),Y (the traced body, starting above the BASIC line) and
    // jumps to the SYS target $080D.
    prg.extend_from_slice(&[
        0xA9, 0x0D, // LDA #$0D
        0x85, 0xFB, // STA $FB
        0xA9, 0x08, // LDA #$08
        0x85, 0xFC, // STA $FC
        0xA0, 0x00, // LDY #$00
        0xA9, 0xEE, // LDA #$EE      <- body fill byte, $040A
        0x91, 0xFB, // STA ($FB),Y   <- $040C
        0xC8, // INY
        0xD0, 0xFB, // BNE ($040C)
        0xE6, 0xFC, // INC $FC
        0xA5, 0xFC, // LDA $FC
        0xC9, 0x20, // CMP #$20      (stop once $FC reaches $20 -> wrote up to $1FFF)
        0x90, 0xF1, // BCC ($040A)
        0x4C, 0x0D, 0x08, // JMP $080D
    ]);
    prg
}

#[test]
fn generic_0400_keeps_real_0801_start_when_sys_launches_payload() {
    let ud = UniDecrunch::with_embedded_configs().unwrap();
    let d = ud
        .decrunch_bytes(&synthetic_0400_basic_prg())
        .expect("detection runs")
        .expect("recognized and unpacked");
    // The $0801 line is genuine here (its SYS $080D is where the depacker
    // jumped), so the start must NOT be pushed up to the traced body $080D.
    assert_eq!(
        d.start, 0x0801,
        "real $0801 start wrongly rejected ({})",
        d.cruncher
    );
    assert_eq!(d.jump_start, 0x080D);
    // The BASIC line bytes at $0801-$080C survive in the output.
    assert_eq!(&d.prg[..2], &[0x01, 0x08]);
    assert_eq!(d.prg[2], 0x0B, "next-line pointer lost");
}

#[test]
fn plain_basic_program_is_not_recognized() {
    // 10 PRINT"HI" with no cruncher signatures anywhere.
    let mut prg = vec![0x01, 0x08];
    prg.extend_from_slice(&[
        0x0B, 0x08, 0x0A, 0x00, 0x99, b'"', b'H', b'I', b'"', 0x00, 0x00, 0x00,
    ]);
    let ud = UniDecrunch::with_embedded_configs().unwrap();
    assert!(ud.detect_bytes(&prg).unwrap().is_none());
}
