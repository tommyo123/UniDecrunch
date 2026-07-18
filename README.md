# UniDecrunch

A Rust library that detects and unpacks C64 cruncher/packer formats **without
knowing the compression algorithm**. The crunched program is executed inside a
6510 emulator, every memory write of the depacker is traced, and the unpacked
program is lifted straight out of emulated RAM.

The core is a library meant to be embedded in other programs. Two runnable front
ends ship as examples.

## Workspace layout

| crate / dir | purpose |
|---|---|
| `crates/mos6510` | 6510 emulator library: full NMOS opcode map including stable illegal opcodes, BCD arithmetic, per-instruction memory-access tracking, C64 PLA banking, and deterministic KERNAL stubs. Reusable on its own. |
| `crates/unidecrunch` | The detection and unpacking library: pattern matching, config loading, write-range analysis, and the three unpack engines. |
| `crates/unidecrunch/examples/cli.rs` | Command-line front end. |
| `crates/unidecrunch/examples/gui.rs` | Drag-and-drop GUI (egui/eframe), behind the `gui` feature. |
| `configs/` | Cruncher definitions as small commented config files. Add new crunchers here with no recompile (see `configs/README.md`). The default set is also embedded in the library. |

## Using the library

```rust
use unidecrunch::UniDecrunch;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ud = UniDecrunch::new();
    if let Some(detection) = ud.detect_file(std::path::Path::new("crunched.prg"))? {
        println!("detected: {}", detection.name());
        let out = detection.decrunch()?;
        out.save_prg_file(std::path::Path::new("out.prg"))?;
    }
    Ok(())
}
```

`UniDecrunch::decrunch_file` combines detection and unpacking in one call and
falls through to later definitions when a matching engine fails. The 6510 core is
independent and can be used directly:

```rust
use mos6510::{C64Mem, Cpu, Bus};

let mut mem = C64Mem::new();
let mut cpu = Cpu::new();
cpu.reset_at(0x0810);
while cpu.step(&mut mem) {}
```

## Running the examples

```text
cargo run -p unidecrunch --example cli -- <input.prg> <output.prg> # detect, unpack, save
cargo run -p unidecrunch --example cli -- info <input.prg>         # detect and report only
cargo run -p unidecrunch --example cli -- scan <dir> [--out <dir>] # try every .prg in a directory
cargo run -p unidecrunch --example gui --features gui              # drag-and-drop GUI

# cli options
--configs <dir>    load cruncher definitions from a directory instead of the embedded set
--verbose, -v      print the engine trace log
```

## How it works

1. **Signature match** (`configs/*.toml`): byte patterns with `??` wildcards and
   `*N` search gaps, matched against the loaded PRG in emulated RAM. The first
   matching config wins (filename order).
2. **Run**: execution starts at the BASIC `SYS` address (parsed the way the C64
   does) or a fixed entry. The engine runs the bootstrap until the relocated
   depack stub is reached, then traces every write until the PC jumps into the
   unpacked program.
3. **Write-range analysis**: writes are folded into contiguous ranges per
   addressing mode. Indirect `(zp),Y` writes are grouped by their zero-page
   pointer, which bridges the gaps left by backward or paused depackers. The
   largest range is the program; shape heuristics classify several crunchers
   behaviorally.
4. Formats with known layouts read their exact boundaries from the depacker's own
   zero-page state instead of guessing.

## Behavior notes

* **Start addresses are never forced to $0801.** The library snaps to $0801 only
  when the written data actually lines up with it, and otherwise keeps the
  address the decruncher really used, so non-BASIC payloads are saved correctly.
* **C64 memory banking.** Memory banking follows the C64 PLA table. Detection
  uses deterministic KERNAL stubs so calls into the KERNAL return predictably.
* **Illegal-opcode writes are tracked.** The emulator records the memory writes
  made by undocumented store/RMW opcodes. The write-range analyzer filters them
  out by default for heuristic stability (`WriteList::include_illegal_writes`
  turns them back on).
* **Failed depacks return an error.** When a depacker never finishes, the library
  returns an error instead of writing a partial or garbage file.

## Adding a cruncher

Drop a `.toml` file in `configs/` (see `configs/README.md` for the syntax) and,
if it should be built into the library, add one `include_str!` line in
`crates/unidecrunch/src/embedded.rs`. No Rust code changes are needed for new
crunchers.

## Building and testing

```text
cargo build --release
cargo test --workspace
```

## License

MIT. See `LICENSE`.
