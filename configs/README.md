# Cruncher definitions

Each `.toml` file in this directory teaches the library to recognize one cruncher
(or one family of crunchers). Files are evaluated in **filename order**: the first
file whose detection matches wins, so specific crunchers get low numbers and the
generic catch-alls get high numbers.

**Ordering principle:** the manually tuned detectors (10-55: CrunchAB, the Time
Cruncher family, the classic `Generic at $xxxx` families with their variants and
behavioral classification) always come first, and their verdicts are trusted. The
`Generic N` families (56+) only ever see a file when no tuned detector matched, or
when a tuned detector matched but its depacker demonstrably failed to finish
(fall-through). Keep new tuned crunchers below 56 and new broad catch-alls above;
`69-generic-6-catchall` must stay last.

The default set is embedded into the library at build time; you can also point the
CLI at any directory of config files with `--configs <dir>` to experiment without
recompiling.

## Anatomy of a config

```toml
# Free-form comments everywhere. Say what the cruncher is and how you found it.
name = "My Cruncher v1.0"     # shown to the user when detected
engine = "generic"            # which unpack strategy to run (see Engines below)

[detect]
base = 0x0801                 # RAM address where the pattern must match
pattern = "A9 34 85 01 *16 4C 00 01"
entry = "sys"                 # where execution starts: "sys" reads the BASIC SYS
                              # line like the C64 would; or a fixed address (0x0818)

[run]                         # parameters for the engine (all optional)
stop_pc = [0x0100, 0x0101]    # phase 1 ends when the PC lands on one of these
exit_above = 0x0800           # phase 2 ends when the PC jumps above this
```

## Pattern syntax

Patterns are byte sequences matched against emulated RAM:

| token | meaning |
|-------|---------|
| `A9`  | this exact byte |
| `??`  | any byte (self-modified bytes, addresses that vary between files) |
| `*96` | a gap: skip **up to** 96 bytes until the next byte in the pattern matches |

Long patterns can be split over several lines as an array of strings:

```toml
pattern = [
    "A9 34 85 01 A0 C4",
    "B9 3C 08 99 F8 00",
]
```

Use `any_of` instead of `pattern` when several signatures should lead to the same
cruncher:

```toml
any_of = ["*768 4C 00 01", "*768 4C 01 01"]
```

## Engines

The *pattern* part of recognition lives in these files. The *unpacking strategy*
(and any behavior-based classification) lives in the library, selected by `engine`:

* `generic`: the workhorse. Runs the decruncher in the emulator until the PC
  reaches `stop_pc` (the relocated depack loop), then traces every memory write
  until the PC jumps above `exit_above` (into the unpacked program). The largest
  written range is the unpacked program; `[run]` options fine-tune how its start
  address is chosen.
* `timecruncher`: Time Cruncher 3.x/4.2 keep their output boundaries in zero page
  ($FC/$FD); this engine reads them directly instead of guessing. `version = 31`
  or `42` selects the address layout.
* `crunchab`: CrunchAB relocates itself to $0340 first; a `[probe]` section runs
  it that far, verifies the relocated code and captures the end address, and the
  engine then finishes the depack and reads start/jump addresses from $040B/$040E.

### `[run]` options for `engine = "generic"`

| key | meaning |
|-----|---------|
| `stop_pc` | address(es) of the relocated depack stub (phase 1 target) |
| `stop_below` | family-wide phase 1: any PC below this = the stub took over (covers whole ranges of stub addresses) |
| `exit_above` | PC above this = decrunching done (phase 2 exit) |
| `exit_into_written` | stricter exit: the PC must also land on an address the depacker itself wrote (i.e. jump into the unpacked program). Also enables the ROM-excursion guard (a `JSR` into ROM is not a hand-off) and the stage-2 filter (a jump deep inside the output range is the next depack stage, not the program) |
| `exit_quiescent` | run until no new byte has been written for N instructions and report the first plausible hand-off as run address; for nested multi-stage depackers that jump through their own output while unpacking |
| `trim_page_overshoot` | "depack high, page-copy down" movers copy whole pages; trim the tail using the staging range's exact size |
| `snap_start` | if the detected start is one of these, use `snap_to` instead; decrunchers that also rewrite the two-byte load-address bytes just below $0801 land here |
| `snap_to` | default `0x0801` |
| `analyze_0100` | enable the behavioral Time Cruncher 5.x / Cruel Cruncher classification (write-direction + average-PC analysis; see `engine/generic.rs`) |
| `byteboozer_ptr` | classify as Byte Boozer when output is written forward through `(ptr),Y` with this zero-page pointer |
| `byteboozer_end_from_ptr` | read the end address from that pointer after depack |
| `use_guess_start` | derive the start address with the BASIC-aware `guess_start` heuristic; overridden by evidence when the decruncher demonstrably jumps into data below the guess |

`[detect]` additionally accepts `always = true` for last-resort catch-all
definitions with no signature (keep those last!). Detection **falls through**:
when a definition matches but its depacker never finishes, the next matching
definition gets a try, since several families share bootstrap signatures.

### `[[variant]]`: refinements

A variant is an extra pattern probed **before** the run to give a more precise name
(and optionally correct the start address). The last matching variant wins:

```toml
[[variant]]
name = "Time Cruncher v4.5+"
base = 0x084E
start_adjust = 1            # added to the detected start address
pattern = [ ... ]
```

## Start addresses and $0801

Several crunchers unpack BASIC programs to $0801 but leave their first visible
write just below it (the copy loop also rewrites the load-address bytes). The
library snaps to $0801 only when the evidence supports it (`snap_start`, or the
written range actually covers $0801); otherwise it keeps the address the
decruncher really used, so non-BASIC payloads are saved correctly.
