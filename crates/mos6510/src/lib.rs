//! MOS 6510 emulator core for cruncher/decruncher work.
//!
//! The CPU implements the complete NMOS opcode map: every documented opcode
//! plus all stable undocumented opcodes (SHA, SHX, SHY, TAS, LAS, ANE, LAX, the
//! multi-byte NOPs and the JAM group), which crunchers rely on heavily. Every
//! instruction records its memory access (`MemOp`) so callers can see which
//! addressing mode wrote where. A `Bus` trait lets the core drive banked C64
//! memory (`c64.rs`) with PLA banking and configurable memory areas.

pub mod c64;
pub mod cpu;

pub use c64::C64Mem;
pub use cpu::{AddrMode, Bus, Cpu, MemOp};
