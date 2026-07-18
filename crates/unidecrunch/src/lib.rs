//! Detection and generic unpacking of C64 cruncher formats.
//!
//! The library runs a crunched PRG inside a 6510 emulator ([`mos6510`]), watches
//! what the decruncher writes where, and extracts the unpacked program without
//! knowing the compression format. Recognition signatures live in small config
//! files (see `configs/README.md`); the unpack strategies ("engines") live in
//! [`engine`].
//!
//! ```no_run
//! use unidecrunch::UniDecrunch;
//!
//! let ud = UniDecrunch::new();
//! if let Some(detection) = ud.detect_file(std::path::Path::new("crunched.prg")).unwrap() {
//!     println!("detected: {}", detection.name());
//!     let result = detection.decrunch().unwrap();
//!     println!("{}: ${:04x}-${:04x}", result.cruncher, result.start, result.end);
//!     result.save_prg_file(std::path::Path::new("out.prg")).unwrap();
//! }
//! ```

pub mod config;
pub mod detect;
mod embedded;
pub mod engine;
pub mod machine;
pub mod pattern;
pub mod writelist;

pub use detect::{Decrunched, Detection, UniDecrunch};
pub use machine::Machine;
