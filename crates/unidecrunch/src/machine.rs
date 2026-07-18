//! A ready-to-run C64: CPU + banked memory, with helpers the engines share.

use mos6510::{C64Mem, Cpu};

pub struct Machine {
    pub cpu: Cpu,
    pub mem: C64Mem,
}

impl Machine {
    pub fn new() -> Self {
        let mut mem = C64Mem::new();
        mem.init_basic_env();
        mem.stub_kernal();
        Machine {
            cpu: Cpu::new(),
            mem,
        }
    }

    pub fn step(&mut self) -> bool {
        self.cpu.step(&mut self.mem)
    }

    /// Run until the PC lands on one of `targets`. Returns true when a target is
    /// reached; false when the CPU stops (JAM/BRK) or `cap` instructions elapse.
    pub fn run_until(&mut self, targets: &[u16], cap: u64) -> bool {
        let mut n: u64 = 0;
        while n < cap {
            if !self.step() {
                return false;
            }
            n += 1;
            if targets.contains(&self.cpu.pc) {
                return true;
            }
        }
        false
    }
}
