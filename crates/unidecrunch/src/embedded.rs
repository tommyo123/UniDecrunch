//! The default cruncher definitions from `configs/`, embedded at build time.
//! They are evaluated in filename order, so keep the list sorted.
//!
//! Adding a new cruncher: drop a file in `configs/` and add one line here, or
//! skip the rebuild entirely and load the directory at runtime
//! (`UniDecrunch::with_config_dir`).

pub const EMBEDDED_CONFIGS: &[(&str, &str)] = &[
    (
        "10-crunchab-v1.0.toml",
        include_str!("../../../configs/10-crunchab-v1.0.toml"),
    ),
    (
        "20-timecruncher-3.1-network.toml",
        include_str!("../../../configs/20-timecruncher-3.1-network.toml"),
    ),
    (
        "21-timecruncher-3.2-network.toml",
        include_str!("../../../configs/21-timecruncher-3.2-network.toml"),
    ),
    (
        "22-timecruncher-4.2.toml",
        include_str!("../../../configs/22-timecruncher-4.2.toml"),
    ),
    (
        "50-generic-jmp-0100.toml",
        include_str!("../../../configs/50-generic-jmp-0100.toml"),
    ),
    (
        "51-generic-jmp-0010.toml",
        include_str!("../../../configs/51-generic-jmp-0010.toml"),
    ),
    (
        "52-generic-jmp-0008.toml",
        include_str!("../../../configs/52-generic-jmp-0008.toml"),
    ),
    (
        "53-generic-jmp-0334.toml",
        include_str!("../../../configs/53-generic-jmp-0334.toml"),
    ),
    (
        "54-generic-jmp-0400.toml",
        include_str!("../../../configs/54-generic-jmp-0400.toml"),
    ),
    (
        "55-generic-jmp-0410.toml",
        include_str!("../../../configs/55-generic-jmp-0410.toml"),
    ),
    (
        "56-generic-1-zeropage.toml",
        include_str!("../../../configs/56-generic-1-zeropage.toml"),
    ),
    (
        "60-generic-2-tapebuffer.toml",
        include_str!("../../../configs/60-generic-2-tapebuffer.toml"),
    ),
    (
        "61-generic-3-stackpage.toml",
        include_str!("../../../configs/61-generic-3-stackpage.toml"),
    ),
    (
        "62-generic-4-lowstub.toml",
        include_str!("../../../configs/62-generic-4-lowstub.toml"),
    ),
    (
        "63-generic-5-wide-0100.toml",
        include_str!("../../../configs/63-generic-5-wide-0100.toml"),
    ),
    (
        "69-generic-6-catchall.toml",
        include_str!("../../../configs/69-generic-6-catchall.toml"),
    ),
];
