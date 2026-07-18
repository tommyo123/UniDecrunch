//! UniDecrunch GUI (egui): open or drop a crunched C64 .prg, see what cruncher
//! it is, and save the unpacked program.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::mpsc;

use eframe::egui;
use unidecrunch::UniDecrunch;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([720.0, 480.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "UniDecrunch",
        options,
        Box::new(|_cc| Ok(Box::new(App::default()))),
    )
}

/// Outcome of one detect+decrunch job, produced on a worker thread.
struct JobResult {
    input: PathBuf,
    outcome: Result<Unpacked, String>,
}

struct Unpacked {
    cruncher: String,
    start: u16,
    end: u16,
    real_start: u16,
    jump_start: u16,
    prg: Vec<u8>,
    log: Vec<String>,
}

#[derive(Default)]
struct App {
    busy: Option<String>,
    rx: Option<mpsc::Receiver<JobResult>>,
    result: Option<JobResult>,
    status: String,
}

impl App {
    fn start_job(&mut self, path: PathBuf) {
        let (tx, rx) = mpsc::channel();
        self.busy = Some(path.display().to_string());
        self.rx = Some(rx);
        self.result = None;
        self.status.clear();
        std::thread::spawn(move || {
            let outcome = run_job(&path);
            let _ = tx.send(JobResult {
                input: path,
                outcome,
            });
        });
    }

    fn poll_job(&mut self) {
        if let Some(rx) = &self.rx {
            if let Ok(res) = rx.try_recv() {
                self.busy = None;
                self.rx = None;
                self.result = Some(res);
            }
        }
    }
}

fn run_job(path: &std::path::Path) -> Result<Unpacked, String> {
    let ud = UniDecrunch::with_embedded_configs()?;
    match ud.detect_file(path)? {
        None => Err("No known cruncher detected.".into()),
        Some(det) => {
            let d = det.decrunch()?;
            Ok(Unpacked {
                cruncher: d.cruncher,
                start: d.start,
                end: d.end,
                real_start: d.real_start,
                jump_start: d.jump_start,
                prg: d.prg,
                log: d.log,
            })
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_job();
        if self.busy.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        // Files dropped onto the window start a job immediately.
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        if self.busy.is_none() {
            if let Some(path) = dropped.into_iter().next() {
                self.start_job(path);
            }
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(self.busy.is_none(), egui::Button::new("Open .prg…"))
                    .clicked()
                {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("C64 program", &["prg", "PRG"])
                        .add_filter("All files", &["*"])
                        .pick_file()
                    {
                        self.start_job(path);
                    }
                }
                if let Some(b) = &self.busy {
                    ui.spinner();
                    ui.label(format!("Working on {b}…"));
                }
            });
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.label(&self.status);
        });

        egui::CentralPanel::default().show(ctx, |ui| match &self.result {
            None => {
                if self.busy.is_none() {
                    ui.centered_and_justified(|ui| {
                        ui.label("Drop a crunched .prg here (or use Open)");
                    });
                }
            }
            Some(res) => {
                ui.heading(
                    res.input
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                );
                match &res.outcome {
                    Err(e) => {
                        ui.colored_label(egui::Color32::LIGHT_RED, e);
                    }
                    Ok(u) => {
                        ui.label(format!("Cruncher: {}", u.cruncher));
                        ui.label(format!(
                            "Unpacked: ${:04x}-${:04x} ({} bytes), run address ${:04x}{}",
                            u.start,
                            u.end,
                            u.end as u32 - u.start as u32 + 1,
                            u.jump_start,
                            if u.real_start != u.start {
                                format!(" (raw start ${:04x})", u.real_start)
                            } else {
                                String::new()
                            }
                        ));
                        if ui.button("Save unpacked .prg…").clicked() {
                            let suggested = res
                                .input
                                .file_stem()
                                .map(|s| format!("{}.decrunched.prg", s.to_string_lossy()))
                                .unwrap_or_else(|| "decrunched.prg".into());
                            if let Some(target) =
                                rfd::FileDialog::new().set_file_name(suggested).save_file()
                            {
                                self.status = match std::fs::write(&target, &u.prg) {
                                    Ok(()) => format!("Saved {}", target.display()),
                                    Err(e) => format!("Save failed: {e}"),
                                };
                            }
                        }
                        ui.separator();
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for line in &u.log {
                                ui.monospace(line);
                            }
                        });
                    }
                }
            }
        });
    }
}
