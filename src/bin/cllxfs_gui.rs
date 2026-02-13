#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use sysinfo::System;

#[derive(PartialEq, Clone, Copy)]
enum Language {
    English,
    Chinese,
}

impl Language {
    fn toggle(&self) -> Self {
        match self {
            Language::English => Language::Chinese,
            Language::Chinese => Language::English,
        }
    }
    
    fn button_text(&self) -> &str {
        match self {
            Language::English => "中",
            Language::Chinese => "Eng",
        }
    }
}

struct Texts {
    title: &'static str,
    subtitle: &'static str,
    mode_encrypt: &'static str,
    mode_decrypt: &'static str,
    input_file: &'static str,
    output_file: &'static str,
    select_file: &'static str,
    select_folder: &'static str,
    save_as: &'static str,
    password: &'static str,
    password_hint: &'static str,
    chunk_size: &'static str,
    bytes: &'static str,
    embed_key: &'static str,
    start_encryption: &'static str,
    start_decryption: &'static str,
    status_log: &'static str,
    ready: &'static str,
    system_monitor: &'static str,
    cpu_usage: &'static str,
    memory_usage: &'static str,
    system_info: &'static str,
    cpu_cores: &'static str,
    total_memory: &'static str,
    processing: &'static str,
    input_folder: &'static str,
    output_folder: &'static str,
}

const TEXTS_EN: Texts = Texts {
    title: "cllX-FS",
    subtitle: "Post-Quantum Secure File Encryption",
    mode_encrypt: "Encrypt",
    mode_decrypt: "Decrypt",
    input_file: "Input File:",
    output_file: "Output File:",
    select_file: "Select File",
    select_folder: "Select Folder",
    save_as: "Save As",
    password: "Password:",
    password_hint: "Optional",
    chunk_size: "Chunk Size:",
    bytes: "bytes",
    embed_key: "Embed key in encrypted file (convenient but less secure)",
    start_encryption: "Start Encryption",
    start_decryption: "Start Decryption",
    status_log: "Status Log:",
    ready: "Ready...",
    system_monitor: "System Monitor",
    cpu_usage: "CPU Usage",
    memory_usage: "Memory Usage",
    system_info: "System Info",
    cpu_cores: "CPU Cores",
    total_memory: "Total Memory",
    processing: "⚙ Processing...",
    input_folder: "Input Folder:",
    output_folder: "Output Folder:",
};

const TEXTS_CN: Texts = Texts {
    title: "cllX-FS",
    subtitle: "后量子安全文件加密系统",
    mode_encrypt: "加密",
    mode_decrypt: "解密",
    input_file: "输入文件：",
    output_file: "输出文件：",
    select_file: "选择文件",
    select_folder: "选择文件夹",
    save_as: "另存为",
    password: "密码：",
    password_hint: "可选",
    chunk_size: "分块大小：",
    bytes: "字节",
    embed_key: "将密钥嵌入加密文件（方便但安全性较低）",
    start_encryption: "开始加密",
    start_decryption: "开始解密",
    status_log: "状态日志：",
    ready: "就绪...",
    system_monitor: "系统监控",
    cpu_usage: "CPU 占用",
    memory_usage: "内存占用",
    system_info: "系统信息",
    cpu_cores: "CPU 核心",
    total_memory: "总内存",
    processing: "⚙ 处理中...",
    input_folder: "输入文件夹：",
    output_folder: "输出文件夹：",
};

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 650.0])
            .with_min_inner_size([800.0, 500.0])
            .with_icon(
                eframe::icon_data::from_png_bytes(&[]).unwrap_or_default(),
            ),
        ..Default::default()
    };

    eframe::run_native(
        "cllX-FS",
        options,
        Box::new(|cc| {
            // Setup custom fonts to support Chinese characters
            setup_custom_fonts(&cc.egui_ctx);
            Box::new(CllxFsApp::default())
        }),
    )
}

fn setup_custom_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    
    // Try to load system fonts for Chinese support
    // On Windows, try common Chinese fonts
    let chinese_font_paths = vec![
        "C:\\Windows\\Fonts\\msyh.ttc",      // Microsoft YaHei
        "C:\\Windows\\Fonts\\simhei.ttf",    // SimHei
        "C:\\Windows\\Fonts\\simsun.ttc",    // SimSun
        "C:\\Windows\\Fonts\\msyhbd.ttc",    // Microsoft YaHei Bold
    ];
    
    let mut font_loaded = false;
    for font_path in chinese_font_paths {
        if let Ok(font_data) = std::fs::read(font_path) {
            fonts.font_data.insert(
                "chinese_font".to_owned(),
                egui::FontData::from_owned(font_data),
            );
            
            // Add to proportional fonts (for UI text)
            fonts.families.entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "chinese_font".to_owned());
            
            // Add to monospace fonts (for code/fixed-width text)
            fonts.families.entry(egui::FontFamily::Monospace)
                .or_default()
                .push("chinese_font".to_owned());
            
            font_loaded = true;
            break;
        }
    }
    
    if !font_loaded {
        eprintln!("Warning: Could not load Chinese font. Chinese characters may not display correctly.");
    }
    
    ctx.set_fonts(fonts);
}

struct CllxFsApp {
    mode: AppMode,
    input_file: Option<PathBuf>,
    output_file: Option<PathBuf>,
    input_folder: Option<PathBuf>,
    output_folder: Option<PathBuf>,
    is_folder_mode: bool,
    password: String,
    chunk_size: String,
    embed_key: bool,
    language: Language,
    status: Arc<Mutex<String>>,
    progress: Arc<Mutex<f32>>,
    is_processing: bool,
    processing_flag: Option<Arc<Mutex<bool>>>,
    system: System,
    cpu_usage: f32,
    memory_usage: f64,
    last_update: std::time::Instant,
}

#[derive(PartialEq, Clone)]
enum AppMode {
    Encrypt,
    Decrypt,
}

impl Default for CllxFsApp {
    fn default() -> Self {
        Self {
            mode: AppMode::Encrypt,
            input_file: None,
            output_file: None,
            input_folder: None,
            output_folder: None,
            is_folder_mode: false,
            password: String::new(),
            chunk_size: String::from("1048576"),
            embed_key: true,
            language: Language::English,
            status: Arc::new(Mutex::new(String::new())),
            progress: Arc::new(Mutex::new(0.0)),
            is_processing: false,
            processing_flag: None,
            system: System::new_all(),
            cpu_usage: 0.0,
            memory_usage: 0.0,
            last_update: std::time::Instant::now(),
        }
    }
}

impl eframe::App for CllxFsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Update system info every second
        if self.last_update.elapsed().as_secs() >= 1 {
            self.system.refresh_cpu();
            self.system.refresh_memory();
            
            // Get global CPU usage
            self.cpu_usage = self.system.global_cpu_info().cpu_usage();
            
            // Get memory usage
            let used_memory = self.system.used_memory() as f64;
            let total_memory = self.system.total_memory() as f64;
            self.memory_usage = (used_memory / total_memory) * 100.0;
            
            self.last_update = std::time::Instant::now();
        }
        
        egui::CentralPanel::default().show(ctx, |ui| {
            // Get current language texts
            let texts = match self.language {
                Language::English => &TEXTS_EN,
                Language::Chinese => &TEXTS_CN,
            };
            
            // Use columns layout for better control
            egui::TopBottomPanel::top("top_panel").show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.heading(texts.title);
                        ui.label(texts.subtitle);
                    });
                    
                    // Language toggle button on the right
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(self.language.button_text()).clicked() {
                            self.language = self.language.toggle();
                        }
                    });
                });
            });
            
            // Main content area with columns
            ui.columns(2, |columns| {
                // Left column - Main controls
                columns[0].vertical(|ui| {
                    ui.add_space(10.0);

                    // Mode selection
                    ui.horizontal(|ui| {
                        let old_mode = self.mode.clone();
                        ui.selectable_value(&mut self.mode, AppMode::Encrypt, texts.mode_encrypt);
                        ui.selectable_value(&mut self.mode, AppMode::Decrypt, texts.mode_decrypt);
                        
                        // Clear file selections when mode changes
                        if old_mode != self.mode {
                            self.input_file = None;
                            self.output_file = None;
                        }
                    });
                    ui.add_space(10.0);

                    // Input file/folder selection
                    if !self.is_folder_mode {
                        ui.horizontal(|ui| {
                            ui.label(texts.input_file);
                            if ui.button(texts.select_file).clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_file() {
                                    self.input_file = Some(path);
                                    self.input_folder = None;
                                }
                            }
                            if ui.button(texts.select_folder).clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                    self.input_folder = Some(path);
                                    self.input_file = None;
                                    self.is_folder_mode = true;
                                }
                            }
                        });
                        if let Some(ref path) = self.input_file {
                            ui.label(path.display().to_string());
                        }
                    } else {
                        ui.horizontal(|ui| {
                            ui.label(texts.input_folder);
                            if ui.button(texts.select_folder).clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                    self.input_folder = Some(path);
                                }
                            }
                            if ui.button(texts.select_file).clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_file() {
                                    self.input_file = Some(path);
                                    self.input_folder = None;
                                    self.is_folder_mode = false;
                                }
                            }
                        });
                        if let Some(ref path) = self.input_folder {
                            ui.label(path.display().to_string());
                        }
                    }
                    ui.add_space(5.0);

                    // Output file/folder selection
                    if !self.is_folder_mode {
                        // 单文件模式：输出文件
                        ui.horizontal(|ui| {
                            ui.label(texts.output_file);
                            if ui.button(texts.save_as).clicked() {
                                let mut dialog = rfd::FileDialog::new();
                                
                                // Set default filename based on input file
                                if let Some(ref input_path) = self.input_file {
                                    if let Some(filename) = input_path.file_stem() {
                                        let default_name = if self.mode == AppMode::Encrypt {
                                            format!("{}.cllx", filename.to_string_lossy())
                                        } else {
                                            filename.to_string_lossy().to_string()
                                        };
                                        dialog = dialog.set_file_name(&default_name);
                                    }
                                    
                                    if let Some(parent) = input_path.parent() {
                                        dialog = dialog.set_directory(parent);
                                    }
                                }
                                
                                if self.mode == AppMode::Encrypt {
                                    dialog = dialog.add_filter("Encrypted Files", &["cllx"]);
                                }
                                
                                if let Some(path) = dialog.save_file() {
                                    self.output_file = Some(path);
                                    self.output_folder = None;
                                }
                            }
                        });
                        if let Some(ref path) = self.output_file {
                            ui.label(path.display().to_string());
                        }
                    } else {
                        // 文件夹模式
                        if self.mode == AppMode::Encrypt {
                            // 加密模式：输出单个.cllx文件
                            ui.horizontal(|ui| {
                                ui.label(texts.output_file);
                                if ui.button(texts.save_as).clicked() {
                                    let mut dialog = rfd::FileDialog::new();
                                    
                                    // Set default filename based on input folder
                                    if let Some(ref input_path) = self.input_folder {
                                        if let Some(filename) = input_path.file_name() {
                                            let default_name = format!("{}.cllx", filename.to_string_lossy());
                                            dialog = dialog.set_file_name(&default_name);
                                        }
                                        
                                        if let Some(parent) = input_path.parent() {
                                            dialog = dialog.set_directory(parent);
                                        }
                                    }
                                    
                                    dialog = dialog.add_filter("Encrypted Files", &["cllx"]);
                                    
                                    if let Some(path) = dialog.save_file() {
                                        self.output_file = Some(path);
                                        self.output_folder = None;
                                    }
                                }
                            });
                            if let Some(ref path) = self.output_file {
                                ui.label(path.display().to_string());
                            }
                        } else {
                            // 解密模式：输出文件夹
                            ui.horizontal(|ui| {
                                ui.label(texts.output_folder);
                                if ui.button(texts.select_folder).clicked() {
                                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                        self.output_folder = Some(path);
                                        self.output_file = None;
                                    }
                                }
                            });
                            if let Some(ref path) = self.output_folder {
                                ui.label(path.display().to_string());
                            }
                        }
                    }
                    ui.add_space(10.0);

                    // Password input
                    ui.horizontal(|ui| {
                        ui.label(texts.password);
                        ui.add(egui::TextEdit::singleline(&mut self.password)
                            .password(true)
                            .hint_text(texts.password_hint));
                    });
                    ui.add_space(5.0);

                    // Chunk size (only for encryption)
                    if self.mode == AppMode::Encrypt {
                        ui.horizontal(|ui| {
                            ui.label(texts.chunk_size);
                            ui.add(egui::TextEdit::singleline(&mut self.chunk_size)
                                .hint_text("1048576"));
                            ui.label(texts.bytes);
                        });
                        ui.add_space(5.0);
                        
                        // Embed key option
                        ui.checkbox(&mut self.embed_key, texts.embed_key);
                        ui.add_space(10.0);
                    }

                    // Action button
                    ui.add_space(10.0);
                    let button_text = match self.mode {
                        AppMode::Encrypt => texts.start_encryption,
                        AppMode::Decrypt => texts.start_decryption,
                    };

                    let can_process = if self.is_folder_mode {
                        if self.mode == AppMode::Encrypt {
                            // 加密模式：需要输入文件夹和输出文件
                            self.input_folder.is_some() && self.output_file.is_some() && !self.is_processing
                        } else {
                            // 解密模式：需要输入文件和输出文件夹
                            self.input_file.is_some() && self.output_folder.is_some() && !self.is_processing
                        }
                    } else {
                        self.input_file.is_some() && self.output_file.is_some() && !self.is_processing
                    };

                    if ui.add_enabled(can_process, egui::Button::new(button_text).min_size(egui::vec2(180.0, 35.0))).clicked() {
                        self.start_processing();
                    }

                    ui.add_space(10.0);

                    // Progress bar
                    if self.is_processing {
                        let progress = *self.progress.lock().unwrap();
                        ui.add(egui::ProgressBar::new(progress).show_percentage());
                        ui.add_space(5.0);
                    }

                    // Status display with auto-scroll
                    ui.separator();
                    ui.add_space(5.0);
                    ui.label(egui::RichText::new(texts.status_log).strong());
                    ui.add_space(3.0);
                    
                    let status = self.status.lock().unwrap().clone();
                    egui::ScrollArea::vertical()
                        .max_height(180.0)
                        .auto_shrink([false; 2])
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            if status.is_empty() {
                                ui.label(egui::RichText::new(texts.ready).italics().weak());
                            } else {
                                ui.label(&status);
                            }
                        });
                });
                
                // Right column - System monitor
                columns[1].vertical(|ui| {
                    ui.add_space(10.0);
                    ui.heading(texts.system_monitor);
                    ui.add_space(15.0);
                    
                    // CPU Usage
                    ui.label(egui::RichText::new(texts.cpu_usage).strong());
                    ui.add_space(5.0);
                    ui.add(egui::ProgressBar::new(self.cpu_usage / 100.0)
                        .text(format!("{:.1}%", self.cpu_usage))
                        .fill(if self.cpu_usage > 80.0 {
                            egui::Color32::from_rgb(255, 100, 100)
                        } else if self.cpu_usage > 50.0 {
                            egui::Color32::from_rgb(255, 200, 100)
                        } else {
                            egui::Color32::from_rgb(100, 200, 100)
                        }));
                    
                    ui.add_space(15.0);
                    
                    // Memory Usage
                    ui.label(egui::RichText::new(texts.memory_usage).strong());
                    ui.add_space(5.0);
                    let used_mb = self.system.used_memory() as f64 / 1024.0 / 1024.0;
                    let total_mb = self.system.total_memory() as f64 / 1024.0 / 1024.0;
                    ui.add(egui::ProgressBar::new((self.memory_usage / 100.0) as f32)
                        .text(format!("{:.1}% ({:.0}/{:.0} MB)", self.memory_usage, used_mb, total_mb))
                        .fill(if self.memory_usage > 80.0 {
                            egui::Color32::from_rgb(255, 100, 100)
                        } else if self.memory_usage > 50.0 {
                            egui::Color32::from_rgb(255, 200, 100)
                        } else {
                            egui::Color32::from_rgb(100, 200, 100)
                        }));
                    
                    ui.add_space(15.0);
                    ui.separator();
                    ui.add_space(10.0);
                    
                    // System Info
                    ui.label(egui::RichText::new(texts.system_info).strong());
                    ui.add_space(5.0);
                    ui.label(format!("{}: {}", texts.cpu_cores, self.system.cpus().len()));
                    ui.label(format!("{}: {:.2} GB", texts.total_memory,
                        self.system.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0));
                    
                    if self.is_processing {
                        ui.add_space(15.0);
                        ui.separator();
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new(texts.processing).color(egui::Color32::from_rgb(100, 200, 255)));
                    }
                });
            });
        });

        // Check if processing is complete
        if let Some(ref flag) = self.processing_flag {
            if !*flag.lock().unwrap() {
                self.is_processing = false;
                self.processing_flag = None;
            }
        }

        // Request repaint if processing or to update system monitor
        if self.is_processing || self.last_update.elapsed().as_millis() > 500 {
            ctx.request_repaint();
        }
    }
}

impl CllxFsApp {
    fn start_processing(&mut self) {
        self.is_processing = true;
        *self.status.lock().unwrap() = String::from("Processing...\n");
        *self.progress.lock().unwrap() = 0.0;

        let password = if self.password.is_empty() {
            None
        } else {
            Some(self.password.clone())
        };
        let chunk_size = self.chunk_size.parse::<usize>().unwrap_or(1048576);
        let embed_key = self.embed_key;
        let mode = self.mode.clone();
        let status = Arc::clone(&self.status);
        let progress = Arc::clone(&self.progress);
        
        // 创建 a flag to track processing completion
        let is_processing = Arc::new(Mutex::new(true));
        let is_processing_clone = Arc::clone(&is_processing);

        if self.is_folder_mode {
            // 文件夹模式
            if self.mode == AppMode::Encrypt {
                // 加密：文件夹 -> .cllx文件
                let input_folder = self.input_folder.clone().unwrap();
                let output_file = self.output_file.clone().unwrap();
                
                thread::spawn(move || {
                    let result = Self::encrypt_folder(
                        input_folder, 
                        output_file, 
                        password, 
                        chunk_size, 
                        embed_key, 
                        status.clone(), 
                        progress.clone()
                    );

                    let mut status_lock = status.lock().unwrap();
                    match result {
                        Ok(_) => {
                            status_lock.push_str("\nCompleted successfully!\n");
                            *progress.lock().unwrap() = 1.0;
                        }
                        Err(e) => {
                            status_lock.push_str(&format!("\nError: {}\n", e));
                        }
                    }
                    
                    *is_processing_clone.lock().unwrap() = false;
                });
            } else {
                // 解密：.cllx文件 -> 文件夹
                let input_file = self.input_file.clone().unwrap();
                let output_folder = self.output_folder.clone().unwrap();
                
                thread::spawn(move || {
                    let result = Self::decrypt_folder(
                        input_file, 
                        output_folder, 
                        password, 
                        status.clone(), 
                        progress.clone()
                    );

                    let mut status_lock = status.lock().unwrap();
                    match result {
                        Ok(_) => {
                            status_lock.push_str("\nCompleted successfully!\n");
                            *progress.lock().unwrap() = 1.0;
                        }
                        Err(e) => {
                            status_lock.push_str(&format!("\nError: {}\n", e));
                        }
                    }
                    
                    *is_processing_clone.lock().unwrap() = false;
                });
            }
        } else {
            // 单文件模式
            let input_file = self.input_file.clone().unwrap();
            let output_file = self.output_file.clone().unwrap();
            
            thread::spawn(move || {
                let result = match mode {
                    AppMode::Encrypt => {
                        Self::encrypt_file(input_file, output_file, password, chunk_size, embed_key, status.clone(), progress.clone())
                    }
                    AppMode::Decrypt => {
                        Self::decrypt_file(input_file, output_file, password, status.clone(), progress.clone())
                    }
                };

                let mut status_lock = status.lock().unwrap();
                match result {
                    Ok(_) => {
                        status_lock.push_str("\nCompleted successfully!\n");
                        *progress.lock().unwrap() = 1.0;
                    }
                    Err(e) => {
                        status_lock.push_str(&format!("\nError: {}\n", e));
                    }
                }
                
                *is_processing_clone.lock().unwrap() = false;
            });
        }
        
        // Store the processing flag for checking in update()
        self.processing_flag = Some(is_processing);
    }

    fn encrypt_file(
        input: PathBuf,
        output: PathBuf,
        password: Option<String>,
        chunk_size: usize,
        embed_key: bool,
        status: Arc<Mutex<String>>,
        progress: Arc<Mutex<f32>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::{File, OpenOptions};
        use std::io::{Read, Write};
        use cllx_fs_pro::core::{MasterKey, KeyDerivation, CipherType};
        use cllx_fs_pro::capsule::mlkem;
        use cllx_fs_pro::chunk::ChunkEngine;

        // Get file size without reading entire file
        status.lock().unwrap().push_str(&format!("Analyzing file: {}\n", input.display()));
        *progress.lock().unwrap() = 0.05;
        
        // Open input file with explicit read-only access
        let mut input_file = match OpenOptions::new()
            .read(true)
            .write(false)
            .open(&input) {
            Ok(f) => f,
            Err(e) => {
                return Err(format!("Cannot open input file '{}': {} (Error code: {:?}). The file may be in use by another program or you don't have read permission.", 
                    input.display(), e, e.kind()).into());
            }
        };
        
        let total_size = input_file.metadata()?.len() as usize;
        let total_chunks = (total_size + chunk_size - 1) / chunk_size;
        
        status.lock().unwrap().push_str(&format!("File size: {} bytes ({} chunks)\n", total_size, total_chunks));
        *progress.lock().unwrap() = 0.1;

        // 生成 master key
        let master_key = MasterKey::generate();
        let keypair = mlkem::MlKemKeyPair::generate()?;
        
        // Prepare secret key data (for embedding or saving to file)
        let secret_key_data = if let Some(password) = &password {
            status.lock().unwrap().push_str("Using password-based encryption\n");
            
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            hasher.update(b"cllx-password-key");
            let password_key: [u8; 32] = hasher.finalize().into();
            
            let cipher = cllx_fs_pro::core::crypto::AeadCipher::new(CipherType::ChaCha20Poly1305);
            let nonce = [0u8; 12];
            let encrypted_secret_key = cipher.encrypt(
                &password_key,
                &nonce,
                keypair.secret_key_bytes(),
                b"cllx-password-protected"
            )?;
            
            let mut data = Vec::new();
            data.extend_from_slice(b"CLLX-PWD");
            data.extend_from_slice(&encrypted_secret_key);
            data
        } else {
            keypair.secret_key_bytes().to_vec()
        };
        
        // 保存 secret key to separate file if not embedding
        if !embed_key {
            let secret_key_path = {
                let mut path = output.clone();
                if let Some(filename) = output.file_name() {
                    let mut new_name = filename.to_os_string();
                    new_name.push(".key");
                    path.set_file_name(new_name);
                }
                path
            };
            
            let mut key_file = match File::create(&secret_key_path) {
                Ok(f) => f,
                Err(e) => {
                    return Err(format!("Cannot create key file at {}: {}. Please check write permissions.", secret_key_path.display(), e).into());
                }
            };
            
            key_file.write_all(&secret_key_data)?;
            status.lock().unwrap().push_str(&format!("Key saved to: {}\n", secret_key_path.display()));
        } else {
            status.lock().unwrap().push_str("Key will be embedded in encrypted file\n");
        }
        
        *progress.lock().unwrap() = 0.15;

        // 创建 capsule
        let mask_seed = KeyDerivation::derive_mask_key(&master_key)?;
        let capsule = mlkem::CapsuleV2::encapsulate(keypair.public_key_bytes(), &master_key, &mask_seed)?;
        
        *progress.lock().unwrap() = 0.2;

        // Prepare for streaming encryption
        status.lock().unwrap().push_str("Encrypting chunks (streaming mode)...\n");
        
        let engine = ChunkEngine::new(chunk_size, CipherType::ChaCha20Poly1305);
        let tree_root_key = KeyDerivation::derive_tree_root(&master_key)?;
        let file_nonce = rand::random::<[u8; 12]>();
        
        // 创建 temporary file for encrypted data in the same directory as output
        let temp_output = {
            let mut path = output.clone();
            // Get the file name and add .tmp extension
            if let Some(filename) = output.file_name() {
                let mut new_name = std::ffi::OsString::from("~tmp_");
                new_name.push(filename);
                new_name.push(".tmp");
                path.set_file_name(new_name);
            }
            path
        };
        
        let mut temp_file = match File::create(&temp_output) {
            Ok(f) => f,
            Err(e) => {
                return Err(format!("Cannot create temporary file at {}: {}. Please check write permissions.", temp_output.display(), e).into());
            }
        };
        
        let mut chunk_sizes = Vec::new();
        let mut chunk_buffer = vec![0u8; chunk_size];
        
        // Stream process: read chunk -> encrypt -> write -> repeat
        for i in 0..total_chunks {
            // 读取 one chunk at a time
            let bytes_read = input_file.read(&mut chunk_buffer)?;
            if bytes_read == 0 {
                break;
            }
            
            // 加密 this chunk
            let chunk_data = &chunk_buffer[..bytes_read];
            let encrypted = engine.encrypt_chunks(&[chunk_data.to_vec()], &tree_root_key, &file_nonce)?;
            
            // 写入 encrypted chunk immediately
            if let Some(enc_chunk) = encrypted.first() {
                chunk_sizes.push(enc_chunk.len() as u32);
                temp_file.write_all(enc_chunk)?;
            }
            
            // Update progress: 0.2 to 0.85 for encryption
            let chunk_progress = 0.2 + (0.65 * (i + 1) as f32 / total_chunks as f32);
            *progress.lock().unwrap() = chunk_progress;
            
            // Update status every 50 chunks or on last chunk
            if (i + 1) % 50 == 0 || i == total_chunks - 1 {
                status.lock().unwrap().push_str(&format!("Encrypted {}/{} chunks\n", i + 1, total_chunks));
            }
        }
        
        temp_file.flush()?;
        drop(temp_file);  // 关闭临时文件
        *progress.lock().unwrap() = 0.87;
        
        // 读取 encrypted data from temp file in streaming fashion
        status.lock().unwrap().push_str("Creating container...\n");
        
        let mut temp_file_read = match File::open(&temp_output) {
            Ok(f) => f,
            Err(e) => {
                return Err(format!("Cannot reopen temporary file: {}", e).into());
            }
        };
        
        // 读取 all encrypted data (this is unavoidable for SimpleContainer format)
        let mut all_encrypted_data = Vec::new();
        temp_file_read.read_to_end(&mut all_encrypted_data)?;
        drop(temp_file_read);
        
        *progress.lock().unwrap() = 0.90;
        
        // Delete temp file immediately after reading
        status.lock().unwrap().push_str("Cleaning up temporary file...\n");
        match std::fs::remove_file(&temp_output) {
            Ok(_) => {},
            Err(e) => {
                status.lock().unwrap().push_str(&format!("Warning: Could not delete temporary file: {}\n", e));
            }
        }
        
        *progress.lock().unwrap() = 0.92;

        // 创建 container with original filename
        let original_filename = input.file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());
        
        use cllx_fs_pro::container::SimpleContainer;
        let container = SimpleContainer::new(
            chunk_size as u32,
            total_chunks as u32,
            file_nonce,
            &capsule,
            chunk_sizes,
            all_encrypted_data,
            original_filename,
            if embed_key { Some(secret_key_data.clone()) } else { None },
        )?;
        
        *progress.lock().unwrap() = 0.95;

        // 写入 container
        status.lock().unwrap().push_str("Writing encrypted file...\n");
        let mut output_file = match File::create(&output) {
            Ok(f) => f,
            Err(e) => {
                return Err(format!("Cannot create output file at {}: {}. Please check write permissions.", output.display(), e).into());
            }
        };
        container.write_to_file(&mut output_file)?;
        
        *progress.lock().unwrap() = 1.0;
        
        status.lock().unwrap().push_str(&format!("Saved to: {}\n", output.display()));
        if !embed_key {
            status.lock().unwrap().push_str("⚠️ Remember to keep the .key file safe!\n");
        } else {
            status.lock().unwrap().push_str("✓ Key embedded in encrypted file\n");
        }

        Ok(())
    }

    fn decrypt_file(
        input: PathBuf,
        output: PathBuf,
        password: Option<String>,
        status: Arc<Mutex<String>>,
        progress: Arc<Mutex<f32>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        use std::io::{Read, Write};
        use cllx_fs_pro::core::{KeyDerivation, CipherType};
        use cllx_fs_pro::chunk::ChunkEngine;
        use cllx_fs_pro::container::SimpleContainer;

        status.lock().unwrap().push_str(&format!("Reading encrypted file: {}\n", input.display()));
        *progress.lock().unwrap() = 0.05;

        // 读取 and parse container first
        let mut input_file = File::open(&input)?;
        let container = SimpleContainer::read_from_file(&mut input_file)?;
        let total_chunks = container.total_chunks as usize;
        
        status.lock().unwrap().push_str(&format!("Container parsed: {} chunks\n", total_chunks));
        *progress.lock().unwrap() = 0.1;
        
        // Try to get secret key from embedded key or external file
        let key_data = if let Some(ref embedded_key) = container.embedded_key {
            status.lock().unwrap().push_str("Using embedded key\n");
            embedded_key.clone()
        } else {
            // Construct key file path using OsString to support Chinese characters
            let key_path = {
                let mut path = input.clone();
                if let Some(filename) = input.file_name() {
                    let mut new_name = filename.to_os_string();
                    new_name.push(".key");
                    path.set_file_name(new_name);
                }
                path
            };
            
            status.lock().unwrap().push_str(&format!("Loading key from: {}\n", key_path.display()));
            
            // 加载 secret key from file
            let mut key_file = match File::open(&key_path) {
                Ok(f) => f,
                Err(e) => {
                    return Err(format!("Cannot find key file at {}: {}. Make sure the .key file is in the same directory as the encrypted file.", 
                        key_path.display(), e).into());
                }
            };
            let mut data = Vec::new();
            key_file.read_to_end(&mut data)?;
            data
        };
        
        *progress.lock().unwrap() = 0.15;
        
        let is_password_protected = key_data.len() > 8 && &key_data[..8] == b"CLLX-PWD";
        
        if is_password_protected && password.is_none() {
            return Err("This file requires a password to decrypt".into());
        }
        
        let secret_key = if is_password_protected {
            status.lock().unwrap().push_str("Password-protected key detected\n");
            
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(password.as_ref().unwrap().as_bytes());
            hasher.update(b"cllx-password-key");
            let password_key: [u8; 32] = hasher.finalize().into();
            
            let encrypted_secret_key = &key_data[8..];
            let cipher = cllx_fs_pro::core::crypto::AeadCipher::new(CipherType::ChaCha20Poly1305);
            let nonce = [0u8; 12];
            
            cipher.decrypt(
                &password_key,
                &nonce,
                encrypted_secret_key,
                b"cllx-password-protected"
            ).map_err(|_| "Wrong password or corrupted key file")?
        } else if key_data.len() == 2400 {
            key_data
        } else {
            return Err(format!("Invalid key file format: expected 2400 bytes or password-protected key, got {} bytes", key_data.len()).into());
        };
        
        status.lock().unwrap().push_str("Key loaded successfully\n");
        
        status.lock().unwrap().push_str("Key loaded successfully\n");
        *progress.lock().unwrap() = 0.2;
        
        // Extract capsule and decapsulate
        let capsule = container.get_capsule()?;
        let (master_key, _mask_seed) = capsule.decapsulate(&secret_key)?;
        
        status.lock().unwrap().push_str("Master key decapsulated\n");
        *progress.lock().unwrap() = 0.25;
        
        // Derive keys
        let tree_root_key = KeyDerivation::derive_tree_root(&master_key)?;
        
        *progress.lock().unwrap() = 0.3;
        
        // 解密 chunks with progress updates (streaming mode)
        status.lock().unwrap().push_str("Decrypting chunks (streaming mode)...\n");
        
        let engine = ChunkEngine::new(container.chunk_size as usize, CipherType::ChaCha20Poly1305);
        
        // Determine final output path with original extension if available
        let final_output = if let Some(ref original_name) = container.original_filename {
            let output_path = std::path::Path::new(&output);
            if output_path.extension().is_none() {
                if let Some(original_ext) = std::path::Path::new(original_name).extension() {
                    let mut new_path = output_path.to_path_buf();
                    if let Some(ext_str) = original_ext.to_str() {
                        new_path.set_extension(ext_str);
                        status.lock().unwrap().push_str(&format!("Restoring original extension: .{}\n", ext_str));
                        new_path
                    } else {
                        output.clone()
                    }
                } else {
                    output.clone()
                }
            } else {
                output.clone()
            }
        } else {
            output.clone()
        };
        
        // Open output file for streaming write
        let mut output_file = File::create(&final_output)?;
        
        // 处理 chunks one at a time
        let mut offset = 0;
        for (i, &size) in container.chunk_sizes.iter().enumerate() {
            let end = offset + size as usize;
            let encrypted_chunk = &container.encrypted_data[offset..end];
            
            // Calculate original size (encrypted size - 16 bytes for auth tag)
            let original_size = (size as usize).saturating_sub(16);
            
            // 解密 this chunk
            let decrypted = engine.decrypt_chunks(
                &[encrypted_chunk.to_vec()],
                &tree_root_key,
                &container.file_nonce,
                &[original_size]
            )?;
            
            // 写入 decrypted chunk immediately
            if let Some(chunk) = decrypted.first() {
                output_file.write_all(chunk)?;
            }
            
            offset = end;
            
            // Update progress: 0.3 to 0.9 for decryption
            let chunk_progress = 0.3 + (0.6 * (i + 1) as f32 / total_chunks as f32);
            *progress.lock().unwrap() = chunk_progress;
            
            // Update status every 50 chunks or on last chunk
            if (i + 1) % 50 == 0 || i == total_chunks - 1 {
                status.lock().unwrap().push_str(&format!("Decrypted {}/{} chunks\n", i + 1, total_chunks));
            }
        }
        
        output_file.flush()?;
        *progress.lock().unwrap() = 1.0;
        
        status.lock().unwrap().push_str(&format!("Saved to: {}\n", final_output.display()));
        status.lock().unwrap().push_str("Decryption completed successfully!\n");

        Ok(())
    }

    // 加密 folder - stream pack and encrypt
    fn encrypt_folder(
        input_folder: PathBuf,
        output_file: PathBuf,
        password: Option<String>,
        chunk_size: usize,
        embed_key: bool,
        status: Arc<Mutex<String>>,
        progress: Arc<Mutex<f32>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        
        status.lock().unwrap().push_str("Streaming folder encryption...\n");
        *progress.lock().unwrap() = 0.05;
        
        // 创建 temporary tar file with streaming
        let temp_tar = std::env::temp_dir().join(format!("cllx_temp_{}.tar", std::process::id()));
        let tar_file = File::create(&temp_tar)?;
        let mut tar_builder = tar::Builder::new(tar_file);
        
        // Add folder to tar archive (streaming)
        let folder_name = input_folder.file_name()
            .ok_or("Invalid folder name")?
            .to_string_lossy()
            .to_string();
        
        status.lock().unwrap().push_str(&format!("Packing folder: {}\n", folder_name));
        tar_builder.append_dir_all(&folder_name, &input_folder)?;
        tar_builder.finish()?;
        
        status.lock().unwrap().push_str("Folder packed, starting encryption...\n");
        *progress.lock().unwrap() = 0.15;
        
        // Now encrypt the tar file using streaming encryption
        let result = Self::encrypt_file(
            temp_tar.clone(),
            output_file,
            password,
            chunk_size,
            embed_key,
            status.clone(),
            progress.clone(),
        );
        
        // Clean up temporary tar file
        status.lock().unwrap().push_str("Cleaning up temporary files...\n");
        let _ = std::fs::remove_file(&temp_tar);
        
        result
    }
    
    // 解密 folder - stream decrypt and unpack tar
    fn decrypt_folder(
        input_file: PathBuf,
        output_folder: PathBuf,
        password: Option<String>,
        status: Arc<Mutex<String>>,
        progress: Arc<Mutex<f32>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        
        status.lock().unwrap().push_str("Streaming folder decryption...\n");
        *progress.lock().unwrap() = 0.05;
        
        // 创建 temporary tar file for decrypted content
        let temp_tar = std::env::temp_dir().join(format!("cllx_temp_{}.tar", std::process::id()));
        
        // 解密 to temporary tar file (streaming)
        status.lock().unwrap().push_str("Decrypting archive...\n");
        let result = Self::decrypt_file(
            input_file,
            temp_tar.clone(),
            password,
            status.clone(),
            progress.clone(),
        );
        
        if let Err(e) = result {
            let _ = std::fs::remove_file(&temp_tar);
            return Err(e);
        }
        
        status.lock().unwrap().push_str("Unpacking archive...\n");
        *progress.lock().unwrap() = 0.85;
        
        // Unpack tar archive (streaming)
        let tar_file = File::open(&temp_tar)?;
        let mut archive = tar::Archive::new(tar_file);
        archive.unpack(&output_folder)?;
        
        // Clean up temporary tar file
        status.lock().unwrap().push_str("Cleaning up temporary files...\n");
        let _ = std::fs::remove_file(&temp_tar);
        
        status.lock().unwrap().push_str(&format!("Unpacked to: {}\n", output_folder.display()));
        *progress.lock().unwrap() = 1.0;
        
        Ok(())
    }
}