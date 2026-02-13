use std::io::{self, Write};

pub struct ProgressBar {
    total: u64,
    current: u64,
    width: usize,
    message: String,
}

impl ProgressBar {
    pub fn new(total: u64, message: &str) -> Self {
        Self {
            total,
            current: 0,
            width: 50,
            message: message.to_string(),
        }
    }

    pub fn update(&mut self, current: u64) {
        self.current = current;
        self.render();
    }

    pub fn increment(&mut self, delta: u64) {
        self.current += delta;
        self.render();
    }

    pub fn finish(&mut self) {
        self.current = self.total;
        self.render();
        println!();
    }

    fn render(&self) {
        let percentage = if self.total > 0 {
            (self.current as f64 / self.total as f64 * 100.0) as u64
        } else {
            0
        };

        let filled = (self.current as f64 / self.total as f64 * self.width as f64) as usize;
        let empty = self.width.saturating_sub(filled);

        let bar = format!(
            "\r{} [{}{}] {}% ({}/{})",
            self.message,
            "█".repeat(filled),
            "░".repeat(empty),
            percentage,
            self.current,
            self.total
        );

        print!("{}", bar);
        io::stdout().flush().unwrap();
    }
}
