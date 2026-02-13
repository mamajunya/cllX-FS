// Colored output helpers
pub fn print_success(message: &str) {
    println!("✓ {}", message);
}

pub fn print_error(message: &str) {
    eprintln!("✗ Error: {}", message);
}

pub fn print_info(message: &str) {
    println!("ℹ {}", message);
}

pub fn print_warning(message: &str) {
    println!("⚠ Warning: {}", message);
}
