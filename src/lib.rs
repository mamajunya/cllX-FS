pub mod core;
pub mod capsule;
pub mod chunk;
pub mod merkle;
pub mod container;
pub mod stealth;
pub mod timelock;
pub mod antiransom;
pub mod dedup;
pub mod cli;
pub mod lazy;
pub mod cllx_math;  // Original mathematical 变换 layer

pub use container::{Container, ContainerBuilder};
pub use core::error::{Error, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_workflow() {
        // Basic integration test placeholder
    }
}
