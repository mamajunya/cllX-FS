// cllX-Math: Integer matrix diffusion layer
// Generates invertible matrices for diffusion

use crate::core::{Result, Error};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand::RngCore;

/// Matrix for integer diffusion (N x N)
#[derive(Clone)]
pub struct DiffusionMatrix {
    pub n: usize,
    pub forward: Vec<Vec<u32>>,
    pub inverse: Vec<Vec<u32>>,
}

impl DiffusionMatrix {
    /// 生成 a new invertible matrix from seed
    /// Using upper triangular matrix with 1s on diagonal (guaranteed invertible)
    pub fn generate(seed: &[u8; 32], n: usize) -> Result<Self> {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        
        // 创建 upper triangular matrix with 1s on diagonal
        let mut forward = vec![vec![0u32; n]; n];
        
        // Set diagonal to 1
        for i in 0..n {
            forward[i][i] = 1;
        }
        
        // Fill upper triangle with random values
        for i in 0..n {
            for j in (i+1)..n {
                forward[i][j] = (rng.next_u32() % 256) as u32;
            }
        }
        
        // Compute inverse using back substitution
        let inverse = Self::invert_upper_triangular(&forward, n);
        
        Ok(Self { n, forward, inverse })
    }
    
    /// Invert an upper triangular matrix with 1s on diagonal
    /// For upper triangular U with U[i][i] = 1, the inverse is also upper triangular
    fn invert_upper_triangular(matrix: &[Vec<u32>], n: usize) -> Vec<Vec<u32>> {
        let mut inv = vec![vec![0u32; n]; n];
        
        // Set diagonal to 1
        for i in 0..n {
            inv[i][i] = 1;
        }
        
        // Back substitution to compute inverse
        // For each column j from right to left
        for j in (0..n).rev() {
            // For each row i above the diagonal
            for i in (0..j).rev() {
                // inv[i][j] = -sum(matrix[i][k] * inv[k][j]) for k = i+1 to j
                let mut sum: u64 = 0;
                for k in (i+1)..=j {
                    sum = sum.wrapping_add(
                        (matrix[i][k] as u64).wrapping_mul(inv[k][j] as u64)
                    );
                }
                inv[i][j] = (0u32.wrapping_sub((sum & 0xFFFFFFFF) as u32));
            }
        }
        
        inv
    }
    
    /// Apply forward diffusion: out[i] = Σ(matrix[i][j] * poly[j]) mod 2^32
    pub fn diffuse(&self, poly: &[u32]) -> Vec<u32> {
        let mut result = Vec::with_capacity(poly.len());
        
        // 处理 in blocks of size n
        for block_start in (0..poly.len()).step_by(self.n) {
            let block_end = (block_start + self.n).min(poly.len());
            let block_size = block_end - block_start;
            
            for i in 0..block_size {
                let mut sum: u64 = 0;
                for j in 0..block_size {
                    sum = sum.wrapping_add(
                        (self.forward[i][j] as u64) * (poly[block_start + j] as u64)
                    );
                }
                result.push((sum & 0xFFFFFFFF) as u32);
            }
        }
        
        result
    }
    
    /// Apply inverse diffusion
    pub fn diffuse_inv(&self, poly: &[u32]) -> Vec<u32> {
        let mut result = Vec::with_capacity(poly.len());
        
        // 处理 in blocks of size n
        for block_start in (0..poly.len()).step_by(self.n) {
            let block_end = (block_start + self.n).min(poly.len());
            let block_size = block_end - block_start;
            
            for i in 0..block_size {
                let mut sum: u64 = 0;
                for j in 0..block_size {
                    sum = sum.wrapping_add(
                        (self.inverse[i][j] as u64) * (poly[block_start + j] as u64)
                    );
                }
                result.push((sum & 0xFFFFFFFF) as u32);
            }
        }
        
        result
    }
    

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matrix_generation() {
        let seed = [42u8; 32];
        let matrix = DiffusionMatrix::generate(&seed, 16).unwrap();
        
        assert_eq!(matrix.n, 16);
        assert_eq!(matrix.forward.len(), 16);
        assert_eq!(matrix.inverse.len(), 16);
    }

    #[test]
    fn test_diffusion_size() {
        let seed = [42u8; 32];
        let matrix = DiffusionMatrix::generate(&seed, 16).unwrap();
        
        let poly = vec![1u32, 2, 3, 4, 5, 6, 7, 8];
        let diffused = matrix.diffuse(&poly);
        
        assert_eq!(diffused.len(), poly.len());
    }
}
