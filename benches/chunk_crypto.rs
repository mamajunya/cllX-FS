use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use cllx_fs_pro::core::{MasterKey, KeyDerivation, AeadCipher, CipherType};
use cllx_fs_pro::chunk::ChunkEngine;

fn bench_chunk_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_encryption");
    
    for size in [1024, 1024 * 1024].iter() {
        let data = vec![0u8; *size];
        let master = MasterKey::generate();
        let tree_root = KeyDerivation::derive_tree_root(&master).unwrap();
        let file_nonce = [0u8; 12];
        
        group.bench_with_input(BenchmarkId::new("aes256gcm", size), size, |b, _| {
            let engine = ChunkEngine::new(*size, CipherType::Aes256Gcm);
            let chunks = vec![data.clone()];
            b.iter(|| {
                engine.encrypt_chunks(black_box(&chunks), &tree_root, &file_nonce).unwrap()
            });
        });
        
        group.bench_with_input(BenchmarkId::new("chacha20", size), size, |b, _| {
            let engine = ChunkEngine::new(*size, CipherType::ChaCha20Poly1305);
            let chunks = vec![data.clone()];
            b.iter(|| {
                engine.encrypt_chunks(black_box(&chunks), &tree_root, &file_nonce).unwrap()
            });
        });
    }
    
    group.finish();
}

criterion_group!(benches, bench_chunk_encryption);
criterion_main!(benches);
