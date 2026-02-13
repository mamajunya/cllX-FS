use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use cllx_fs_pro::core::MasterKey;
use cllx_fs_pro::chunk::ChunkEngine;
use cllx_fs_pro::merkle::MerkleTree;
use cllx_fs_pro::capsule::mlkem::MlKemCapsule;

fn bench_chunk_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_encryption");
    
    for size in [1024, 4096, 16384, 65536, 262144, 1048576].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let master_key = MasterKey::generate();
            let engine = ChunkEngine::new(master_key);
            let data = vec![0u8; size];
            
            b.iter(|| {
                engine.encrypt_chunk(
                    black_box(0),
                    black_box(&data),
                    black_box(1),
                    black_box([0u8; 16]),
                    black_box(1)
                ).unwrap()
            });
        });
    }
    group.finish();
}

fn bench_chunk_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_decryption");
    
    for size in [1024, 4096, 16384, 65536, 262144, 1048576].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let master_key = MasterKey::generate();
            let engine = ChunkEngine::new(master_key);
            let data = vec![0u8; size];
            let encrypted = engine.encrypt_chunk(0, &data, 1, [0u8; 16], 1).unwrap();
            
            b.iter(|| {
                engine.decrypt_chunk(
                    black_box(0),
                    black_box(&encrypted),
                    black_box(1),
                    black_box([0u8; 16]),
                    black_box(1)
                ).unwrap()
            });
        });
    }
    group.finish();
}

fn bench_merkle_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_tree");
    
    for num_chunks in [10, 100, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(num_chunks), num_chunks, |b, &num_chunks| {
            let hashes: Vec<[u8; 32]> = (0..num_chunks)
                .map(|i| {
                    let mut hash = [0u8; 32];
                    hash[0] = (i & 0xFF) as u8;
                    hash
                })
                .collect();
            
            b.iter(|| {
                MerkleTree::new(black_box(hashes.clone()))
            });
        });
    }
    group.finish();
}

fn bench_mlkem_keygen(c: &mut Criterion) {
    c.bench_function("mlkem_keygen", |b| {
        b.iter(|| {
            MlKemCapsule::generate_keypair()
        });
    });
}

fn bench_mlkem_encapsulate(c: &mut Criterion) {
    let (ek, _dk) = MlKemCapsule::generate_keypair();
    let master_key = MasterKey::generate();
    
    c.bench_function("mlkem_encapsulate", |b| {
        b.iter(|| {
            MlKemCapsule::encapsulate(black_box(&ek), black_box(&master_key)).unwrap()
        });
    });
}

fn bench_mlkem_decapsulate(c: &mut Criterion) {
    let (ek, dk) = MlKemCapsule::generate_keypair();
    let master_key = MasterKey::generate();
    let capsule = MlKemCapsule::encapsulate(&ek, &master_key).unwrap();
    
    c.bench_function("mlkem_decapsulate", |b| {
        b.iter(|| {
            capsule.decapsulate(black_box(&dk)).unwrap()
        });
    });
}

criterion_group!(
    benches,
    bench_chunk_encryption,
    bench_chunk_decryption,
    bench_merkle_tree,
    bench_mlkem_keygen,
    bench_mlkem_encapsulate,
    bench_mlkem_decapsulate
);
criterion_main!(benches);
