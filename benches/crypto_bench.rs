use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use kms_rs::crypto::{
    aes_decrypt_block_v4, aes_decrypt_block_v6, aes_encrypt_block_v4, aes_encrypt_block_v6,
    build_round_keys, expand_key, galois_mult, kms_decrypt_cbc, kms_encrypt_cbc, pkcs7_pad,
    pkcs7_unpad, random_salt, v4_hash, v6_hmac, v6_hmac_parts, v6_mac_key, V5_KEY,
};

fn bench_data(n: usize, seed: u8) -> Vec<u8> {
    let mut data = vec![0u8; n];
    for i in 0..n {
        data[i] = ((i.wrapping_mul(31)).wrapping_add(seed as usize) & 0xFF) as u8;
    }
    data
}

fn bench_pkcs7_pad(c: &mut Criterion) {
    let data = bench_data(100, 0x11);
    let mut g = c.benchmark_group("PKCS7Pad");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("len_100", |b| {
        b.iter(|| pkcs7_pad(black_box(&data), 16));
    });
    g.finish();
}

fn bench_pkcs7_unpad(c: &mut Criterion) {
    let data = pkcs7_pad(&bench_data(100, 0x22), 16);
    let mut g = c.benchmark_group("PKCS7Unpad");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("len_112", |b| {
        b.iter(|| pkcs7_unpad(black_box(&data)).unwrap());
    });
    g.finish();
}

fn bench_v4_hash(c: &mut Criterion) {
    let data = bench_data(384, 0x33);
    let mut g = c.benchmark_group("V4Hash");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("len_384", |b| {
        b.iter(|| v4_hash(black_box(&data)));
    });
    g.finish();
}

fn bench_aes_cbc_encrypt_v5(c: &mut Criterion) {
    let data = pkcs7_pad(&bench_data(256, 0x44), 16);
    let iv = bench_data(16, 0x55);
    let mut g = c.benchmark_group("AESEncryptCBC_V5");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("len_256", |b| {
        b.iter(|| kms_encrypt_cbc(black_box(&data), black_box(&iv), false).unwrap());
    });
    g.finish();
}

fn bench_aes_cbc_decrypt_v5(c: &mut Criterion) {
    let data = bench_data(256, 0x66);
    let iv = bench_data(16, 0x77);
    let mut g = c.benchmark_group("AESDecryptCBC_V5");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("len_256", |b| {
        b.iter(|| kms_decrypt_cbc(black_box(&data), black_box(&iv), false).unwrap());
    });
    g.finish();
}

fn bench_aes_cbc_encrypt_v6(c: &mut Criterion) {
    let data = pkcs7_pad(&bench_data(256, 0x88), 16);
    let iv = bench_data(16, 0x99);
    let mut g = c.benchmark_group("AESEncryptCBC_V6");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("len_256", |b| {
        b.iter(|| kms_encrypt_cbc(black_box(&data), black_box(&iv), true).unwrap());
    });
    g.finish();
}

fn bench_aes_cbc_decrypt_v6(c: &mut Criterion) {
    let data = bench_data(256, 0xAA);
    let iv = bench_data(16, 0xBB);
    let mut g = c.benchmark_group("AESDecryptCBC_V6");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("len_256", |b| {
        b.iter(|| kms_decrypt_cbc(black_box(&data), black_box(&iv), true).unwrap());
    });
    g.finish();
}

fn bench_v6_hmac(c: &mut Criterion) {
    let key = bench_data(16, 0xCC);
    let data = bench_data(100, 0xDD);
    let mut g = c.benchmark_group("V6HMAC");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("len_100", |b| {
        b.iter(|| v6_hmac(black_box(&key), black_box(&data)));
    });
    g.finish();
}

fn bench_v6_mac_key(c: &mut Criterion) {
    c.bench_function("V6MACKey", |b| {
        b.iter(|| v6_mac_key(black_box(13_322_345_678_901_234_567u64)));
    });
}

fn bench_aes_encrypt_block_v6(c: &mut Criterion) {
    let block = bench_data(16, 0xEE);
    let mut dst = vec![0u8; 16];
    let mut g = c.benchmark_group("AesEncryptBlockV6");
    g.throughput(Throughput::Bytes(16));
    g.bench_function("block_16", |b| {
        b.iter(|| aes_encrypt_block_v6(black_box(&block), black_box(&mut dst)));
    });
    g.finish();
}

fn bench_aes_decrypt_block_v6(c: &mut Criterion) {
    let block = bench_data(16, 0xEF);
    let mut dst = vec![0u8; 16];
    let mut g = c.benchmark_group("AesDecryptBlockV6");
    g.throughput(Throughput::Bytes(16));
    g.bench_function("block_16", |b| {
        b.iter(|| aes_decrypt_block_v6(black_box(&block), black_box(&mut dst)));
    });
    g.finish();
}

fn bench_aes_encrypt_block_custom(c: &mut Criterion) {
    let block = bench_data(16, 0xF1);
    let mut dst = vec![0u8; 16];
    let mut g = c.benchmark_group("AesEncryptBlockCustom");
    g.throughput(Throughput::Bytes(16));
    g.bench_function("block_16", |b| {
        b.iter(|| aes_encrypt_block_v4(black_box(&block), black_box(&mut dst)));
    });
    g.finish();
}

fn bench_aes_decrypt_block_custom(c: &mut Criterion) {
    let block = bench_data(16, 0xF2);
    let mut dst = vec![0u8; 16];
    let mut g = c.benchmark_group("AesDecryptBlockCustom");
    g.throughput(Throughput::Bytes(16));
    g.bench_function("block_16", |b| {
        b.iter(|| aes_decrypt_block_v4(black_box(&block), black_box(&mut dst)));
    });
    g.finish();
}

fn bench_expand_key_16(c: &mut Criterion) {
    let key = bench_data(16, 0xF3);
    let mut g = c.benchmark_group("ExpandKey_16");
    g.throughput(Throughput::Bytes(key.len() as u64));
    g.bench_function("key_16", |b| {
        b.iter(|| expand_key(black_box(&key), 16, 176));
    });
    g.finish();
}

fn bench_expand_key_20(c: &mut Criterion) {
    let key = bench_data(20, 0xF4);
    let mut g = c.benchmark_group("ExpandKey_20");
    g.throughput(Throughput::Bytes(key.len() as u64));
    g.bench_function("key_20", |b| {
        b.iter(|| expand_key(black_box(&key), 20, 192));
    });
    g.finish();
}

fn bench_v4_encrypt_cycle(c: &mut Criterion) {
    let data = bench_data(256, 0xF5);
    let mut g = c.benchmark_group("V4EncryptCycle");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("len_256", |b| {
        b.iter(|| v4_hash(black_box(&data)));
    });
    g.finish();
}

fn bench_build_round_keys(c: &mut Criterion) {
    let expanded = expand_key(&V5_KEY, 16, 176);
    c.bench_function("BuildRoundKeys", |b| {
        b.iter(|| build_round_keys(black_box(&expanded), 10));
    });
}

fn bench_galois_mult(c: &mut Criterion) {
    c.bench_function("GaloisMult", |b| {
        b.iter(|| galois_mult(black_box(0x57), black_box(0x83)));
    });
}

fn bench_random_salt(c: &mut Criterion) {
    c.bench_function("RandomSalt", |b| {
        b.iter(random_salt);
    });
}

fn bench_v6_encrypt_with_hmac(c: &mut Criterion) {
    let data = pkcs7_pad(&bench_data(256, 0xF6), 16);
    let iv = bench_data(16, 0xF7);
    let mac_key = bench_data(16, 0xF8);
    let mut g = c.benchmark_group("V6EncryptWithHMAC");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("len_256", |b| {
        b.iter(|| {
            let encrypted = kms_encrypt_cbc(black_box(&data), black_box(&iv), true).unwrap();
            v6_hmac_parts(black_box(&mac_key), &[&encrypted])
        });
    });
    g.finish();
}

fn bench_full_cycle_v5(c: &mut Criterion) {
    let plain = bench_data(200, 0xF9);
    let salt = bench_data(16, 0xFA);
    let mut request = Vec::with_capacity(16 + plain.len());
    request.extend_from_slice(&salt);
    request.extend_from_slice(&plain);
    let padded = pkcs7_pad(&request, 16);
    let mut g = c.benchmark_group("FullCryptoCycle_V5");
    g.throughput(Throughput::Bytes(padded.len() as u64));
    g.bench_function("len_224", |b| {
        b.iter(|| {
            let enc = kms_encrypt_cbc(black_box(&padded), black_box(&salt), false).unwrap();
            let dec = kms_decrypt_cbc(&enc, &salt, false).unwrap();
            pkcs7_unpad(&dec).unwrap()
        });
    });
    g.finish();
}

fn bench_full_cycle_v6(c: &mut Criterion) {
    let plain = bench_data(200, 0xFB);
    let salt = bench_data(16, 0xFC);
    let mut request = Vec::with_capacity(16 + plain.len());
    request.extend_from_slice(&salt);
    request.extend_from_slice(&plain);
    let padded = pkcs7_pad(&request, 16);
    let mut g = c.benchmark_group("FullCryptoCycle_V6");
    g.throughput(Throughput::Bytes(padded.len() as u64));
    g.bench_function("len_224", |b| {
        b.iter(|| {
            let enc = kms_encrypt_cbc(black_box(&padded), black_box(&salt), true).unwrap();
            let dec = kms_decrypt_cbc(&enc, &salt, true).unwrap();
            pkcs7_unpad(&dec).unwrap()
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_pkcs7_pad,
    bench_pkcs7_unpad,
    bench_v4_hash,
    bench_aes_cbc_encrypt_v5,
    bench_aes_cbc_decrypt_v5,
    bench_aes_cbc_encrypt_v6,
    bench_aes_cbc_decrypt_v6,
    bench_v6_hmac,
    bench_v6_mac_key,
    bench_aes_encrypt_block_v6,
    bench_aes_decrypt_block_v6,
    bench_aes_encrypt_block_custom,
    bench_aes_decrypt_block_custom,
    bench_expand_key_16,
    bench_expand_key_20,
    bench_v4_encrypt_cycle,
    bench_build_round_keys,
    bench_galois_mult,
    bench_random_salt,
    bench_v6_encrypt_with_hmac,
    bench_full_cycle_v5,
    bench_full_cycle_v6,
);
criterion_main!(benches);
