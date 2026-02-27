package crypto

import (
	"crypto/rand"
	"testing"
)

// Benchmark for PKCS7 padding
func BenchmarkPKCS7Pad(b *testing.B) {
	data := make([]byte, 100)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PKCS7Pad(data, 16)
	}
}

func BenchmarkPKCS7Unpad(b *testing.B) {
	data := make([]byte, 112) // 100 + 12 padding
	rand.Read(data)
	// Set valid padding
	for i := 100; i < 112; i++ {
		data[i] = 12
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PKCS7Unpad(data)
	}
}

// Benchmark for V4 hash
func BenchmarkV4Hash(b *testing.B) {
	data := make([]byte, 384) // Typical KMS request size
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		V4Hash(data)
	}
}

// Benchmark for AES-CBC encryption (V5)
func BenchmarkAESEncryptCBC_V5(b *testing.B) {
	data := make([]byte, 256)
	rand.Read(data)
	// Pad to block size
	data = PKCS7Pad(data, 16)
	iv := make([]byte, 16)
	rand.Read(iv)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AESEncryptCBC(data, V5Key, iv, false)
	}
}

// Benchmark for AES-CBC decryption (V5)
func BenchmarkAESDecryptCBC_V5(b *testing.B) {
	data := make([]byte, 256)
	rand.Read(data)
	iv := make([]byte, 16)
	rand.Read(iv)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AESDecryptCBC(data, V5Key, iv, false)
	}
}

// Benchmark for AES-CBC encryption (V6)
func BenchmarkAESEncryptCBC_V6(b *testing.B) {
	data := make([]byte, 256)
	rand.Read(data)
	data = PKCS7Pad(data, 16)
	iv := make([]byte, 16)
	rand.Read(iv)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AESEncryptCBC(data, V6Key, iv, true)
	}
}

// Benchmark for AES-CBC decryption (V6)
func BenchmarkAESDecryptCBC_V6(b *testing.B) {
	data := make([]byte, 256)
	rand.Read(data)
	iv := make([]byte, 16)
	rand.Read(iv)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AESDecryptCBC(data, V6Key, iv, true)
	}
}

// Benchmark for V6 HMAC
func BenchmarkV6HMAC(b *testing.B) {
	key := make([]byte, 16)
	data := make([]byte, 100)
	rand.Read(key)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		V6HMAC(key, data)
	}
}

// Benchmark for V6 MAC key derivation
func BenchmarkV6MACKey(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		V6MACKey(13322345678901234567)
	}
}

// Benchmark for individual AES block encryption (V6)
func BenchmarkAesEncryptBlockV6(b *testing.B) {
	block := make([]byte, 16)
	rand.Read(block)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aesEncryptBlockV6(block)
	}
}

// Benchmark for individual AES block decryption (V6)
func BenchmarkAesDecryptBlockV6(b *testing.B) {
	block := make([]byte, 16)
	rand.Read(block)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aesDecryptBlockV6(block)
	}
}

// Benchmark for individual AES block encryption (Custom/V4)
func BenchmarkAesEncryptBlockCustom(b *testing.B) {
	block := make([]byte, 16)
	rand.Read(block)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aesEncryptBlockCustom(block, 20)
	}
}

// Benchmark for individual AES block decryption (Custom/V4)
func BenchmarkAesDecryptBlockCustom(b *testing.B) {
	block := make([]byte, 16)
	rand.Read(block)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aesDecryptBlockCustom(block, 20)
	}
}

// Benchmark for expandKey
func BenchmarkExpandKey_16(b *testing.B) {
	key := make([]byte, 16)
	rand.Read(key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		expandKey(key, 16, 176)
	}
}

func BenchmarkExpandKey_20(b *testing.B) {
	key := make([]byte, 20)
	rand.Read(key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		expandKey(key, 20, 192)
	}
}
