package crypto

import "testing"

func benchData(n int, seed byte) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte((i*31 + int(seed)) & 0xFF)
	}
	return data
}

// Benchmark for PKCS7 padding
func BenchmarkPKCS7Pad(b *testing.B) {
	data := benchData(100, 0x11)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PKCS7Pad(data, 16)
	}
}

func BenchmarkPKCS7Unpad(b *testing.B) {
	data := PKCS7Pad(benchData(100, 0x22), 16)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PKCS7Unpad(data)
	}
}

// Benchmark for V4 hash
func BenchmarkV4Hash(b *testing.B) {
	data := benchData(384, 0x33) // Typical KMS request size
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		V4Hash(data)
	}
}

// Benchmark for AES-CBC encryption (V5)
func BenchmarkAESEncryptCBC_V5(b *testing.B) {
	data := PKCS7Pad(benchData(256, 0x44), 16)
	iv := benchData(16, 0x55)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		KMSEncryptCBC(data, iv, false)
	}
}

// Benchmark for AES-CBC decryption (V5)
func BenchmarkAESDecryptCBC_V5(b *testing.B) {
	data := benchData(256, 0x66)
	iv := benchData(16, 0x77)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		KMSDecryptCBC(data, iv, false)
	}
}

// Benchmark for AES-CBC encryption (V6)
func BenchmarkAESEncryptCBC_V6(b *testing.B) {
	data := PKCS7Pad(benchData(256, 0x88), 16)
	iv := benchData(16, 0x99)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		KMSEncryptCBC(data, iv, true)
	}
}

// Benchmark for AES-CBC decryption (V6)
func BenchmarkAESDecryptCBC_V6(b *testing.B) {
	data := benchData(256, 0xAA)
	iv := benchData(16, 0xBB)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		KMSDecryptCBC(data, iv, true)
	}
}

// Benchmark for V6 HMAC
func BenchmarkV6HMAC(b *testing.B) {
	key := benchData(16, 0xCC)
	data := benchData(100, 0xDD)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		V6HMAC(key, data)
	}
}

// Benchmark for V6 MAC key derivation
func BenchmarkV6MACKey(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		V6MACKey(13322345678901234567)
	}
}

// Benchmark for individual AES block encryption (V6)
func BenchmarkAesEncryptBlockV6(b *testing.B) {
	block := benchData(16, 0xEE)
	b.ReportAllocs()
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aesEncryptBlockV6(block)
	}
}

// Benchmark for individual AES block decryption (V6)
func BenchmarkAesDecryptBlockV6(b *testing.B) {
	block := benchData(16, 0xEF)
	b.ReportAllocs()
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aesDecryptBlockV6(block)
	}
}

// Benchmark for individual AES block encryption (Custom/V4)
func BenchmarkAesEncryptBlockCustom(b *testing.B) {
	block := benchData(16, 0xF1)
	b.ReportAllocs()
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aesEncryptBlockCustom(block, 20)
	}
}

// Benchmark for individual AES block decryption (Custom/V4)
func BenchmarkAesDecryptBlockCustom(b *testing.B) {
	block := benchData(16, 0xF2)
	b.ReportAllocs()
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aesDecryptBlockCustom(block, 20)
	}
}

// Benchmark for expandKey
func BenchmarkExpandKey_16(b *testing.B) {
	key := benchData(16, 0xF3)
	b.ReportAllocs()
	b.SetBytes(int64(len(key)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		expandKey(key, 16, 176)
	}
}

func BenchmarkExpandKey_20(b *testing.B) {
	key := benchData(20, 0xF4)
	b.ReportAllocs()
	b.SetBytes(int64(len(key)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		expandKey(key, 20, 192)
	}
}
