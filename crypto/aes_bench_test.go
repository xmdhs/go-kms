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
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aesEncryptBlockV6InPlace(dst, block)
	}
}

// Benchmark for individual AES block decryption (V6)
func BenchmarkAesDecryptBlockV6(b *testing.B) {
	block := benchData(16, 0xEF)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aesDecryptBlockV6InPlace(dst, block)
	}
}

// Benchmark for individual AES block encryption (Custom/V4)
func BenchmarkAesEncryptBlockCustom(b *testing.B) {
	block := benchData(16, 0xF1)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aesEncryptBlockV4InPlace(dst, block)
	}
}

// Benchmark for individual AES block decryption (Custom/V4)
func BenchmarkAesDecryptBlockCustom(b *testing.B) {
	block := benchData(16, 0xF2)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aesDecryptBlockV4InPlace(dst, block)
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

// Benchmark for V4 full encryption/decryption cycle
func BenchmarkV4EncryptCycle(b *testing.B) {
	data := benchData(256, 0xF5)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// V4 uses custom AES block encryption via V4Hash
		V4Hash(data)
	}
}

// Benchmark for buildRoundKeys
func BenchmarkBuildRoundKeys(b *testing.B) {
	expanded := expandKey(V5Key, 16, 176)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildRoundKeys(expanded, 10)
	}
}

// Benchmark for galois multiplication (used in MixColumns)
func BenchmarkGaloisMult(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		galoisMult(0x57, 0x83)
	}
}

// Benchmark for RandomSalt
func BenchmarkRandomSalt(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RandomSalt()
	}
}

// Benchmark for complete V6 encryption cycle with HMAC
func BenchmarkV6EncryptWithHMAC(b *testing.B) {
	data := PKCS7Pad(benchData(256, 0xF6), 16)
	iv := benchData(16, 0xF7)
	macKey := benchData(16, 0xF8)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := KMSEncryptCBC(data, iv, true)
		_ = V6HMACParts(macKey, encrypted)
	}
}

// Benchmark for KMS V5/V6 full request-response cycle simulation
func BenchmarkFullCryptoCycle_V5(b *testing.B) {
	// Simulate a typical KMS request encryption/decryption cycle
	plainData := benchData(200, 0xF9)
	salt := benchData(16, 0xFA)

	// Build request: salt + kmsData
	request := make([]byte, 16+len(plainData))
	copy(request[:16], salt)
	copy(request[16:], plainData)
	padded := PKCS7Pad(request, 16)

	b.ReportAllocs()
	b.SetBytes(int64(len(padded)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Encrypt
		encrypted, _ := KMSEncryptCBC(padded, salt, false)
		// Decrypt
		decrypted, _ := KMSDecryptCBC(encrypted, salt, false)
		// Unpad
		PKCS7Unpad(decrypted)
	}
}

func BenchmarkFullCryptoCycle_V6(b *testing.B) {
	plainData := benchData(200, 0xFB)
	salt := benchData(16, 0xFC)
	request := make([]byte, 16+len(plainData))
	copy(request[:16], salt)
	copy(request[16:], plainData)
	padded := PKCS7Pad(request, 16)

	b.ReportAllocs()
	b.SetBytes(int64(len(padded)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := KMSEncryptCBC(padded, salt, true)
		decrypted, _ := KMSDecryptCBC(encrypted, salt, true)
		PKCS7Unpad(decrypted)
	}
}
