package crypto

import (
	"bytes"
	"crypto/aes"
	"testing"
)

// FuzzPKCS7Unpad verifies that any successfully unpadded block repads to its
// exact original form (PKCS7 padding is unique, so unpad is an exact inverse
// of pad on valid input).
func FuzzPKCS7Unpad(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3})
	f.Add(PKCS7Pad([]byte("kms-fuzz"), 16))
	f.Add(bytes.Repeat([]byte{0x41}, 15))
	f.Add(bytes.Repeat([]byte{0x80}, 16)) // padding fills the whole block
	f.Fuzz(func(t *testing.T, data []byte) {
		unpadded, err := PKCS7Unpad(data)
		if err != nil {
			return
		}
		if !bytes.Equal(PKCS7Pad(unpadded, 16), data) {
			t.Fatalf("pad(unpad(data)) mismatch for %x", data)
		}
	})
}

// FuzzPKCS7PadUnpad verifies the pad side of the round trip: any input padded
// to a 16-byte boundary must unpad back to the original bytes.
func FuzzPKCS7PadUnpad(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3})
	f.Add([]byte("kms-fuzz"))
	f.Add(bytes.Repeat([]byte{0x41}, 15))
	f.Add(make([]byte, 16))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		padded := PKCS7Pad(data, 16)
		orig, err := PKCS7Unpad(padded)
		if err != nil {
			t.Fatalf("unpad(pad(data)) error = %v", err)
		}
		if !bytes.Equal(orig, data) {
			t.Fatalf("pad/unpad round trip mismatch: %x != %x", orig, data)
		}
	})
}

// aesEncryptWithRoundKeys runs the unpatched AES-128 rounds exactly like
// aesEncryptBlockV6Go, but against caller-supplied round keys. Leaving the
// protocol round patches out makes the core comparable to crypto/aes.
func aesEncryptWithRoundKeys(dst, input []byte, roundKeys [][16]byte) {
	var state [16]byte
	for i := range 4 {
		for j := range 4 {
			state[i+j*4] = input[i*4+j]
		}
	}
	addRoundKey(state[:], &roundKeys[0])
	for i := 1; i < 10; i++ {
		subBytes(state[:], false)
		shiftRows(state[:], false)
		mixColumns(state[:], false)
		addRoundKey(state[:], &roundKeys[i])
	}
	subBytes(state[:], false)
	shiftRows(state[:], false)
	addRoundKey(state[:], &roundKeys[10])
	for i := range 4 {
		for j := range 4 {
			dst[i*4+j] = state[i+j*4]
		}
	}
}

// aesDecryptWithRoundKeys is the inverse counterpart of aesEncryptWithRoundKeys.
func aesDecryptWithRoundKeys(dst, input []byte, roundKeys [][16]byte) {
	var state [16]byte
	for i := range 4 {
		for j := range 4 {
			state[i+j*4] = input[i*4+j]
		}
	}
	addRoundKey(state[:], &roundKeys[10])
	for i := 9; i > 0; i-- {
		shiftRows(state[:], true)
		subBytes(state[:], true)
		addRoundKey(state[:], &roundKeys[i])
		mixColumns(state[:], true)
	}
	shiftRows(state[:], true)
	subBytes(state[:], true)
	addRoundKey(state[:], &roundKeys[0])
	for i := range 4 {
		for j := range 4 {
			dst[i*4+j] = state[i+j*4]
		}
	}
}

// FuzzAESBlockMatchesStdlib cross-checks the custom AES core (expandKey,
// buildRoundKeys, sbox, shiftRows, mixColumns, addRoundKey) against
// crypto/aes on arbitrary keys and blocks. V6 is only divergent from standard
// AES through its protocol round patches, so the unpatched core must be
// bit-identical to AES-128.
func FuzzAESBlockMatchesStdlib(f *testing.F) {
	f.Add([]byte{0xCD, 0x7E, 0x79, 0x6F, 0x2A, 0xB2, 0x5D, 0xCB, 0x55, 0xFF, 0xC8, 0xEF, 0x83, 0x64, 0xC4, 0x70}, []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f})
	f.Add([]byte{0xA9, 0x4A, 0x41, 0x95, 0xE2, 0x01, 0x43, 0x2D, 0x9B, 0xCB, 0x46, 0x04, 0x05, 0xD8, 0x4A, 0x21}, []byte{})
	f.Add(make([]byte, 16), make([]byte, 16))
	f.Fuzz(func(t *testing.T, key, in []byte) {
		if len(key) != 16 || len(in) != 16 {
			return
		}
		stdBlock, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("aes.NewCipher: %v", err)
		}
		roundKeys := buildRoundKeys(expandKey(key, 16, 176), 10)

		var got, want [16]byte
		stdBlock.Encrypt(want[:], in)
		aesEncryptWithRoundKeys(got[:], in, roundKeys)
		if got != want {
			t.Fatalf("custom AES encrypt mismatch: key=%x in=%x got=%x want=%x", key, in, got, want)
		}

		stdBlock.Decrypt(want[:], in)
		aesDecryptWithRoundKeys(got[:], in, roundKeys)
		if got != want {
			t.Fatalf("custom AES decrypt mismatch: key=%x in=%x got=%x want=%x", key, in, got, want)
		}
	})
}

// FuzzKMSEncryptDecryptCBC verifies the KMS CBC envelopes round-trip for any
// block-aligned plaintext: v5 uses the standard library AES, v6 the custom
// patched AES-128. IV length is fixed at 16 because the mid-handshake helper
// mangles arbitrary-length IVs.
func FuzzKMSEncryptDecryptCBC(f *testing.F) {
	f.Add([]byte("0123456789abcdef"), []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, false)
	f.Add([]byte("0123456789abcdef"), []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, true)
	f.Add(make([]byte, 16), make([]byte, 16), true)
	f.Fuzz(func(t *testing.T, data, iv []byte, v6 bool) {
		if len(data) > 1<<16 || len(data)%16 != 0 || len(iv) != 16 {
			return
		}
		ct, err := KMSEncryptCBC(data, iv, v6)
		if err != nil {
			t.Fatalf("KMSEncryptCBC error = %v", err)
		}
		pt, err := KMSDecryptCBC(ct, iv, v6)
		if err != nil {
			t.Fatalf("KMSDecryptCBC error = %v", err)
		}
		if !bytes.Equal(pt, data) {
			t.Fatalf("CBC round trip mismatch (v6=%v): %x != %x", v6, pt, data)
		}
	})
}
