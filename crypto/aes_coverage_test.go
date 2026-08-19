package crypto

import (
	"bytes"
	"testing"
)

// TestRandomSalt exercises the rand.Read wrapper.
func TestRandomSalt(t *testing.T) {
	salt := RandomSalt()
	if len(salt) != 16 {
		t.Fatalf("RandomSalt() length = %d, want 16", len(salt))
	}
}

func TestKMSEncryptCBCNonBlockSizeV5(t *testing.T) {
	iv := make([]byte, 16)
	if _, err := KMSEncryptCBC([]byte{1, 2, 3}, iv, false); err == nil {
		t.Fatal("expected error for non-block-sized plaintext (v5)")
	}
}

func TestKMSDecryptCBCNonBlockSizeV5(t *testing.T) {
	iv := make([]byte, 16)
	if _, err := KMSDecryptCBC([]byte{1, 2, 3}, iv, false); err == nil {
		t.Fatal("expected error for non-block-sized ciphertext (v5)")
	}
}

func TestAESEncryptCBCV6NonBlockSize(t *testing.T) {
	iv := make([]byte, 16)
	if _, err := aesEncryptCBCV6([]byte{1, 2, 3}, iv); err == nil {
		t.Fatal("expected error for non-block-sized plaintext (v6)")
	}
}

func TestAESDecryptCBCV6NonBlockSize(t *testing.T) {
	iv := make([]byte, 16)
	if _, err := aesDecryptCBCV6([]byte{1, 2, 3}, iv); err == nil {
		t.Fatal("expected error for non-block-sized ciphertext (v6)")
	}
}

// TestExpandKeyBranches covers the key-expansion switch branches:
// 16-, 20- and 32-byte keys (the 32-byte path hits the size==32 extra
// sub-byte application at currentSize%size==16).
func TestExpandKeyBranches(t *testing.T) {
	key16 := bytes.Repeat([]byte{0x01}, 16)
	key20 := bytes.Repeat([]byte{0x02}, 20)
	key32 := bytes.Repeat([]byte{0x03}, 32)

	if out := expandKey(key16, 16, 176); len(out) != 176 {
		t.Fatalf("expandKey(16) len = %d, want 176", len(out))
	}
	if out := expandKey(key20, 20, 192); len(out) != 192 {
		t.Fatalf("expandKey(20) len = %d, want 192", len(out))
	}
	if out := expandKey(key32, 32, 240); len(out) != 240 {
		t.Fatalf("expandKey(32) len = %d, want 240", len(out))
	}
}

// TestGoAESBlockFunctions directly exercises the pure-Go block cipher
// implementations regardless of whether the asm variants are selected at
// init time.
func TestGoAESBlockFunctions(t *testing.T) {
	in16 := [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

	roundTrip := func(enc, dec func(dst, input []byte), name string) {
		t.Helper()
		encOut := make([]byte, 16)
		decOut := make([]byte, 16)
		enc(encOut, in16[:])
		dec(decOut, encOut)
		if !bytes.Equal(decOut, in16[:]) {
			t.Fatalf("%s round trip mismatch: %x != %x", name, decOut, in16)
		}
	}

	roundTrip(aesEncryptBlockV4Go, aesDecryptBlockV4Go, "V4")
	roundTrip(aesEncryptBlockV6Go, aesDecryptBlockV6Go, "V6")
}

// TestGoBlockHelpersDirect covers parts of the AES internals that are only
// reached through the pure-Go block implementation.
func TestGoBlockHelpersDirect(t *testing.T) {
	// subBytes                -> both inv and forward.
	sub := bytes.Repeat([]byte{0x11}, 16)
	subBytes(sub, false)
	subBytes(sub, true)
	if !bytes.Equal(sub, bytes.Repeat([]byte{0x11}, 16)) {
		t.Fatalf("subBytes round trip mismatch: %x", sub)
	}

	// shiftRows               -> both inv and forward.
	shift := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	shiftRows(shift, false)
	shiftRows(shift, true)
	if !bytes.Equal(shift, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}) {
		t.Fatalf("shiftRows round trip mismatch: %x", shift)
	}

	// mixColumns              -> both inv and forward.
	mix := []byte{0xdb, 0x13, 0x53, 0x45, 0x13, 0x53, 0x45, 0xdb, 0x53, 0x45, 0xdb, 0x13, 0x45, 0xdb, 0x13, 0x53}
	mixColumns(mix, false)
	mixColumns(mix, true)
	if !bytes.Equal(mix, []byte{0xdb, 0x13, 0x53, 0x45, 0x13, 0x53, 0x45, 0xdb, 0x53, 0x45, 0xdb, 0x13, 0x45, 0xdb, 0x13, 0x53}) {
		t.Fatalf("mixColumns round trip mismatch: %x", mix)
	}

	// addRoundKey
	key := [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ak := bytes.Repeat([]byte{0x00}, 16)
	addRoundKey(ak, &key)
	if bytes.Equal(ak, bytes.Repeat([]byte{0x00}, 16)) {
		t.Fatal("addRoundKey had no effect")
	}

	// buildRoundKeys
	rk := buildRoundKeys(expandKey(bytes.Repeat([]byte{0x44}, 16), 16, 176), 10)
	if len(rk) != 11 {
		t.Fatalf("buildRoundKeys len = %d, want 11", len(rk))
	}
	v4rk := buildRoundKeys(expandKey(V4Key, 20, 192), 11)
	if len(v4rk) != 12 {
		t.Fatalf("buildRoundKeys(20) len = %d, want 12", len(v4rk))
	}
}

// TestV4RealKeyEncDec ensures the real V4 round keys round-trip correctly
// through both block directions.
func TestV4RealKeyEncDec(t *testing.T) {
	in := [16]byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00}
	enc := make([]byte, 16)
	dec := make([]byte, 16)
	aesEncryptBlockV4InPlace(enc, in[:])
	aesDecryptBlockV4InPlace(dec, enc)
	if !bytes.Equal(dec, in[:]) {
		t.Fatalf("V4 real key mismatch: %x", dec)
	}
}

// TestV5RoundKeysDirect forces the lazy v5RoundKeys initializer to run. This
// closure is otherwise dead code (v5 uses the standard library AES), so it is
// exercised directly to keep block-level coverage complete.
func TestV5RoundKeysDirect(t *testing.T) {
	rk := v5RoundKeys()
	if len(rk) != 11 {
		t.Fatalf("v5RoundKeys len = %d, want 11", len(rk))
	}
}
