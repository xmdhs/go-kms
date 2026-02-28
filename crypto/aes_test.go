package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestPKCS7Pad(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		blockSize int
		wantLen   int
		wantPad   byte
	}{
		{name: "empty", input: []byte{}, blockSize: 16, wantLen: 16, wantPad: 16},
		{name: "not aligned", input: []byte("abc"), blockSize: 16, wantLen: 16, wantPad: 13},
		{name: "aligned", input: bytes.Repeat([]byte{0x11}, 16), blockSize: 16, wantLen: 32, wantPad: 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PKCS7Pad(append([]byte(nil), tt.input...), tt.blockSize)
			if len(got) != tt.wantLen {
				t.Fatalf("len(PKCS7Pad()) = %d, want %d", len(got), tt.wantLen)
			}
			for i := len(got) - int(tt.wantPad); i < len(got); i++ {
				if got[i] != tt.wantPad {
					t.Fatalf("padding byte[%d] = %d, want %d", i, got[i], tt.wantPad)
				}
			}
		})
	}
}

func TestPKCS7Unpad(t *testing.T) {
	valid := PKCS7Pad([]byte("kms-test"), 16)
	got, err := PKCS7Unpad(valid)
	if err != nil {
		t.Fatalf("PKCS7Unpad(valid) error = %v", err)
	}
	if string(got) != "kms-test" {
		t.Fatalf("PKCS7Unpad(valid) = %q, want %q", string(got), "kms-test")
	}

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "empty data", input: []byte{}},
		{name: "non block size", input: []byte{1, 2, 3}},
		{name: "zero padding", input: append(bytes.Repeat([]byte{0x41}, 15), 0x00)},
		{name: "padding too large", input: append(bytes.Repeat([]byte{0x41}, 15), 0x11)},
		{name: "padding mismatch", input: append(bytes.Repeat([]byte{0x41}, 14), 0x02, 0x03)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PKCS7Unpad(tt.input); err == nil {
				t.Fatalf("PKCS7Unpad(%v) expected error, got nil", tt.input)
			}
		})
	}
}

func TestKMSEncryptDecryptCBCRoundTrip(t *testing.T) {
	iv := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
	lengths := []int{0, 1, 15, 16, 17, 31, 32, 63}
	versions := []struct {
		name string
		v6   bool
	}{
		{name: "v5", v6: false},
		{name: "v6", v6: true},
	}

	for _, v := range versions {
		for _, n := range lengths {
			t.Run(fmt.Sprintf("%s-len-%d", v.name, n), func(t *testing.T) {
				plain := bytes.Repeat([]byte{byte(n + 1)}, n)
				padded := PKCS7Pad(plain, 16)
				cipherText, err := KMSEncryptCBC(padded, iv, v.v6)
				if err != nil {
					t.Fatalf("KMSEncryptCBC error = %v", err)
				}
				decrypted, err := KMSDecryptCBC(cipherText, iv, v.v6)
				if err != nil {
					t.Fatalf("KMSDecryptCBC error = %v", err)
				}
				unpadded, err := PKCS7Unpad(decrypted)
				if err != nil {
					t.Fatalf("PKCS7Unpad error = %v", err)
				}
				if !bytes.Equal(unpadded, plain) {
					t.Fatalf("round trip mismatch: got %x want %x", unpadded, plain)
				}
			})
		}
	}
}

func TestAESV6BlockRoundTrip(t *testing.T) {
	blocks := [][]byte{
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		bytes.Repeat([]byte{0x5A}, 16),
	}

	for i, block := range blocks {
		encrypted := aesEncryptBlockV6(block)
		decrypted := aesDecryptBlockV6(encrypted)
		if !bytes.Equal(decrypted, block) {
			t.Fatalf("block #%d mismatch: got %x want %x", i, decrypted, block)
		}
	}
}

func TestV4HashDeterministic(t *testing.T) {
	input := []byte("fixed-v4-hash-input")
	h1 := V4Hash(input)
	h2 := V4Hash(input)
	if !bytes.Equal(h1, h2) {
		t.Fatalf("V4Hash not deterministic: %x != %x", h1, h2)
	}
}

func TestStableVectorsMatchBaseline(t *testing.T) {
	iv := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
	plain := PKCS7Pad([]byte("baseline-vector-data"), 16)

	v5c, err := KMSEncryptCBC(plain, iv, false)
	if err != nil {
		t.Fatalf("KMSEncryptCBC v5 error: %v", err)
	}
	v6c, err := KMSEncryptCBC(plain, iv, true)
	if err != nil {
		t.Fatalf("KMSEncryptCBC v6 error: %v", err)
	}
	v5p, err := KMSDecryptCBC(v5c, iv, false)
	if err != nil {
		t.Fatalf("KMSDecryptCBC v5 error: %v", err)
	}
	v6p, err := KMSDecryptCBC(v6c, iv, true)
	if err != nil {
		t.Fatalf("KMSDecryptCBC v6 error: %v", err)
	}

	checkHex := func(name string, got []byte, want string) {
		t.Helper()
		if hex.EncodeToString(got) != want {
			t.Fatalf("%s mismatch: got %s want %s", name, hex.EncodeToString(got), want)
		}
	}

	checkHex("V5CBC", v5c, "3de528e57853c743ede9ffbb4177d273792e4ec579be591cc4cdc8e1f970df76")
	checkHex("V6CBC", v6c, "72e5d15d6c3ec1cf9f3b035cef80c853eea1766833d799e008648877675ca750")
	checkHex("V5DEC", v5p, "626173656c696e652d766563746f722d646174610c0c0c0c0c0c0c0c0c0c0c0c")
	checkHex("V6DEC", v6p, "626173656c696e652d766563746f722d646174610c0c0c0c0c0c0c0c0c0c0c0c")

	block := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
	v6e := aesEncryptBlockV6(block)
	v6d := aesDecryptBlockV6(v6e)
	v4e := aesEncryptBlockCustom(block, 20)
	v4d := aesDecryptBlockCustom(v4e, 20)

	checkHex("V6BLKENC", v6e, "ca89ca11b2c4e77a94e806af17136b38")
	checkHex("V6BLKDEC", v6d, "000102030405060708090a0b0c0d0e0f")
	checkHex("V4BLKENC", v4e, "28916e4a0ee525b42cf393cae0f4dc9a")
	checkHex("V4BLKDEC", v4d, "000102030405060708090a0b0c0d0e0f")

	h := V4Hash([]byte("baseline-v4-hash-input"))
	k := V6MACKey(13322345678901234567)
	m := V6HMAC(k, []byte("baseline-v6-hmac-input"))

	checkHex("V4HASH", h, "7f2db248dc798b8bc805f6e330a9b06b")
	checkHex("V6MACKEY", k, "8012fac9c77fb0f401b438c8b96f4e1d")
	checkHex("V6HMAC", m, "27214d078c7f492a71a86a75ccc0f83a31fcf1f29529689c5a4add1ddd17a148")
}
