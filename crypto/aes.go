package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
)

// PKCS7Pad pads data to a multiple of blockSize using PKCS7.
func PKCS7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padBytes := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padBytes...)
}

// PKCS7Unpad removes PKCS7 padding.
func PKCS7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("data length %d is not a multiple of 16", len(data))
	}
	padding := int(data[len(data)-1])
	if padding > 16 || padding == 0 {
		return nil, fmt.Errorf("invalid PKCS7 padding: %d", padding)
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid PKCS7 padding byte at position %d", i)
		}
	}
	return data[:len(data)-padding], nil
}

// V5Key is the AES key used for KMS protocol version 5.
var V5Key = []byte{0xCD, 0x7E, 0x79, 0x6F, 0x2A, 0xB2, 0x5D, 0xCB, 0x55, 0xFF, 0xC8, 0xEF, 0x83, 0x64, 0xC4, 0x70}

// V6Key is the AES key used for KMS protocol version 6.
var V6Key = []byte{0xA9, 0x4A, 0x41, 0x95, 0xE2, 0x01, 0x43, 0x2D, 0x9B, 0xCB, 0x46, 0x04, 0x05, 0xD8, 0x4A, 0x21}

// V4Key is the custom 160-bit key used for KMS protocol version 4.
var V4Key = []byte{0x05, 0x3D, 0x83, 0x07, 0xF9, 0xE5, 0xF0, 0x88, 0xEB, 0x5E, 0xA6, 0x68, 0x6C, 0xF0, 0x37, 0xC7, 0xE4, 0xEF, 0xD2, 0xD6}

// Precomputed round keys for performance (using sync.OnceValue for lazy initialization)
var (
	v5RoundKeys = sync.OnceValue(func() [][16]byte {
		return buildRoundKeys(expandKey(V5Key, 16, 176), 10)
	})
	v6RoundKeys = sync.OnceValue(func() [][16]byte {
		return buildRoundKeys(expandKey(V6Key, 16, 176), 10)
	})
	v4RoundKeys = sync.OnceValue(func() [][16]byte {
		return buildRoundKeys(expandKey(V4Key, 20, 192), 11)
	})
)

// KMSEncryptCBC encrypts KMS V5/V6 payload data using protocol-defined AES-CBC.
// The caller is responsible for PKCS7 padding before calling this function.
func KMSEncryptCBC(data, iv []byte, v6 bool) ([]byte, error) {
	if v6 {
		return aesEncryptCBCV6(data, iv)
	}
	block, err := aes.NewCipher(V5Key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("plaintext is not a multiple of block size")
	}
	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)
	return ciphertext, nil
}

// KMSDecryptCBC decrypts KMS V5/V6 payload data using protocol-defined AES-CBC.
func KMSDecryptCBC(data, iv []byte, v6 bool) ([]byte, error) {
	if v6 {
		return aesDecryptCBCV6(data, iv)
	}
	block, err := aes.NewCipher(V5Key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}
	plaintext := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, data)
	return plaintext, nil
}

// v6RoundPatch returns the XOR patch applied during V6 AES rounds.
// Round 4: state[0] ^= 0x73, Round 6: state[0] ^= 0x09, Round 8: state[0] ^= 0xE4
func v6RoundPatch(round int) byte {
	switch round {
	case 4:
		return 0x73
	case 6:
		return 0x09
	case 8:
		return 0xE4
	default:
		return 0
	}
}

// aesEncryptCBCV6 implements AES-CBC encryption with V6 round modifications.
// Since Go's standard crypto/aes doesn't support round-level hooks,
// we implement a custom AES for V6 that applies XOR patches at specific rounds.
func aesEncryptCBCV6(data, iv []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("plaintext is not a multiple of block size")
	}
	ciphertext := make([]byte, len(data))
	var prevBlock [16]byte
	copy(prevBlock[:], iv)
	var block [16]byte
	var encrypted [16]byte

	for i := 0; i < len(data); i += 16 {
		for j := range 16 {
			block[j] = data[i+j] ^ prevBlock[j]
		}
		aesEncryptBlockV6InPlace(encrypted[:], block[:])
		copy(ciphertext[i:], encrypted[:])
		copy(prevBlock[:], encrypted[:])
	}
	return ciphertext, nil
}

func aesDecryptCBCV6(data, iv []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}
	plaintext := make([]byte, len(data))
	var prevBlock [16]byte
	copy(prevBlock[:], iv)
	var decrypted [16]byte

	for i := 0; i < len(data); i += 16 {
		aesDecryptBlockV6InPlace(decrypted[:], data[i:i+16])
		for j := range 16 {
			plaintext[i+j] = decrypted[j] ^ prevBlock[j]
		}
		copy(prevBlock[:], data[i:i+16])
	}
	return plaintext, nil
}

// V4Hash computes the KMS V4 hash (custom AES-CMAC variant with 160-bit key).
func V4Hash(message []byte) []byte {
	messageSize := len(message)
	var hashBuffer [16]byte
	var encrypted [16]byte
	roundKeys := v4RoundKeys()

	// Number of full 16-byte blocks.
	j := messageSize >> 4
	// Remaining bytes.
	k := messageSize & 0xf

	// Process full blocks.
	for i := range j {
		base := i * 16
		for b := range 16 {
			hashBuffer[b] ^= message[base+b]
		}
		aesEncryptBlockCustomInPlace(encrypted[:], hashBuffer[:], roundKeys, 11)
		hashBuffer = encrypted
	}

	// Process last block with bit padding.
	var lastBlock [16]byte
	for i := range k {
		lastBlock[i] = message[j*16+i]
	}
	lastBlock[k] = 0x80

	for b := range 16 {
		hashBuffer[b] ^= lastBlock[b]
	}
	aesEncryptBlockCustomInPlace(encrypted[:], hashBuffer[:], v4RoundKeys(), 11)
	hashBuffer = encrypted

	output := make([]byte, 16)
	copy(output, hashBuffer[:])
	return output
}

// RandomSalt generates a 16-byte random salt.
func RandomSalt() []byte {
	salt := make([]byte, 16)
	rand.Read(salt)
	return salt
}

// V6MACKey derives the HMAC key from the request timestamp.
func V6MACKey(requestTime uint64) []byte {
	c1 := uint64(0x00000022816889BD)
	c2 := uint64(0x000000208CBAB5ED)
	c3 := uint64(0x3156CD5AC628477A)

	i1 := requestTime / c1
	i2 := i1 * c2
	seed := i2 + c3

	h := sha256.New()
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, seed)
	h.Write(buf)
	digest := h.Sum(nil)

	return digest[16:]
}

// V6HMAC computes the HMAC-SHA256 for V6 response.
func V6HMAC(macKey, data []byte) []byte {
	h := hmac.New(sha256.New, macKey)
	h.Write(data)
	return h.Sum(nil)
}

// --- Custom AES implementation for V4 (160-bit key) and V6 (round patches) ---

// Rijndael S-box.
var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

// Rijndael inverse S-box.
var rsbox = [256]byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

// Rcon values.
var rcon = [256]byte{
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
	0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
	0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
	0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
	0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
	0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
	0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
	0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
	0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
	0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
	0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
	0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
	0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
	0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
	0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
	0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
	0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
	0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
	0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
	0xe8, 0xcb,
}

func galoisMult(a, b byte) byte {
	var p byte
	for range 8 {
		if b&1 != 0 {
			p ^= a
		}
		hiBit := a & 0x80
		a <<= 1
		if hiBit != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

func buildRoundKeys(expandedKey []byte, rounds int) [][16]byte {
	roundKeys := make([][16]byte, rounds+1)
	for r := 0; r <= rounds; r++ {
		offset := r * 16
		for i := range 4 {
			for j := range 4 {
				roundKeys[r][j*4+i] = expandedKey[offset+i*4+j]
			}
		}
	}
	return roundKeys
}

func buildMulTable(mult byte) [256]byte {
	var table [256]byte
	for i := 0; i < 256; i++ {
		table[i] = galoisMult(byte(i), mult)
	}
	return table
}

var (
	mul2Table  = buildMulTable(2)
	mul3Table  = buildMulTable(3)
	mul9Table  = buildMulTable(9)
	mul11Table = buildMulTable(11)
	mul13Table = buildMulTable(13)
	mul14Table = buildMulTable(14)
)

func expandKey(key []byte, size, expandedKeySize int) []byte {
	expandedKey := make([]byte, expandedKeySize)
	copy(expandedKey, key[:size])
	currentSize := size
	rconIteration := 1

	for currentSize < expandedKeySize {
		var t [4]byte
		copy(t[:], expandedKey[currentSize-4:currentSize])

		if currentSize%size == 0 {
			// Rotate.
			t[0], t[1], t[2], t[3] = t[1], t[2], t[3], t[0]
			// SubBytes.
			for i := range t {
				t[i] = sbox[t[i]]
			}
			t[0] ^= rcon[rconIteration]
			rconIteration++
		}
		if size == 32 && currentSize%size == 16 {
			for i := range t {
				t[i] = sbox[t[i]]
			}
		}

		for i := range 4 {
			expandedKey[currentSize] = expandedKey[currentSize-size] ^ t[i]
			currentSize++
		}
	}
	return expandedKey
}

func subBytes(state []byte, inv bool) {
	box := &sbox
	if inv {
		box = &rsbox
	}
	for i := range state {
		state[i] = box[state[i]]
	}
}

func shiftRows(state []byte, inv bool) {
	if inv {
		state[4], state[5], state[6], state[7] = state[7], state[4], state[5], state[6]
		state[8], state[9], state[10], state[11] = state[10], state[11], state[8], state[9]
		state[12], state[13], state[14], state[15] = state[13], state[14], state[15], state[12]
		return
	}

	state[4], state[5], state[6], state[7] = state[5], state[6], state[7], state[4]
	state[8], state[9], state[10], state[11] = state[10], state[11], state[8], state[9]
	state[12], state[13], state[14], state[15] = state[15], state[12], state[13], state[14]
}

func mixColumn(state []byte, i0, i1, i2, i3 int, inv bool) {
	a0, a1, a2, a3 := state[i0], state[i1], state[i2], state[i3]
	if inv {
		state[i0] = mul14Table[a0] ^ mul9Table[a3] ^ mul13Table[a2] ^ mul11Table[a1]
		state[i1] = mul14Table[a1] ^ mul9Table[a0] ^ mul13Table[a3] ^ mul11Table[a2]
		state[i2] = mul14Table[a2] ^ mul9Table[a1] ^ mul13Table[a0] ^ mul11Table[a3]
		state[i3] = mul14Table[a3] ^ mul9Table[a2] ^ mul13Table[a1] ^ mul11Table[a0]
		return
	}
	state[i0] = mul2Table[a0] ^ a3 ^ a2 ^ mul3Table[a1]
	state[i1] = mul2Table[a1] ^ a0 ^ a3 ^ mul3Table[a2]
	state[i2] = mul2Table[a2] ^ a1 ^ a0 ^ mul3Table[a3]
	state[i3] = mul2Table[a3] ^ a2 ^ a1 ^ mul3Table[a0]
}

func mixColumns(state []byte, inv bool) {
	mixColumn(state, 0, 4, 8, 12, inv)
	mixColumn(state, 1, 5, 9, 13, inv)
	mixColumn(state, 2, 6, 10, 14, inv)
	mixColumn(state, 3, 7, 11, 15, inv)
}

func addRoundKey(state []byte, roundKey *[16]byte) {
	for i := range 16 {
		state[i] ^= roundKey[i]
	}
}

func aesEncryptBlockCustomInPlace(dst, input []byte, roundKeys [][16]byte, nbrRounds int) {
	// Map input to state (column-major).
	var state [16]byte
	for i := range 4 {
		for j := range 4 {
			state[i+j*4] = input[i*4+j]
		}
	}

	// Initial round key addition.
	addRoundKey(state[:], &roundKeys[0])

	// Main rounds.
	for i := 1; i < nbrRounds; i++ {
		subBytes(state[:], false)
		shiftRows(state[:], false)
		mixColumns(state[:], false)
		addRoundKey(state[:], &roundKeys[i])
	}

	// Final round (no mixColumns).
	subBytes(state[:], false)
	shiftRows(state[:], false)
	addRoundKey(state[:], &roundKeys[nbrRounds])

	// Unmap state to output.
	for i := range 4 {
		for j := range 4 {
			dst[i*4+j] = state[i+j*4]
		}
	}
}

func aesEncryptBlockCustom(input []byte, keySize int) []byte {
	output := make([]byte, 16)
	switch keySize {
	case 16:
		aesEncryptBlockCustomInPlace(output, input, v5RoundKeys(), 10)
	case 20:
		aesEncryptBlockCustomInPlace(output, input, v4RoundKeys(), 11)
	default:
		panic(fmt.Sprintf("invalid key size: %d", keySize))
	}
	return output
}

func aesDecryptBlockCustomInPlace(dst, input []byte, roundKeys [][16]byte, nbrRounds int) {
	var state [16]byte
	for i := range 4 {
		for j := range 4 {
			state[i+j*4] = input[i*4+j]
		}
	}

	addRoundKey(state[:], &roundKeys[nbrRounds])

	for i := nbrRounds - 1; i > 0; i-- {
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

func aesDecryptBlockCustom(input []byte, keySize int) []byte {
	output := make([]byte, 16)
	switch keySize {
	case 16:
		aesDecryptBlockCustomInPlace(output, input, v5RoundKeys(), 10)
	case 20:
		aesDecryptBlockCustomInPlace(output, input, v4RoundKeys(), 11)
	default:
		panic(fmt.Sprintf("invalid key size: %d", keySize))
	}
	return output
}

// aesEncryptBlockV6 encrypts a single block using AES-128 with V6 round patches.
func aesEncryptBlockV6InPlace(dst, input []byte) {
	roundKeys := v6RoundKeys()
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
		if patch := v6RoundPatch(i); patch != 0 {
			state[0] ^= patch
		}
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

func aesEncryptBlockV6(input []byte) []byte {
	output := make([]byte, 16)
	aesEncryptBlockV6InPlace(output, input)
	return output
}

// aesDecryptBlockV6 decrypts a single block using AES-128 with V6 round patches.
func aesDecryptBlockV6InPlace(dst, input []byte) {
	roundKeys := v6RoundKeys()
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
		if patch := v6RoundPatch(i); patch != 0 {
			state[0] ^= patch
		}
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

func aesDecryptBlockV6(input []byte) []byte {
	output := make([]byte, 16)
	aesDecryptBlockV6InPlace(output, input)
	return output
}
