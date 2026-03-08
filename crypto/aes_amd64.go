//go:build amd64 && !purego && !noasm

package crypto

import "sync"

var (
	aesAsmEnabled = sync.OnceValue(func() bool {
		return supportsAESASM() != 0
	})
	v4AsmRoundKeys = sync.OnceValue(func() *asmRoundKeys {
		return buildAsmRoundKeys(expandKey(V4Key, 20, 192), 11, false)
	})
	v6AsmRoundKeys = sync.OnceValue(func() *asmRoundKeys {
		return buildAsmRoundKeys(expandKey(V6Key, 16, 176), 10, true)
	})
)

func init() {
	if !aesAsmEnabled() {
		return
	}
	v4Keys := v4AsmRoundKeys()
	v6Keys := v6AsmRoundKeys()
	aesEncryptBlockV4Impl = func(dst, input []byte) {
		aesEncryptBlockAsm(11, &v4Keys.enc[0], dst, input)
	}
	aesDecryptBlockV4Impl = func(dst, input []byte) {
		aesDecryptBlockAsm(11, &v4Keys.dec[0], dst, input)
	}
	aesEncryptBlockV6Impl = func(dst, input []byte) {
		aesEncryptBlockAsm(10, &v6Keys.enc[0], dst, input)
	}
	aesDecryptBlockV6Impl = func(dst, input []byte) {
		aesDecryptBlockAsm(10, &v6Keys.dec[0], dst, input)
	}
}

//go:noescape
func supportsAESASM() uint32

//go:noescape
func aesEncryptBlockAsm(rounds int, roundKeys *[16]byte, dst, input []byte)

//go:noescape
func aesDecryptBlockAsm(rounds int, roundKeys *[16]byte, dst, input []byte)

func buildAsmRoundKeys(expandedKey []byte, rounds int, patchV6 bool) *asmRoundKeys {
	keys := &asmRoundKeys{}
	for i := 0; i <= rounds; i++ {
		copy(keys.enc[i][:], expandedKey[i*16:(i+1)*16])
	}
	if patchV6 {
		applyV6RoundPatches(keys.enc[:rounds+1])
	}
	keys.dec[0] = keys.enc[rounds]
	for i := 1; i < rounds; i++ {
		keys.dec[i] = invMixColumnsRoundKey(keys.enc[rounds-i])
	}
	keys.dec[rounds] = keys.enc[0]
	return keys
}

func invMixColumnsRoundKey(key [16]byte) [16]byte {
	out := key
	for col := range 4 {
		off := col * 4
		a0, a1, a2, a3 := out[off], out[off+1], out[off+2], out[off+3]
		out[off] = mul14Table[a0] ^ mul11Table[a1] ^ mul13Table[a2] ^ mul9Table[a3]
		out[off+1] = mul9Table[a0] ^ mul14Table[a1] ^ mul11Table[a2] ^ mul13Table[a3]
		out[off+2] = mul13Table[a0] ^ mul9Table[a1] ^ mul14Table[a2] ^ mul11Table[a3]
		out[off+3] = mul11Table[a0] ^ mul13Table[a1] ^ mul9Table[a2] ^ mul14Table[a3]
	}
	return out
}
