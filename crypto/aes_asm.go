//go:build (amd64 || arm64) && !purego && !noasm

package crypto

import "sync"

var (
	aesAsmEnabled = sync.OnceValue(platformAESAsmAvailable)
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
