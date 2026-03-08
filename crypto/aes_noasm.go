//go:build !amd64 || purego || noasm

package crypto

func aesAsmAvailable() bool {
	return false
}

func supportsAESASM() uint32 {
	return 0
}

func aesEncryptBlockAsm(rounds int, roundKeys *[16]byte, dst, input []byte) {
	panic("aes asm unavailable")
}

func aesDecryptBlockAsm(rounds int, roundKeys *[16]byte, dst, input []byte) {
	panic("aes asm unavailable")
}

func v4AsmKeys() *asmRoundKeys {
	panic("aes asm unavailable")
}

func v6AsmKeys() *asmRoundKeys {
	panic("aes asm unavailable")
}
