//go:build amd64 && !purego && !noasm

package crypto

func platformAESAsmAvailable() bool {
	return supportsAESASM() != 0
}


//go:noescape
func supportsAESASM() uint32
