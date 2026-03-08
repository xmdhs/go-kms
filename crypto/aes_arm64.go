//go:build arm64 && !purego && !noasm

package crypto

import "golang.org/x/sys/cpu"

func platformAESAsmAvailable() bool {
	return cpu.ARM64.HasAES
}
