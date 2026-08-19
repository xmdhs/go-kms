//go:build (amd64 || arm64) && !purego && !noasm

package crypto

import (
	"bytes"
	"sync"
	"testing"
)

// TestSetupAESAsmToggle exercises both paths of setupAESAsm: the early-return
// (no hardware AES) branch and the asm wiring branch. On dev machines with AES
// support the early return would otherwise never run.
func TestSetupAESAsmToggle(t *testing.T) {
	origEncV4, origDecV4 := aesEncryptBlockV4Impl, aesDecryptBlockV4Impl
	origEncV6, origDecV6 := aesEncryptBlockV6Impl, aesDecryptBlockV6Impl
	origEnabled := aesAsmEnabled

	t.Cleanup(func() {
		aesAsmEnabled = origEnabled
		aesEncryptBlockV4Impl = origEncV4
		aesDecryptBlockV4Impl = origDecV4
		aesEncryptBlockV6Impl = origEncV6
		aesDecryptBlockV6Impl = origDecV6
		// Re-run setup so later tests use the normal asm paths again.
		setupAESAsm()
	})

	// Disabled path: early return, impls must not change.
	aesAsmEnabled = sync.OnceValue(func() bool { return false })
	setupAESAsm()

	// Enabled path: impls are wired to asm closures.
	aesAsmEnabled = sync.OnceValue(func() bool { return true })
	setupAESAsm()

	in := bytes.Repeat([]byte{0x42}, 16)
	enc := make([]byte, 16)
	dec := make([]byte, 16)
	aesEncryptBlockV4Impl(enc, in)
	aesDecryptBlockV4Impl(dec, enc)
	if !bytes.Equal(dec, in) {
		t.Fatal("asm V4 round trip mismatch")
	}
	aesEncryptBlockV6Impl(enc, in)
	aesDecryptBlockV6Impl(dec, enc)
	if !bytes.Equal(dec, in) {
		t.Fatal("asm V6 round trip mismatch")
	}
}
