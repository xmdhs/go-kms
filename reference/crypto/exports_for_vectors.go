// Exported wrappers for low-level block-cipher primitives, intended for use by
// the parity test-vector generator (cmd/genvectors). Not part of the public
// runtime API of the project.

package crypto

func AESEncryptBlockV4(dst, input []byte) { aesEncryptBlockV4InPlace(dst, input) }
func AESDecryptBlockV4(dst, input []byte) { aesDecryptBlockV4InPlace(dst, input) }
func AESEncryptBlockV6(dst, input []byte) { aesEncryptBlockV6InPlace(dst, input) }
func AESDecryptBlockV6(dst, input []byte) { aesDecryptBlockV6InPlace(dst, input) }
