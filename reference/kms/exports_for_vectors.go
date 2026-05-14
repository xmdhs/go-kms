// Exported helpers for the parity test-vector generator. Not used at runtime.

package kms

// EpidBytesForTest returns the cached UTF-16LE epid bytes after at least one
// ServerLogic invocation has populated config.epid. If empty, encodes the
// configured EPID string directly (or generates a random UUID otherwise).
func (c *ServerConfig) EpidBytesForTest() []byte {
	c.epidOnce.Do(func() {
		if c.EPID == "" {
			c.epid = EncodeUTF16LE(RandomUUID().String())
			return
		}
		c.epid = EncodeUTF16LE(c.EPID)
	})
	return c.epid
}
