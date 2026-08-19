package client

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/xmdhs/go-kms/kms"
)

// TestRun drives the os.Stdout wrapper end-to-end against a fake server.
func TestRun(t *testing.T) {
	port, closeFn := startFakeServer(t, kms.DefaultServerConfig())
	defer closeFn()

	cfg := &ClientConfig{IP: "127.0.0.1", Port: port, Mode: "Windows8.1",
		CMID: "78563412-bc9a-f0de-1122-334455667788", Machine: "TESTBOX"}
	if err := Run(cfg); err != nil {
		t.Fatalf("Run error = %v", err)
	}
}

// TestParseV5V6DecryptError drives the "failed to decrypt response" branch via
// a ciphertext whose length is not a multiple of the block size.
func TestParseV5V6DecryptError(t *testing.T) {
	var out bytes.Buffer
	// bodyLen1 = 8 -> padding 4; remaining is 37 bytes so that
	// encryptedEnd = 37-4 = 33 and encrypted = remaining[16:33] = 17 bytes.
	r := make([]byte, 16+37)
	binary.LittleEndian.PutUint32(r[0:4], 8)
	if err := parseV5V6Response(r, false, &out); err == nil {
		t.Fatal("expected decrypt error")
	}
}

// TestParseV4ResponseParseError drives ParseKMSResponse failure inside
// parseV4ResponseTo (body captures zero bytes of request data).
func TestParseV4ResponseParseError(t *testing.T) {
	var out bytes.Buffer
	// bodyLen2 = 20 with 28 bytes of remaining data -> responseData = 4 bytes,
	// which ParseKMSResponse rejects (needs at least 12).
	r := make([]byte, 12+28)
	binary.LittleEndian.PutUint32(r[8:12], 20)
	if err := parseV4ResponseTo(r, &out); err == nil {
		t.Fatal("expected ParseKMSResponse error")
	}
}
