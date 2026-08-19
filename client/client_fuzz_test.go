package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/xmdhs/go-kms/crypto"
	"github.com/xmdhs/go-kms/kms"
)

// mkReqWireNoT builds a valid KMS request wire without a *testing.T.
func mkReqWireNoT(major uint16, isV6 bool) []byte {
	req := &kms.KMSRequest{
		VersionMinor: 1, VersionMajor: major, LicenseStatus: 2, GraceTime: 100,
		ApplicationID: kms.RandomUUID(), SKUID: kms.RandomUUID(),
		KMSCountedID: kms.RandomUUID(), ClientMachineID: kms.RandomUUID(),
		RequiredClientCount: 25, RequestTime: 123, MachineNameRaw: make([]byte, 128),
	}
	kb := req.Marshal()
	esalt := crypto.RandomSalt()
	dsalt, err := crypto.KMSDecryptCBC(esalt, esalt, isV6)
	if err != nil {
		panic(err)
	}
	plain := make([]byte, 0, 16+len(kb))
	plain = append(plain, dsalt[:16]...)
	plain = append(plain, kb...)
	ct, err := crypto.KMSEncryptCBC(crypto.PKCS7Pad(plain, 16), esalt, isV6)
	if err != nil {
		panic(err)
	}
	bodyLen := uint32(2 + 2 + len(ct))
	w := make([]byte, 12+len(ct))
	binary.LittleEndian.PutUint32(w[0:4], bodyLen)
	binary.LittleEndian.PutUint32(w[4:8], bodyLen)
	binary.LittleEndian.PutUint16(w[8:10], 1)
	binary.LittleEndian.PutUint16(w[10:12], major)
	copy(w[12:], ct)
	return w
}

func mkRespWireNoT(reqWire []byte) []byte {
	data, err := kms.GenerateKMSResponseData(context.Background(), reqWire, kms.DefaultServerConfig())
	if err != nil {
		panic(err)
	}
	return data
}

// FuzzParseV4ResponseTo exercises the V4 response parser. Success must print
// the full response header, so the parser never swallows a valid payload.
func FuzzParseV4ResponseTo(f *testing.F) {
	f.Add([]byte{})
	f.Add(mkRespWireNoT(mkReqWireNoT(4, false)))
	f.Fuzz(func(t *testing.T, data []byte) {
		var buf bytes.Buffer
		if err := parseV4ResponseTo(data, &buf); err != nil {
			return
		}
		if !bytes.Contains(buf.Bytes(), []byte("KMS Response")) {
			t.Fatalf("successful parse printed no response: %q", buf.String())
		}
	})
}

// FuzzParseV5ResponseTo exercises the V5 response parser (standard-library AES
// decrypt path). V5 and V6 must be fuzzed separately: their decrypt branches
// diverge inside KMSDecryptCBC.
func FuzzParseV5ResponseTo(f *testing.F) {
	f.Add([]byte{})
	f.Add(mkRespWireNoT(mkReqWireNoT(5, false)))
	f.Fuzz(func(t *testing.T, data []byte) {
		var buf bytes.Buffer
		if err := parseV5V6Response(data, false, &buf); err != nil {
			return
		}
		if !bytes.Contains(buf.Bytes(), []byte("KMS Response")) {
			t.Fatalf("successful parse printed no response: %q", buf.String())
		}
	})
}

// FuzzParseV6ResponseTo exercises the V6 response parser (custom patched AES
// decrypt path).
func FuzzParseV6ResponseTo(f *testing.F) {
	f.Add([]byte{})
	f.Add(mkRespWireNoT(mkReqWireNoT(6, true)))
	f.Fuzz(func(t *testing.T, data []byte) {
		var buf bytes.Buffer
		if err := parseV5V6Response(data, true, &buf); err != nil {
			return
		}
		if !bytes.Contains(buf.Bytes(), []byte("KMS Response")) {
			t.Fatalf("successful parse printed no response: %q", buf.String())
		}
	})
}
