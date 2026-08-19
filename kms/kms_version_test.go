package kms

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/xmdhs/go-kms/crypto"
)

// makeV5V6WireData mirrors client.buildV5V6ClientRequest: it produces a
// request the server's handleV5V6Request can successfully decrypt.
func makeV5V6WireData(kmsBytes []byte, protMajor uint16, isV6 bool) []byte {
	esalt := crypto.RandomSalt()
	iv := append([]byte(nil), esalt...)
	dsalt, err := crypto.KMSDecryptCBC(esalt, iv, isV6)
	if err != nil {
		panic(err)
	}
	plain := make([]byte, 0, 16+len(kmsBytes))
	plain = append(plain, dsalt[:16]...)
	plain = append(plain, kmsBytes...)
	padded := crypto.PKCS7Pad(plain, 16)
	encIV := append([]byte(nil), esalt...)
	encrypted, err := crypto.KMSEncryptCBC(padded, encIV, isV6)
	if err != nil {
		panic(err)
	}

	bodyLen := uint32(2 + 2 + len(encrypted))
	data := make([]byte, 12+len(encrypted))
	binary.LittleEndian.PutUint32(data[0:4], bodyLen)
	binary.LittleEndian.PutUint32(data[4:8], bodyLen)
	binary.LittleEndian.PutUint16(data[8:10], 1) // version minor
	binary.LittleEndian.PutUint16(data[10:12], protMajor)
	copy(data[12:], encrypted)
	return data
}

func validKMSBytes(t *testing.T) []byte {
	t.Helper()
	return buildValidRequestData()
}

func makeHeader(bodyLen1, bodyLen2 uint32, minor, major uint16) []byte {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], bodyLen1)
	binary.LittleEndian.PutUint32(data[4:8], bodyLen2)
	binary.LittleEndian.PutUint16(data[8:10], minor)
	binary.LittleEndian.PutUint16(data[10:12], major)
	return data
}

func TestHandleV4RequestErrors(t *testing.T) {
	ctx := context.Background()
	cfg := &ServerConfig{}

	req := &KMSRequest{
		VersionMinor: 0, VersionMajor: 4, LicenseStatus: 2, GraceTime: 100,
		ApplicationID: RandomUUID(), SKUID: RandomUUID(),
		KMSCountedID: RandomUUID(), ClientMachineID: RandomUUID(),
		RequiredClientCount: 25, RequestTime: 123, MachineNameRaw: make([]byte, 128),
	}
	reqBytes := req.Marshal()
	hash := crypto.V4Hash(reqBytes)

	wire := make([]byte, 4+4+len(reqBytes)+16)
	binary.LittleEndian.PutUint32(wire[0:4], uint32(len(reqBytes)+16))
	binary.LittleEndian.PutUint32(wire[4:8], uint32(len(reqBytes)+16))
	copy(wire[8:], reqBytes)
	copy(wire[8+len(reqBytes):], hash[:])

	if _, err := HandleV4Request(ctx, wire[:7], cfg); err == nil {
		t.Fatal("expected error for data < 8 bytes")
	}

	// bodyLength1 shorter than the hash (16).
	shortLen := make([]byte, 8)
	binary.LittleEndian.PutUint32(shortLen[0:4], 4)
	binary.LittleEndian.PutUint32(shortLen[4:8], 4)
	shortData := append(shortLen, make([]byte, 16)...)
	if _, err := HandleV4Request(ctx, shortData, cfg); err == nil {
		t.Fatal("expected error for body length < 16")
	}

	// bodyLength1 larger than the remaining data.
	bigLen := make([]byte, 8)
	binary.LittleEndian.PutUint32(bigLen[0:4], 500)
	binary.LittleEndian.PutUint32(bigLen[4:8], 500)
	if _, err := HandleV4Request(ctx, bigLen, cfg); err == nil {
		t.Fatal("expected body length mismatch error")
	}

	// bodyLength1 covers the hash (16) but leaves a KMS request too short to parse.
	emptyReq := make([]byte, 8+16)
	binary.LittleEndian.PutUint32(emptyReq[0:4], 16)
	binary.LittleEndian.PutUint32(emptyReq[4:8], 16)
	if _, err := HandleV4Request(ctx, emptyReq, cfg); err == nil {
		t.Fatal("expected KMS request parse error")
	}

	// Success path.
	resp, err := HandleV4Request(ctx, wire, cfg)
	if err != nil {
		t.Fatalf("HandleV4Request success error = %v", err)
	}
	if len(resp) < 12 {
		t.Fatalf("V4 response too short: %d", len(resp))
	}
}

func TestHandleV5V6Branches(t *testing.T) {
	ctx := context.Background()
	cfg := &ServerConfig{}

	versions := []struct {
		name  string
		major uint16
		isV6  bool
	}{
		{"v5", 5, false},
		{"v6", 6, true},
	}

	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			call := func(ctx context.Context, data []byte, hdr *GenericRequestHeader) ([]byte, error) {
				if v.isV6 {
					return HandleV6Request(ctx, data, hdr, cfg)
				}
				return HandleV5Request(ctx, data, hdr, cfg)
			}

			// Success (uses the correct handler for the wire's own protocol).
			wire := makeV5V6WireData(validKMSBytes(t), v.major, v.isV6)
			if _, err := call(ctx, wire, &GenericRequestHeader{BodyLength1: binary.LittleEndian.Uint32(wire[0:4]), VersionMinor: 1, VersionMajor: v.major}); err != nil {
				t.Fatalf("%s success error = %v", v.name, err)
			}

			// Ciphertext length longer than the message data.
			hdrBig := &GenericRequestHeader{BodyLength1: 1000, VersionMinor: 1, VersionMajor: v.major}
			if _, err := call(ctx, make([]byte, 12), hdrBig); err == nil {
				t.Fatal("expected message-too-short error")
			}

			// ciphertextLen < 16.
			short := make([]byte, 12+16)
			copy(short[:12], makeHeader(18, 18, 1, v.major))
			if _, err := call(ctx, short, &GenericRequestHeader{BodyLength1: 18, VersionMinor: 1, VersionMajor: v.major}); err == nil {
				t.Fatal("expected ciphertext-too-short error")
			}

			// Decrypt failure: ciphertext length is not a multiple of 16.
			badCT := make([]byte, 12+17)
			copy(badCT[:12], makeHeader(21, 21, 1, v.major))
			if _, err := call(ctx, badCT, &GenericRequestHeader{BodyLength1: 21, VersionMinor: 1, VersionMajor: v.major}); err == nil {
				t.Fatal("expected decrypt error")
			}
		})
	}
}

// findInvalidPaddingSalt searches for a 16-byte ciphertext whose single-block
// decryption result has invalid PKCS7 padding (so PKCS7Unpad errors).
func findInvalidPaddingSalt(t *testing.T, isV6 bool) []byte {
	t.Helper()
	for i := 0; i < 3000; i++ {
		x := crypto.RandomSalt()
		dec, err := crypto.KMSDecryptCBC(x, x, isV6)
		if err != nil {
			continue
		}
		if _, err := crypto.PKCS7Unpad(dec); err != nil {
			return x
		}
	}
	t.Fatal("could not find invalid padding salt")
	return nil
}

// findShortUnpaddedSalt searches for a 16-byte ciphertext whose decryption
// unpads to fewer than 16 bytes (so handleV5V6Request hits len<16).
func findShortUnpaddedSalt(t *testing.T, isV6 bool) []byte {
	t.Helper()
	for i := 0; i < 3000; i++ {
		x := crypto.RandomSalt()
		dec, err := crypto.KMSDecryptCBC(x, x, isV6)
		if err != nil {
			continue
		}
		unpadded, err := crypto.PKCS7Unpad(dec)
		if err != nil {
			continue
		}
		if len(unpadded) < 16 {
			return x
		}
	}
	t.Fatal("could not find short-unpadded salt")
	return nil
}

// callHandler dispatches to the version-correct handler.
func callHandler(t *testing.T, ctx context.Context, config *ServerConfig, data []byte, hdr *GenericRequestHeader, isV6 bool) ([]byte, error) {
	t.Helper()
	if isV6 {
		return HandleV6Request(ctx, data, hdr, config)
	}
	return HandleV5Request(ctx, data, hdr, config)
}

func TestHandleV5V6UnpadAndShortBranches(t *testing.T) {
	ctx := context.Background()
	cfg := &ServerConfig{}

	versions := []struct {
		name  string
		major uint16
		isV6  bool
	}{
		{"v5", 5, false},
		{"v6", 6, true},
	}

	for _, v := range versions {
		// Unpad failure after successful decryption.
		bad := findInvalidPaddingSalt(t, v.isV6)
		badData := append(makeHeader(uint32(len(bad)+4), uint32(len(bad)+4), 1, v.major), bad...)
		hdr := &GenericRequestHeader{BodyLength1: uint32(len(bad) + 4), VersionMinor: 1, VersionMajor: v.major}
		if _, err := callHandler(t, ctx, cfg, badData, hdr, v.isV6); err == nil {
			t.Fatalf("%s expected unpad error", v.name)
		}

		// Unpadded data shorter than 16 bytes.
		short := findShortUnpaddedSalt(t, v.isV6)
		shortData := append(makeHeader(uint32(len(short)+4), uint32(len(short)+4), 1, v.major), short...)
		hdr2 := &GenericRequestHeader{BodyLength1: uint32(len(short) + 4), VersionMinor: 1, VersionMajor: v.major}
		if _, err := callHandler(t, ctx, cfg, shortData, hdr2, v.isV6); err == nil {
			t.Fatalf("%s expected too-short-decrypted error", v.name)
		}

		// Decrypted KMS request is too short to parse.
		shortKMS := makeV5V6WireData([]byte{0x01, 0x02, 0x03}, v.major, v.isV6)
		hdr3 := &GenericRequestHeader{BodyLength1: binary.LittleEndian.Uint32(shortKMS[0:4]), VersionMinor: 1, VersionMajor: v.major}
		if _, err := callHandler(t, ctx, cfg, shortKMS, hdr3, v.isV6); err == nil {
			t.Fatalf("%s expected KMS parse error", v.name)
		}
	}
}

func TestGenerateKMSResponseData(t *testing.T) {
	ctx := context.Background()
	cfg := &ServerConfig{}

	// Header too short.
	if _, err := GenerateKMSResponseData(ctx, []byte{1, 2, 3}, cfg); err == nil {
		t.Fatal("expected header error")
	}

	// Unknown version -> HandleUnknownRequest.
	unknown := makeHeader(100, 100, 1, 99)
	resp, err := GenerateKMSResponseData(ctx, unknown, cfg)
	if err != nil {
		t.Fatalf("unknown version error = %v", err)
	}
	if got := binary.LittleEndian.Uint32(resp[8:12]); got != 0xC004F042 {
		t.Fatalf("unknown status = 0x%x, want 0xC004F042", got)
	}

	// Version 4.
	v4req := &KMSRequest{
		VersionMajor: 4, LicenseStatus: 2, ApplicationID: RandomUUID(),
		SKUID: RandomUUID(), KMSCountedID: RandomUUID(),
		ClientMachineID: RandomUUID(), RequiredClientCount: 25, RequestTime: 1,
		MachineNameRaw: make([]byte, 128),
	}
	rb := v4req.Marshal()
	hash := crypto.V4Hash(rb)
	v4 := make([]byte, 4+4+len(rb)+16)
	binary.LittleEndian.PutUint32(v4[0:4], uint32(len(rb)+16))
	binary.LittleEndian.PutUint32(v4[4:8], uint32(len(rb)+16))
	copy(v4[8:], rb)
	copy(v4[8+len(rb):], hash[:])
	if _, err := GenerateKMSResponseData(ctx, v4, cfg); err != nil {
		t.Fatalf("v4 response error = %v", err)
	}

	// Version 5 and 6.
	for _, v := range []struct {
		major uint16
		isV6  bool
	}{{5, false}, {6, true}} {
		wire := makeV5V6WireData(validKMSBytes(t), v.major, v.isV6)
		if _, err := GenerateKMSResponseData(ctx, wire, cfg); err != nil {
			t.Fatalf("v%d response error = %v", v.major, err)
		}
	}
}

func TestHandleUnknownRequest(t *testing.T) {
	resp, err := HandleUnknownRequest()
	if err != nil {
		t.Fatalf("HandleUnknownRequest error = %v", err)
	}
	if len(resp) != 12 {
		t.Fatalf("response length = %d, want 12", len(resp))
	}
	if !bytes.Equal(make([]byte, 4), resp[0:4]) || binary.LittleEndian.Uint32(resp[8:12]) != 0xC004F042 {
		t.Fatalf("unexpected response: %x", resp)
	}
}

func TestBuildV5V6ResponseStructure(t *testing.T) {
	resp := buildV5V6Response(1, 6, make([]byte, 16), make([]byte, 32))
	if len(resp) < 12+2+2+16+32 {
		t.Fatalf("response too short: %d", len(resp))
	}
	if binary.LittleEndian.Uint16(resp[12:14]) != 1 || binary.LittleEndian.Uint16(resp[14:16]) != 6 {
		t.Fatalf("version fields wrong: %x %x", resp[12:14], resp[14:16])
	}
}
