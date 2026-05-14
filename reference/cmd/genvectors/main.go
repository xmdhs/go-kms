// genvectors emits a JSON file of byte-level KMS test vectors used by Rust's
// tests/parity.rs to verify that the Rust port produces identical outputs.
//
// Usage: go run ./cmd/genvectors path/to/vectors.json
//
// Vectors are deterministic: all "random" components are replaced with fixed
// values, so re-running the program produces byte-identical output.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"reference/crypto"
	"reference/kms"
	"reference/rpc"
)

type kv map[string]any

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: genvectors <output.json>")
		os.Exit(1)
	}
	out := os.Args[1]

	vectors := kv{
		"pkcs7_pad":     pkcs7PadCases(),
		"pkcs7_unpad":   pkcs7UnpadCases(),
		"v4_block":      v4BlockCases(),
		"v5_block":      v5BlockCases(),
		"v6_block":      v6BlockCases(),
		"v5_cbc":        v5CbcCases(),
		"v6_cbc":        v6CbcCases(),
		"v4_hash":       v4HashCases(),
		"v6_mac_key":    v6MacKeyCases(),
		"v6_hmac":       v6HmacCases(),
		"uuid_string":   uuidStringCases(),
		"uuid_parse":    uuidParseCases(),
		"filetime":      filetimeCases(),
		"utf16le":       utf16Cases(),
		"kms_request":   kmsRequestCases(),
		"kms_response":  kmsResponseCases(),
		"generic_hdr":   genericHdrCases(),
		"rpc_bind_req":  rpcBindReqCases(),
		"rpc_bind_ack":  rpcBindAckCases(),
		"rpc_request":   rpcRequestCases(),
		"rpc_response":  rpcResponseCases(),
		"handle_v4":     handleV4Cases(),
		"server_logic":  serverLogicCases(),
		"v5_envelope":   v5EnvelopeCases(),
		"v6_envelope":   v6EnvelopeCases(),
		"constants": kv{
			"msrpc_header_size":         rpc.MSRPCHeaderSize,
			"msrpc_request_header_size": rpc.MSRPCRequestHeaderSize,
			"msrpc_resp_header_size":    rpc.MSRPCRespHeaderSize,
			"ctx_item_size":             rpc.CtxItemSize,
			"ctx_item_result_size":      rpc.CtxItemResultSize,
		},
	}

	buf, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(out, append(buf, '\n'), 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("wrote", out)
}

// ---------- helpers ----------

func hx(b []byte) string { return hex.EncodeToString(b) }

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func ascending(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// ---------- PKCS7 ----------

func pkcs7PadCases() []kv {
	inputs := [][]byte{
		nil, []byte("a"), []byte("kms-test"), ascending(16), ascending(17), ascending(31), ascending(32),
	}
	cases := make([]kv, 0, len(inputs))
	for _, in := range inputs {
		cases = append(cases, kv{"input": hx(in), "out": hx(crypto.PKCS7Pad(in, 16))})
	}
	return cases
}

func pkcs7UnpadCases() []kv {
	valid := crypto.PKCS7Pad([]byte("kms-test"), 16)
	out := []kv{{"input": hx(valid), "out": hx([]byte("kms-test")), "ok": true}}
	invalids := [][]byte{
		{},
		{1, 2, 3},
		append(repeat(0x41, 15), 0x00),
		append(repeat(0x41, 15), 0x11),
		append(repeat(0x41, 14), 0x02, 0x03),
	}
	for _, in := range invalids {
		out = append(out, kv{"input": hx(in), "ok": false})
	}
	return out
}

// ---------- Block ----------

func v4BlockCases() []kv {
	inputs := [][]byte{ascending(16), repeat(0x5a, 16), mustHex("000102030405060708090a0b0c0d0e0f")}
	out := []kv{}
	for _, in := range inputs {
		enc := make([]byte, 16)
		dec := make([]byte, 16)
		crypto.AESEncryptBlockV4(enc, in)
		crypto.AESDecryptBlockV4(dec, enc)
		out = append(out, kv{"input": hx(in), "enc": hx(enc), "dec_of_enc": hx(dec)})
	}
	return out
}

func v5BlockCases() []kv {
	inputs := [][]byte{ascending(16), repeat(0x5a, 16)}
	out := []kv{}
	iv := repeat(0, 16)
	for _, in := range inputs {
		enc, _ := crypto.KMSEncryptCBC(in, iv, false)
		dec, _ := crypto.KMSDecryptCBC(enc, iv, false)
		out = append(out, kv{"input": hx(in), "enc": hx(enc), "dec_of_enc": hx(dec)})
	}
	return out
}

func v6BlockCases() []kv {
	inputs := [][]byte{ascending(16), repeat(0x5a, 16), mustHex("000102030405060708090a0b0c0d0e0f")}
	out := []kv{}
	for _, in := range inputs {
		enc := make([]byte, 16)
		dec := make([]byte, 16)
		crypto.AESEncryptBlockV6(enc, in)
		crypto.AESDecryptBlockV6(dec, enc)
		out = append(out, kv{"input": hx(in), "enc": hx(enc), "dec_of_enc": hx(dec)})
	}
	return out
}

// ---------- CBC ----------

func v5CbcCases() []kv {
	iv := mustHex("000102030405060708090a0b0c0d0e0f")
	out := []kv{}
	plains := [][]byte{
		ascending(16),
		ascending(32),
		crypto.PKCS7Pad([]byte("baseline-vector-data"), 16),
		crypto.PKCS7Pad(nil, 16),
		crypto.PKCS7Pad([]byte("kms-test"), 16),
	}
	for _, p := range plains {
		c, _ := crypto.KMSEncryptCBC(p, iv, false)
		d, _ := crypto.KMSDecryptCBC(c, iv, false)
		out = append(out, kv{"iv": hx(iv), "plain": hx(p), "cipher": hx(c), "decrypted": hx(d)})
	}
	return out
}

func v6CbcCases() []kv {
	iv := mustHex("000102030405060708090a0b0c0d0e0f")
	out := []kv{}
	plains := [][]byte{
		ascending(16),
		ascending(32),
		crypto.PKCS7Pad([]byte("baseline-vector-data"), 16),
		crypto.PKCS7Pad([]byte("kms-test"), 16),
	}
	for _, p := range plains {
		c, _ := crypto.KMSEncryptCBC(p, iv, true)
		d, _ := crypto.KMSDecryptCBC(c, iv, true)
		out = append(out, kv{"iv": hx(iv), "plain": hx(p), "cipher": hx(c), "decrypted": hx(d)})
	}
	return out
}

// ---------- V4 Hash ----------

func v4HashCases() []kv {
	inputs := [][]byte{
		nil,
		[]byte("fixed-v4-hash-input"),
		[]byte("baseline-v4-hash-input"),
		ascending(64),
		ascending(127),
	}
	out := []kv{}
	for _, in := range inputs {
		h := crypto.V4Hash(in)
		out = append(out, kv{"input": hx(in), "hash": hx(h[:])})
	}
	return out
}

// ---------- V6 MAC ----------

func v6MacKeyCases() []kv {
	inputs := []uint64{0, 1, 42, 13322345678901234567, 0xFFFFFFFFFFFFFFFF, 116444736000000000}
	out := []kv{}
	for _, t := range inputs {
		k := crypto.V6MACKey(t)
		out = append(out, kv{"request_time": fmt.Sprintf("%d", t), "key": hx(k[:])})
	}
	return out
}

func v6HmacCases() []kv {
	out := []kv{}
	pairs := []struct {
		key  []byte
		data []byte
	}{
		{[]byte("0123456789abcdef"), []byte("baseline-v6-hmac-input")},
		{mustHex("8012fac9c77fb0f401b438c8b96f4e1d"), []byte("baseline-v6-hmac-input")},
		{repeat(0xAA, 16), nil},
		{repeat(0x11, 16), ascending(64)},
	}
	for _, p := range pairs {
		h := crypto.V6HMAC(p.key, p.data)
		out = append(out, kv{"key": hx(p.key), "data": hx(p.data), "hmac": hx(h[:])})
	}
	return out
}

// ---------- UUID ----------

func uuidStringCases() []kv {
	out := []kv{}
	uuids := []string{
		"00000000000000000000000000000000",
		"0102030405060708090a0b0c0d0e0f10",
		"112233445566778899aabbccddeeff00",
		"00000000-0000-0000-0000-000000000000",
		"01234567-89ab-cdef-0123-456789abcdef",
	}
	for _, s := range uuids {
		u, err := kms.UUIDFromString(s)
		if err != nil {
			panic(err)
		}
		out = append(out, kv{"input": s, "bytes_le": hx(u[:]), "string": u.String()})
	}
	return out
}

func uuidParseCases() []kv {
	out := []kv{}
	// Examples: canonical UUID strings -> their bytes_le encoding.
	uuids := []string{
		"00000000-0000-0000-0000-000000000000",
		"01234567-89ab-cdef-0123-456789abcdef",
		"cfd8ff08-c0d7-452b-9f60-ef5c70c32094",
		"73111121-5571-4dd9-98a7-44d8780b9385",
		"d450596f-894d-49e0-966a-fd39ed4c4c64",
	}
	for _, s := range uuids {
		u, err := kms.UUIDFromString(s)
		if err != nil {
			panic(err)
		}
		out = append(out, kv{"input": s, "bytes_le": hx(u[:])})
	}
	return out
}

// ---------- FileTime ----------

func filetimeCases() []kv {
	out := []kv{}
	values := []int64{kms.EpochAsFiletime, kms.EpochAsFiletime + 1, kms.EpochAsFiletime + kms.HundredsOfNanoseconds,
		133592832000000000, 132580512000000000, 116444800000000000}
	for _, ft := range values {
		t := kms.FileTimeToTime(ft)
		secs := t.Unix()
		nanos := uint32(t.Nanosecond())
		back := kms.TimeToFileTime(t)
		out = append(out, kv{
			"filetime": fmt.Sprintf("%d", ft),
			"secs":     fmt.Sprintf("%d", secs),
			"nanos":    nanos,
			"roundtrip": fmt.Sprintf("%d", back),
		})
	}
	return out
}

// ---------- UTF-16LE ----------

func utf16Cases() []kv {
	out := []kv{}
	for _, s := range []string{"", "A", "hello", "Windows10", "测试-σ-π", "ABC123-_-XYZ"} {
		enc := kms.EncodeUTF16LE(s)
		dec := kms.DecodeUTF16LE(append(enc, 0, 0))
		out = append(out, kv{"input": s, "utf16le": hx(enc), "decoded": dec})
	}
	return out
}

// ---------- KMSRequest marshal/parse ----------

func sampleRequest() *kms.KMSRequest {
	return &kms.KMSRequest{
		VersionMinor:            0,
		VersionMajor:            6,
		IsClientVM:              1,
		LicenseStatus:           2,
		GraceTime:               43200 * 2,
		ApplicationID:           kms.MustUUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
		SKUID:                   kms.MustUUID("81671aaf-79d1-4eb1-b004-8cbbe173afea"),
		KMSCountedID:            kms.MustUUID("cb8fc780-2c05-495a-9710-85afffc904d7"),
		ClientMachineID:         kms.MustUUID("01234567-89ab-cdef-0123-456789abcdef"),
		RequiredClientCount:     25,
		RequestTime:             132580512000000000,
		PreviousClientMachineID: kms.UUID{},
		MachineNameRaw:          padMachine("HELLOWORLD"),
	}
}

func padMachine(s string) []byte {
	out := make([]byte, 128)
	enc := kms.EncodeUTF16LE(s)
	copy(out, enc)
	return out
}

func kmsRequestCases() []kv {
	out := []kv{}
	r := sampleRequest()
	w := r.Marshal()
	parsed, err := kms.ParseKMSRequest(w)
	if err != nil {
		panic(err)
	}
	rt := parsed.Marshal()
	out = append(out, kv{"wire": hx(w), "roundtrip": hx(rt)})
	return out
}

func kmsResponseCases() []kv {
	out := []kv{}
	r := &kms.KMSResponse{
		VersionMinor:         0,
		VersionMajor:         6,
		KMSEpid:              kms.EncodeUTF16LE("03612-00206-471-111111-03-1033-19041.0000-1232024"),
		ClientMachineID:      kms.MustUUID("01234567-89ab-cdef-0123-456789abcdef"),
		ResponseTime:         132580512000000000,
		CurrentClientCount:   50,
		VLActivationInterval: 120,
		VLRenewalInterval:    10080,
	}
	w := r.Marshal()
	parsed, err := kms.ParseKMSResponse(w)
	if err != nil {
		panic(err)
	}
	rt := parsed.Marshal()
	out = append(out, kv{"wire": hx(w), "roundtrip": hx(rt), "epid_len": parsed.EPIDLen})
	return out
}

// ---------- GenericRequestHeader ----------

func genericHdrCases() []kv {
	out := []kv{}
	samples := []struct {
		bl1, bl2 uint32
		minor    uint16
		major    uint16
	}{
		{200, 200, 0, 4},
		{216, 216, 0, 5},
		{232, 232, 0, 6},
	}
	for _, s := range samples {
		data := make([]byte, 12)
		binary.LittleEndian.PutUint32(data[0:], s.bl1)
		binary.LittleEndian.PutUint32(data[4:], s.bl2)
		binary.LittleEndian.PutUint16(data[8:], s.minor)
		binary.LittleEndian.PutUint16(data[10:], s.major)
		out = append(out, kv{
			"input":        hx(data),
			"body_length1": s.bl1,
			"body_length2": s.bl2,
			"version_minor": s.minor,
			"version_major": s.major,
		})
	}
	return out
}

// ---------- RPC ----------

func rpcBindReqCases() []kv {
	out := []kv{}
	for _, cid := range []uint32{1, 2, 0x12345678} {
		b := rpc.BuildBindRequest(cid)
		out = append(out, kv{"call_id": cid, "bytes": hx(b)})
	}
	return out
}

func rpcBindAckCases() []kv {
	out := []kv{}
	req := rpc.BuildBindRequest(1)
	for _, port := range []int{1688, 12345} {
		b, err := rpc.BuildBindAckResponse(req, port, 1)
		if err != nil {
			panic(err)
		}
		out = append(out, kv{"request": hx(req), "port": port, "call_id": 1, "bytes": hx(b)})
	}
	return out
}

func rpcRequestCases() []kv {
	out := []kv{}
	for _, n := range []int{16, 100, 256} {
		data := ascending(n)
		b := rpc.BuildRPCRequest(data, 2)
		out = append(out, kv{"kms_data": hx(data), "call_id": 2, "bytes": hx(b)})
	}
	return out
}

func rpcResponseCases() []kv {
	out := []kv{}
	for _, n := range []int{16, 100, 256} {
		data := ascending(n)
		req := rpc.BuildRPCRequest(data, 7)
		header, err := rpc.ParseMSRPCRequestHeader(req)
		if err != nil {
			panic(err)
		}
		pdu := ascending(n / 2)
		resp := rpc.BuildMSRPCResponse(header, pdu)
		out = append(out, kv{"req_header_bytes": hx(req[:rpc.MSRPCRequestHeaderSize]), "pdu": hx(pdu), "bytes": hx(resp)})
	}
	return out
}

// ---------- handle_v4 end-to-end (deterministic) ----------

func handleV4Cases() []kv {
	out := []kv{}
	cfg := kms.DefaultServerConfig()
	cfg.EPID = "03612-00206-471-111111-03-1033-19041.0000-1232024"

	r := sampleRequest()
	r.VersionMinor = 0
	r.VersionMajor = 4
	body := r.Marshal()
	// V4 wraps as: bodyLen(le) + bodyLen(le) + body + V4Hash(body) [+ pad]
	// But HandleV4Request treats `data` as bodyLength1 + bodyLength2 + (request + hash + padding).
	// We use bodyLength = len(body) + 16.
	bodyLen := uint32(len(body) + 16)
	req := make([]byte, 8+len(body)+16)
	binary.LittleEndian.PutUint32(req[0:4], bodyLen)
	binary.LittleEndian.PutUint32(req[4:8], bodyLen)
	copy(req[8:], body)
	h := crypto.V4Hash(body)
	copy(req[8+len(body):], h[:])

	resp, err := kms.HandleV4Request(context.Background(), req, cfg)
	if err != nil {
		panic(err)
	}
	out = append(out, kv{"request": hx(req), "response": hx(resp)})
	return out
}

// ---------- server_logic ----------

func serverLogicCases() []kv {
	out := []kv{}
	cfg := kms.DefaultServerConfig()
	cfg.EPID = "03612-00206-471-111111-03-1033-19041.0000-1232024"
	cfg.Activation = 120
	cfg.Renewal = 10080
	req := sampleRequest()
	resp := kms.ServerLogic(context.Background(), req, cfg)
	out = append(out, kv{
		"request":            hx(req.Marshal()),
		"response_wire":      hx(resp.Marshal()),
		"epid_utf16le":       hx(resp.KMSEpid),
		"current_client_count": resp.CurrentClientCount,
	})
	// With explicit ClientCount.
	for _, cc := range []int{0, 10, 25, 40, 50, 100} {
		cfg2 := kms.DefaultServerConfig()
		cfg2.EPID = "fixed-epid"
		ccc := cc
		cfg2.ClientCount = &ccc
		resp := kms.ServerLogic(context.Background(), req, cfg2)
		out = append(out, kv{
			"client_count":         cc,
			"current_client_count": resp.CurrentClientCount,
		})
	}
	return out
}

// ---------- V5/V6 envelope (deterministic salts) ----------
//
// Reproduces the byte layout of handleV5V6Request with `salt`, `decryptedSalt`,
// and `randomSalt` all set to fixed test values.  No reliance on crypto/rand.

func v5EnvelopeCases() []kv {
	return v5v6EnvelopeCases(false)
}

func v6EnvelopeCases() []kv {
	return v5v6EnvelopeCases(true)
}

func v5v6EnvelopeCases(isV6 bool) []kv {
	out := []kv{}

	cfg := kms.DefaultServerConfig()
	cfg.EPID = "03612-00206-471-111111-03-1033-19041.0000-1232024"
	req := sampleRequest()
	if isV6 {
		req.VersionMajor = 6
	} else {
		req.VersionMajor = 5
	}

	// Fixed deterministic salts.
	salt := repeat(0x11, 16)
	decryptedSalt := repeat(0x22, 16)
	randomSalt := repeat(0x33, 16)
	saltS := repeat(0x44, 16)

	resp := kms.ServerLogic(context.Background(), req, cfg)
	respBytes := resp.Marshal()
	hashResult := sha256.Sum256(randomSalt)

	versionMinor := req.VersionMinor
	versionMajor := req.VersionMajor

	var encrypted []byte
	var iv []byte
	if isV6 {
		// Build messageBytes = response + randomStuff(16) + hash(32) + hwid + xorSalts(16)
		msg := make([]byte, 0, len(respBytes)+16+32+len(cfg.HWID)+16+16)
		msg = append(msg, respBytes...)
		for i := 0; i < 16; i++ {
			msg = append(msg, salt[i]^decryptedSalt[i]^randomSalt[i])
		}
		msg = append(msg, hashResult[:]...)
		msg = append(msg, cfg.HWID...)
		for i := 0; i < 16; i++ {
			msg = append(msg, salt[i]^decryptedSalt[i])
		}
		// Compute dsaltS = decrypt(saltS, saltS, true)
		dsaltS, err := crypto.KMSDecryptCBC(saltS, saltS, true)
		if err != nil {
			panic(err)
		}
		hmacKey := crypto.V6MACKey(req.RequestTime)
		var xorSalts [16]byte
		for i := 0; i < 16; i++ {
			xorSalts[i] = saltS[i] ^ dsaltS[i]
		}
		digest := crypto.V6HMACParts(hmacKey[:], xorSalts[:], msg)
		msg = append(msg, digest[16:]...)
		padded := crypto.PKCS7Pad(msg, 16)
		enc, err := crypto.KMSEncryptCBC(padded, saltS, true)
		if err != nil {
			panic(err)
		}
		encrypted = enc
		iv = saltS
	} else {
		rd := make([]byte, 0, len(respBytes)+16+32)
		rd = append(rd, respBytes...)
		for i := 0; i < 16; i++ {
			rd = append(rd, decryptedSalt[i]^salt[i]^randomSalt[i])
		}
		rd = append(rd, hashResult[:]...)
		padded := crypto.PKCS7Pad(rd, 16)
		enc, err := crypto.KMSEncryptCBC(padded, salt, false)
		if err != nil {
			panic(err)
		}
		encrypted = enc
		iv = salt
	}

	// Build final wire response identical to buildV5V6Response.
	bodyLength := uint32(2 + 2 + len(iv) + len(encrypted))
	padding := make([]byte, kms.GetPadding(int(bodyLength)))
	full := make([]byte, 0, 4+4+4+2+2+len(iv)+len(encrypted)+len(padding))
	full = append(full, le32(bodyLength)...)
	full = append(full, be32(0x00000200)...)
	full = append(full, le32(bodyLength)...)
	full = append(full, le16(versionMinor)...)
	full = append(full, le16(versionMajor)...)
	full = append(full, iv...)
	full = append(full, encrypted...)
	full = append(full, padding...)

	out = append(out, kv{
		"request_bytes":  hx(req.Marshal()),
		"salt":           hx(salt),
		"decrypted_salt": hx(decryptedSalt),
		"random_salt":    hx(randomSalt),
		"salt_s":         hx(saltS),
		"epid_utf16le":   hx(cfg.EpidBytesForTest()),
		"hwid":           hx(cfg.HWID),
		"response_bytes": hx(respBytes),
		"encrypted":      hx(encrypted),
		"full":           hx(full),
	})
	return out
}

func le16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
