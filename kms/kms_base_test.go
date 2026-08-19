package kms

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestUUIDString(t *testing.T) {
	cases := []struct {
		in   UUID
		want string
	}{
		{UUID{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}, "78563412-bc9a-f0de-1122-334455667788"},
		{UUID{}, "00000000-0000-0000-0000-000000000000"},
	}
	for _, c := range cases {
		if got := c.in.String(); got != c.want {
			t.Errorf("UUID.String() = %q, want %q", got, c.want)
		}
	}
}

func TestHexVal(t *testing.T) {
	for c := byte('0'); c <= '9'; c++ {
		if got := hexVal(c); got != c-'0' {
			t.Errorf("hexVal(%q) = %d", c, got)
		}
	}
	for c := byte('a'); c <= 'f'; c++ {
		if got := hexVal(c); got != c-'a'+10 {
			t.Errorf("hexVal(%q) = %d", c, got)
		}
	}
	for c := byte('A'); c <= 'F'; c++ {
		if got := hexVal(c); got != c-'A'+10 {
			t.Errorf("hexVal(%q) = %d", c, got)
		}
	}
	if got := hexVal('z'); got != 255 {
		t.Errorf("hexVal('z') = %d, want 255", got)
	}
	if got := hexVal('-'); got != 255 {
		t.Errorf("hexVal('-') = %d, want 255", got)
	}
}

func TestUUIDFromStringRoundTrip(t *testing.T) {
	s := "78563412-bc9a-f0de-1122-334455667788"
	u, err := UUIDFromString(s)
	if err != nil {
		t.Fatalf("UUIDFromString(%q) error = %v", s, err)
	}
	if u.String() != s {
		t.Fatalf("round trip = %q, want %q", u.String(), s)
	}

	// 32 hex chars, no dashes.
	u32, err := UUIDFromString("78563412bc9af0de1122334455667788")
	if err != nil {
		t.Fatalf("UUIDFromString(32) error = %v", err)
	}
	if u32.String() != s {
		t.Fatalf("32-char round trip = %q, want %q", u32.String(), s)
	}
}

func TestUUIDFromStringErrors(t *testing.T) {
	bad := []string{
		"short",
		strings.Repeat("a", 35),                // wrong length
		strings.Repeat("a", 37),                // wrong length
		"zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", // invalid hex chars
		"78563412-bc9a-f0de-1122-33445566778z", // invalid trailing char
		strings.Repeat("a", 34) + "-0",         // hits the j >= 16 guard
		strings.Repeat("-", 35) + "0",          // hits the i+1 >= len branch
		strings.Repeat("-", 36),                // all dashes (j != 16)
	}
	for _, s := range bad {
		if _, err := UUIDFromString(s); err == nil {
			t.Errorf("UUIDFromString(%q) expected error, got nil", s)
		}
	}
}

func TestMustUUIDPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustUUID(bad) expected panic")
		}
	}()
	MustUUID("not-a-uuid")
}

func TestMustUUIDValid(t *testing.T) {
	u := MustUUID("78563412-bc9a-f0de-1122-334455667788")
	if u.String() != "78563412-bc9a-f0de-1122-334455667788" {
		t.Fatalf("MustUUID valid = %q", u.String())
	}
}

func TestRandomUUIDLength(t *testing.T) {
	u := RandomUUID()
	if len(u) != 16 {
		t.Fatalf("RandomUUID() length = %d, want 16", len(u))
	}
}

func buildValidRequestData() []byte {
	req := &KMSRequest{
		VersionMinor:        1,
		VersionMajor:        6,
		IsClientVM:          0,
		LicenseStatus:       2,
		GraceTime:           100,
		ApplicationID:       RandomUUID(),
		SKUID:               RandomUUID(),
		KMSCountedID:        RandomUUID(),
		ClientMachineID:     RandomUUID(),
		RequiredClientCount: 25,
		RequestTime:         1234567890,
		MachineNameRaw:      make([]byte, 128),
	}
	return req.Marshal()
}

func TestParseKMSRequest(t *testing.T) {
	data := buildValidRequestData()
	r, err := ParseKMSRequest(data)
	if err != nil {
		t.Fatalf("ParseKMSRequest(valid) error = %v", err)
	}
	if r.VersionMajor != 6 || r.RequiredClientCount != 25 {
		t.Fatalf("unexpected fields: %+v", r)
	}
	if len(r.MachineNameRaw) != 128 {
		t.Fatalf("MachineNameRaw len = %d, want 128", len(r.MachineNameRaw))
	}

	if _, err := ParseKMSRequest(data[:100]); err == nil {
		t.Fatal("expected error for short data")
	}

	// Data longer than the fixed 108-byte body only sets MachineNameRaw.
	extra := append(data, 0x01, 0x02)
	r2, err := ParseKMSRequest(extra)
	if err != nil {
		t.Fatalf("ParseKMSRequest(extra) error = %v", err)
	}
	if len(r2.MachineNameRaw) != 130 {
		t.Fatalf("extra MachineNameRaw len = %d, want 130", len(r2.MachineNameRaw))
	}
}

func TestKMSRequestMarshalRoundTrip(t *testing.T) {
	req := &KMSRequest{
		VersionMinor: 2, VersionMajor: 5, IsClientVM: 1, LicenseStatus: 3,
		GraceTime: 43200, ApplicationID: RandomUUID(), SKUID: RandomUUID(),
		KMSCountedID: RandomUUID(), ClientMachineID: RandomUUID(),
		RequiredClientCount: 50, RequestTime: 999, MachineNameRaw: []byte{0x41, 0x00, 0x42, 0x00},
	}
	out := req.Marshal()
	parsed, err := ParseKMSRequest(out)
	if err != nil {
		t.Fatalf("parse round trip error = %v", err)
	}
	if parsed.RequestTime != 999 || parsed.RequiredClientCount != 50 {
		t.Fatalf("round trip fields mismatch: %+v", parsed)
	}
}

func TestKMSResponseMarshalParse(t *testing.T) {
	resp := &KMSResponse{
		VersionMinor: 1, VersionMajor: 6,
		KMSEpid:              EncodeUTF16LE("test-epid"),
		ClientMachineID:      RandomUUID(),
		ResponseTime:         555,
		CurrentClientCount:   26,
		VLActivationInterval: 120,
		VLRenewalInterval:    10080,
	}
	data := resp.Marshal()
	// EPIDLen includes the null terminator.
	epidLen := binary.LittleEndian.Uint32(data[4:8])
	wantEpidLen := uint32(len(resp.KMSEpid) + 2)
	if epidLen != wantEpidLen {
		t.Fatalf("EPIDLen = %d, want %d", epidLen, wantEpidLen)
	}

	parsed, err := ParseKMSResponse(data)
	if err != nil {
		t.Fatalf("ParseKMSResponse error = %v", err)
	}
	if parsed.VLRenewalInterval != 10080 || parsed.ResponseTime != 555 {
		t.Fatalf("parsed fields mismatch: %+v", parsed)
	}
}

func TestParseKMSResponseErrors(t *testing.T) {
	if _, err := ParseKMSResponse([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for too-short response")
	}

	// EPIDLen larger than remaining data.
	short := make([]byte, 12)
	binary.LittleEndian.PutUint32(short[4:8], 500)
	if _, err := ParseKMSResponse(short); err == nil {
		t.Fatal("expected EPID length mismatch error")
	}

	// Fixed tail fields truncated.
	body := make([]byte, 12+4)
	binary.LittleEndian.PutUint32(body[4:8], 4)
	if _, err := ParseKMSResponse(body); err == nil {
		t.Fatal("expected truncated fixed-fields error")
	}
}

func TestParseGenericRequestHeader(t *testing.T) {
	data := make([]byte, 12)
	if _, err := ParseGenericRequestHeader(data[:5]); err == nil {
		t.Fatal("expected short header error")
	}
	h, err := ParseGenericRequestHeader(data)
	if err != nil {
		t.Fatalf("ParseGenericRequestHeader error = %v", err)
	}
	if h.VersionMajor != 0 || h.BodyLength1 != 0 {
		t.Fatalf("unexpected header: %+v", h)
	}
}

func TestLicenseStates(t *testing.T) {
	for i := uint32(0); i <= 6; i++ {
		if LicenseStates[i] == "" {
			t.Fatalf("missing license state for %d", i)
		}
	}
}

func TestDefaultServerConfig(t *testing.T) {
	c := DefaultServerConfig()
	if c.Port != 1688 || c.IP != "0.0.0.0" || len(c.HWID) != 8 {
		t.Fatalf("unexpected default config: %+v", c)
	}
}

func TestGetPadding(t *testing.T) {
	// padding = 4 + ((4 - len%4) % 4), so len+padding ≡ 0 (mod 4) plus 4 extra.
	want := map[int]int{0: 4, 1: 7, 2: 6, 3: 5, 4: 4, 5: 7}
	for in, w := range want {
		if got := GetPadding(in); got != w {
			t.Errorf("GetPadding(%d) = %d, want %d", in, got, w)
		}
	}
}

func TestServerLogicClientCountBranches(t *testing.T) {
	ctx := context.Background()
	mkReq := func() *KMSRequest {
		r, _ := ParseKMSRequest(buildValidRequestData())
		r.RequiredClientCount = 25
		return r
	}

	// cc = 0  -> falls through all branches, count stays 0.
	zero := 0
	resp := ServerLogic(ctx, mkReq(), &ServerConfig{ClientCount: &zero})
	if resp.CurrentClientCount != 0 {
		t.Fatalf("cc=0 count = %d, want 0", resp.CurrentClientCount)
	}

	// cc < minClients -> minClients + 1
	small := 1
	resp = ServerLogic(ctx, mkReq(), &ServerConfig{ClientCount: &small})
	if resp.CurrentClientCount != 26 {
		t.Fatalf("cc<min count = %d, want 26", resp.CurrentClientCount)
	}

	// minClients <= cc < required -> cc
	mid := 30
	resp = ServerLogic(ctx, mkReq(), &ServerConfig{ClientCount: &mid})
	if resp.CurrentClientCount != 30 {
		t.Fatalf("mid count = %d, want 30", resp.CurrentClientCount)
	}

	// cc >= required -> required (50)
	high := 60
	resp = ServerLogic(ctx, mkReq(), &ServerConfig{ClientCount: &high})
	if resp.CurrentClientCount != 50 {
		t.Fatalf("high count = %d, want 50", resp.CurrentClientCount)
	}

	// ClientCount nil -> requiredClients
	resp = ServerLogic(ctx, mkReq(), &ServerConfig{})
	if resp.CurrentClientCount != 50 {
		t.Fatalf("nil count = %d, want 50", resp.CurrentClientCount)
	}
}

func TestServerLogicEPID(t *testing.T) {
	ctx := context.Background()
	req, _ := ParseKMSRequest(buildValidRequestData())

	// Empty EPID -> auto-generated random UUID.
	c1 := &ServerConfig{}
	resp1 := ServerLogic(ctx, req, c1)
	if len(resp1.KMSEpid) == 0 {
		t.Fatal("expected auto-generated EPID")
	}
	// Once cached: same bytes on second call.
	resp1b := ServerLogic(ctx, req, c1)
	if string(resp1b.KMSEpid) != string(resp1.KMSEpid) {
		t.Fatal("epidOnce did not cache")
	}

	// Explicit EPID.
	c2 := &ServerConfig{EPID: "explicit-epid"}
	resp2 := ServerLogic(ctx, req, c2)
	if got := DecodeUTF16LE(resp2.KMSEpid); got != "explicit-epid" {
		t.Fatalf("explicit EPID = %q, want explicit-epid", got)
	}
}

func TestEncodeDecodeUTF16LE(t *testing.T) {
	s := "hello-世界"
	enc := EncodeUTF16LE(s)
	if got := DecodeUTF16LE(enc); got != s {
		t.Fatalf("round trip = %q, want %q", got, s)
	}

	// Odd-length input is truncated by DecodeUTF16LE.
	odd := []byte{0x41, 0x00, 0x42}
	if got := DecodeUTF16LE(odd); got != "A" {
		t.Fatalf("odd decode = %q, want A", got)
	}

	// Trailing nulls are trimmed.
	withNull := []byte{0x41, 0x00, 0x42, 0x00, 0x00, 0x00}
	if got := DecodeUTF16LE(withNull); got != "AB" {
		t.Fatalf("null trim decode = %q, want AB", got)
	}
}

func TestFileTimeRoundTrip(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 30, 45, 123400000, time.UTC)
	ft := TimeToFileTime(now)
	back := FileTimeToTime(ft)
	if !back.Equal(now.Truncate(time.Microsecond)) {
		t.Fatalf("filetime round trip = %v, want %v", back, now)
	}

	// Specific known value.
	if FileTimeToTime(116444736000000000).Unix() != 0 {
		t.Fatal("epoch filetime should map to unix 0")
	}
}
