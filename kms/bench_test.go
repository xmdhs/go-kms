package kms

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/xmdhs/go-kms/crypto"
)

func BenchmarkEncodeUTF16LE(b *testing.B) {
	s := "TEST-MACHINE-001"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeUTF16LE(s)
	}
}

func BenchmarkDecodeUTF16LE(b *testing.B) {
	s := "TEST-MACHINE-001"
	data := EncodeUTF16LE(s)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeUTF16LE(data)
	}
}

func BenchmarkUUIDString(b *testing.B) {
	uuid := MustUUID("55c92734-d682-4d71-983e-d6ec3f16059f")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uuid.String()
	}
}

func BenchmarkUUIDFromString(b *testing.B) {
	s := "55c92734-d682-4d71-983e-d6ec3f16059f"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		UUIDFromString(s)
	}
}

func BenchmarkRandomUUID(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RandomUUID()
	}
}

func BenchmarkParseKMSRequest(b *testing.B) {
	// Create a valid KMS request
	req := &KMSRequest{
		VersionMinor:        1,
		VersionMajor:        6,
		IsClientVM:          0,
		LicenseStatus:       2,
		GraceTime:           43200 * 2,
		ApplicationID:       RandomUUID(),
		SKUID:               RandomUUID(),
		KMSCountedID:        RandomUUID(),
		ClientMachineID:     RandomUUID(),
		RequiredClientCount: 25,
		RequestTime:         uint64(TimeToFileTime(time.Now())),
		MachineNameRaw:      make([]byte, 128),
	}
	data := req.Marshal()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseKMSRequest(data)
	}
}

func BenchmarkKMSRequestMarshal(b *testing.B) {
	req := &KMSRequest{
		VersionMinor:        1,
		VersionMajor:        6,
		IsClientVM:          0,
		LicenseStatus:       2,
		GraceTime:           43200 * 2,
		ApplicationID:       RandomUUID(),
		SKUID:               RandomUUID(),
		KMSCountedID:        RandomUUID(),
		ClientMachineID:     RandomUUID(),
		RequiredClientCount: 25,
		RequestTime:         uint64(TimeToFileTime(time.Now())),
		MachineNameRaw:      make([]byte, 128),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Marshal()
	}
}

func BenchmarkKMSResponseMarshal(b *testing.B) {
	resp := &KMSResponse{
		VersionMinor:         1,
		VersionMajor:         6,
		KMSEpid:              EncodeUTF16LE("03612-00206-000-000000-03-1033-17763.0000-0012024"),
		ClientMachineID:      RandomUUID(),
		ResponseTime:         uint64(TimeToFileTime(time.Now())),
		CurrentClientCount:   50,
		VLActivationInterval: 120,
		VLRenewalInterval:    10080,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Marshal()
	}
}

func BenchmarkParseKMSResponse(b *testing.B) {
	resp := &KMSResponse{
		VersionMinor:         1,
		VersionMajor:         6,
		KMSEpid:              EncodeUTF16LE("03612-00206-000-000000-03-1033-17763.0000-0012024"),
		ClientMachineID:      RandomUUID(),
		ResponseTime:         uint64(TimeToFileTime(time.Now())),
		CurrentClientCount:   50,
		VLActivationInterval: 120,
		VLRenewalInterval:    10080,
	}
	data := resp.Marshal()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseKMSResponse(data)
	}
}

func BenchmarkServerLogic(b *testing.B) {
	req := &KMSRequest{
		VersionMinor:        1,
		VersionMajor:        6,
		IsClientVM:          0,
		LicenseStatus:       2,
		GraceTime:           43200 * 2,
		ApplicationID:       RandomUUID(),
		SKUID:               RandomUUID(),
		KMSCountedID:        MustUUID("cb8fc780-2c05-495a-9710-85afffc904d7"),
		ClientMachineID:     RandomUUID(),
		RequiredClientCount: 25,
		RequestTime:         uint64(TimeToFileTime(time.Now())),
		MachineNameRaw:      make([]byte, 128),
	}
	config := DefaultServerConfig()

	for b.Loop() {
		ServerLogic(context.Background(), req, config)
	}
}

func BenchmarkFileTimeToTime(b *testing.B) {
	ft := TimeToFileTime(time.Now())

	for b.Loop() {
		FileTimeToTime(ft)
	}
}

func BenchmarkTimeToFileTime(b *testing.B) {
	t := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		TimeToFileTime(t)
	}
}

// Benchmark for GetPadding
func BenchmarkGetPadding(b *testing.B) {
	sizes := []int{100, 256, 384, 512, 1024}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range sizes {
			GetPadding(s)
		}
	}
}

// Combined benchmark for full V6 request/response cycle
func BenchmarkV6Cycle(b *testing.B) {
	// Setup
	req := &KMSRequest{
		VersionMinor:        1,
		VersionMajor:        6,
		IsClientVM:          0,
		LicenseStatus:       2,
		GraceTime:           43200 * 2,
		ApplicationID:       RandomUUID(),
		SKUID:               RandomUUID(),
		KMSCountedID:        MustUUID("cb8fc780-2c05-495a-9710-85afffc904d7"),
		ClientMachineID:     RandomUUID(),
		RequiredClientCount: 25,
		RequestTime:         uint64(TimeToFileTime(time.Now())),
		MachineNameRaw:      make([]byte, 128),
	}
	config := DefaultServerConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Marshal request
		_ = req.Marshal()
		// Process through ServerLogic
		resp := ServerLogic(context.Background(), req, config)
		// Marshal response
		_ = resp.Marshal()
	}
}

// Benchmark for MachineName String conversion
func BenchmarkMachineName_String(b *testing.B) {
	machineName := MachineName{MachineNameRaw: EncodeUTF16LE("TEST-MACHINE-001")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = machineName.String()
	}
}

// Benchmark for ParseGenericRequestHeader
func BenchmarkParseGenericRequestHeader(b *testing.B) {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], 260)
	binary.LittleEndian.PutUint32(data[4:8], 260)
	binary.LittleEndian.PutUint16(data[8:10], 0)
	binary.LittleEndian.PutUint16(data[10:12], 6)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseGenericRequestHeader(data)
	}
}

// Full end-to-end server benchmark with realistic scenarios
func BenchmarkFullServerFlow_V4(b *testing.B) {
	config := DefaultServerConfig()

	// Pre-build request to avoid setup overhead
	kmsReq := &KMSRequest{
		VersionMinor:        1,
		VersionMajor:        4,
		IsClientVM:          0,
		LicenseStatus:       2,
		GraceTime:           43200 * 2,
		ApplicationID:       MustUUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
		SKUID:               MustUUID("ae2ee509-1b34-41c0-acb7-6d4650168915"),
		KMSCountedID:        MustUUID("212a64dc-43b1-4d3d-a30c-2fc69d2095c6"),
		ClientMachineID:     RandomUUID(),
		RequiredClientCount: 25,
		RequestTime:         uint64(TimeToFileTime(time.Now())),
		MachineNameRaw:      make([]byte, 128),
	}
	kmsData := kmsReq.Marshal()
	bodyLength := uint32(len(kmsData) + 16) // + hash
	padding := make([]byte, GetPadding(int(bodyLength)))

	packet := make([]byte, 4+4+len(kmsData)+16+len(padding))
	offset := 0
	binary.LittleEndian.PutUint32(packet[offset:], bodyLength)
	offset += 4
	binary.LittleEndian.PutUint32(packet[offset:], bodyLength)
	offset += 4
	copy(packet[offset:], kmsData)
	offset += len(kmsData)
	copy(packet[offset:], make([]byte, 16)) // fake hash

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HandleV4Request(ctx, packet, config)
	}
}

func BenchmarkFullServerFlow_V5(b *testing.B) {
	config := DefaultServerConfig()

	kmsReq := &KMSRequest{
		VersionMinor:        1,
		VersionMajor:        5,
		IsClientVM:          0,
		LicenseStatus:       2,
		GraceTime:           43200 * 2,
		ApplicationID:       MustUUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
		SKUID:               MustUUID("458e1bec-837a-45f6-b9d5-925ed5d299de"),
		KMSCountedID:        MustUUID("3c40b358-5948-45af-923b-53d21fcc7e79"),
		ClientMachineID:     RandomUUID(),
		RequiredClientCount: 25,
		RequestTime:         uint64(TimeToFileTime(time.Now())),
		MachineNameRaw:      make([]byte, 128),
	}
	kmsData := kmsReq.Marshal()

	salt := make([]byte, 16)
	plaintext := append(salt, kmsData...)
	padded := crypto.PKCS7Pad(plaintext, 16)
	encrypted, _ := crypto.KMSDecryptCBC(padded, salt, false)

	bodyLength := uint32(4 + len(encrypted))
	padding := make([]byte, GetPadding(int(bodyLength)))

	packet := make([]byte, 4+4+2+2+len(encrypted)+len(padding))
	offset := 0
	binary.LittleEndian.PutUint32(packet[offset:], bodyLength)
	offset += 4
	binary.LittleEndian.PutUint32(packet[offset:], bodyLength)
	offset += 4
	binary.LittleEndian.PutUint16(packet[offset:], 1)
	offset += 2
	binary.LittleEndian.PutUint16(packet[offset:], 5)
	offset += 2
	copy(packet[offset:], encrypted)

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HandleV5Request(ctx, packet, config)
	}
}

func BenchmarkFullServerFlow_V6(b *testing.B) {
	config := DefaultServerConfig()

	kmsReq := &KMSRequest{
		VersionMinor:        1,
		VersionMajor:        6,
		IsClientVM:          0,
		LicenseStatus:       2,
		GraceTime:           43200 * 2,
		ApplicationID:       MustUUID("55c92734-d682-4d71-983e-d6ec3f16059f"),
		SKUID:               MustUUID("81671aaf-79d1-4eb1-b004-8cbbe173afea"),
		KMSCountedID:        MustUUID("cb8fc780-2c05-495a-9710-85afffc904d7"),
		ClientMachineID:     RandomUUID(),
		RequiredClientCount: 25,
		RequestTime:         uint64(TimeToFileTime(time.Now())),
		MachineNameRaw:      make([]byte, 128),
	}
	kmsData := kmsReq.Marshal()

	salt := make([]byte, 16)
	plaintext := append(salt, kmsData...)
	padded := crypto.PKCS7Pad(plaintext, 16)
	encrypted, _ := crypto.KMSDecryptCBC(padded, salt, true)

	bodyLength := uint32(4 + len(encrypted))
	padding := make([]byte, GetPadding(int(bodyLength)))

	packet := make([]byte, 4+4+2+2+len(encrypted)+len(padding))
	offset := 0
	binary.LittleEndian.PutUint32(packet[offset:], bodyLength)
	offset += 4
	binary.LittleEndian.PutUint32(packet[offset:], bodyLength)
	offset += 4
	binary.LittleEndian.PutUint16(packet[offset:], 1)
	offset += 2
	binary.LittleEndian.PutUint16(packet[offset:], 6)
	offset += 2
	copy(packet[offset:], encrypted)

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HandleV6Request(ctx, packet, config)
	}
}
