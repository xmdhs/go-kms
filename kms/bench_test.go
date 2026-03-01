package kms

import (
	"context"
	"testing"
	"time"
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
