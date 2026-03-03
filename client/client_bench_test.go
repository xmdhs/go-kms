package client

import (
	"testing"
)

func BenchmarkBuildKMSRequest(b *testing.B) {
	product := Products["Windows10"]
	cmid := "55c92734-d682-4d71-983e-d6ec3f16059f"
	machine := "TEST-MACHINE-001"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildKMSRequest(product, cmid, machine)
	}
}

func BenchmarkBuildV4ClientRequest(b *testing.B) {
	product := Products["Windows7"]
	cmid := "55c92734-d682-4d71-983e-d6ec3f16059f"
	machine := "TEST-MACHINE-001"
	kmsData, _ := buildKMSRequest(product, cmid, machine)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildV4ClientRequest(kmsData)
	}
}

func BenchmarkBuildV5ClientRequest(b *testing.B) {
	product := Products["Windows8"]
	cmid := "55c92734-d682-4d71-983e-d6ec3f16059f"
	machine := "TEST-MACHINE-001"
	kmsData, _ := buildKMSRequest(product, cmid, machine)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildV5ClientRequest(kmsData, product.ProtoMinor, uint16(product.ProtoMajor))
	}
}

func BenchmarkBuildV6ClientRequest(b *testing.B) {
	product := Products["Windows10"]
	cmid := "55c92734-d682-4d71-983e-d6ec3f16059f"
	machine := "TEST-MACHINE-001"
	kmsData, _ := buildKMSRequest(product, cmid, machine)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildV6ClientRequest(kmsData, product.ProtoMinor, uint16(product.ProtoMajor))
	}
}

func BenchmarkParseV4Response(b *testing.B) {
	// Build a mock V4 response
	product := Products["Windows7"]
	cmid := "55c92734-d682-4d71-983e-d6ec3f16059f"
	machine := "TEST-MACHINE-001"
	kmsData, _ := buildKMSRequest(product, cmid, machine)
	request := buildV4ClientRequest(kmsData)

	// Create a simple mock response (just the envelope, no actual encryption)
	// For benchmark purposes, we're testing parsing logic
	responseData := make([]byte, len(request))
	copy(responseData, request)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseV4Response(responseData)
	}
}

func BenchmarkParseV5Response(b *testing.B) {
	// Build a mock V5 response structure
	product := Products["Windows8"]
	cmid := "55c92734-d682-4d71-983e-d6ec3f16059f"
	machine := "TEST-MACHINE-001"
	kmsData, _ := buildKMSRequest(product, cmid, machine)
	request, _ := buildV5ClientRequest(kmsData, product.ProtoMinor, uint16(product.ProtoMajor))

	responseData := make([]byte, len(request))
	copy(responseData, request)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseV5Response(responseData)
	}
}

func BenchmarkParseV6Response(b *testing.B) {
	product := Products["Windows10"]
	cmid := "55c92734-d682-4d71-983e-d6ec3f16059f"
	machine := "TEST-MACHINE-001"
	kmsData, _ := buildKMSRequest(product, cmid, machine)
	request, _ := buildV6ClientRequest(kmsData, product.ProtoMinor, uint16(product.ProtoMajor))

	responseData := make([]byte, len(request))
	copy(responseData, request)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseV6Response(responseData)
	}
}

func BenchmarkRandomMachineName(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		randomMachineName()
	}
}

// Full client flow benchmarks
func BenchmarkClientFlowV4(b *testing.B) {
	product := Products["Windows7"]
	cmid := "55c92734-d682-4d71-983e-d6ec3f16059f"
	machine := "TEST-MACHINE-001"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kmsData, _ := buildKMSRequest(product, cmid, machine)
		_ = buildV4ClientRequest(kmsData)
	}
}

func BenchmarkClientFlowV5(b *testing.B) {
	product := Products["Windows8"]
	cmid := "55c92734-d682-4d71-983e-d6ec3f16059f"
	machine := "TEST-MACHINE-001"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kmsData, _ := buildKMSRequest(product, cmid, machine)
		_, _ = buildV5ClientRequest(kmsData, product.ProtoMinor, uint16(product.ProtoMajor))
	}
}

func BenchmarkClientFlowV6(b *testing.B) {
	product := Products["Windows10"]
	cmid := "55c92734-d682-4d71-983e-d6ec3f16059f"
	machine := "TEST-MACHINE-001"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kmsData, _ := buildKMSRequest(product, cmid, machine)
		_, _ = buildV6ClientRequest(kmsData, product.ProtoMinor, uint16(product.ProtoMajor))
	}
}

