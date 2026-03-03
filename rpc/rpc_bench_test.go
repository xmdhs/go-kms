package rpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// buildTestBindRequest creates a valid BIND request for benchmarking.
func buildTestBindRequest() []byte {
	req := BuildBindRequest(1)
	return req
}

// buildTestRPCRequest creates a valid RPC request for benchmarking.
func buildTestRPCRequest(kmsData []byte) []byte {
	return BuildRPCRequest(kmsData, 1)
}

// buildTestRPCResponse creates a valid RPC response for benchmarking.
func buildTestRPCResponse() ([]byte, *MSRPCRequestHeader) {
	kmsData := make([]byte, 100)
	req := BuildRPCRequest(kmsData, 1)
	reqHeader, _ := ParseMSRPCRequestHeader(req)
	resp := BuildMSRPCResponse(reqHeader, kmsData)
	return resp, reqHeader
}

func BenchmarkParseMSRPCHeader(b *testing.B) {
	data := buildTestBindRequest()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseMSRPCHeader(data)
	}
}

func BenchmarkMSRPCHeader_Marshal(b *testing.B) {
	h := &MSRPCHeader{
		VerMajor:       5,
		VerMinor:       0,
		Type:           PacketTypeBind,
		Flags:          FlagFirstFrag | FlagLastFrag,
		Representation: 0x10,
		FragLen:        100,
		AuthLen:        0,
		CallID:         1,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Marshal()
	}
}

func BenchmarkParseMSRPCRequestHeader(b *testing.B) {
	kmsData := make([]byte, 100)
	data := BuildRPCRequest(kmsData, 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseMSRPCRequestHeader(data)
	}
}

func BenchmarkMSRPCRequestHeader_PDUData(b *testing.B) {
	kmsData := make([]byte, 100)
	data := BuildRPCRequest(kmsData, 1)
	header, _ := ParseMSRPCRequestHeader(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header.PDUData(data)
	}
}

func BenchmarkBuildMSRPCResponse(b *testing.B) {
	kmsData := make([]byte, 100)
	req := BuildRPCRequest(kmsData, 1)
	reqHeader, _ := ParseMSRPCRequestHeader(req)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildMSRPCResponse(reqHeader, kmsData)
	}
}

func BenchmarkParseBindRequest(b *testing.B) {
	data := buildTestBindRequest()
	// Skip header
	pduData := PDUData(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseBindRequest(pduData)
	}
}

func BenchmarkBuildBindAckResponse(b *testing.B) {
	data := buildTestBindRequest()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildBindAckResponse(data, 1688, 1)
	}
}

func BenchmarkBuildBindRequest(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildBindRequest(1)
	}
}

func BenchmarkBuildRPCRequest(b *testing.B) {
	kmsData := make([]byte, 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildRPCRequest(kmsData, 1)
	}
}

// BenchmarkPDUData extracts PDU data from various packet types.
func BenchmarkPDUData_Bind(b *testing.B) {
	data := buildTestBindRequest()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PDUData(data)
	}
}

func BenchmarkPDUData_Request(b *testing.B) {
	kmsData := make([]byte, 100)
	data := BuildRPCRequest(kmsData, 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PDUData(data)
	}
}

// Benchmark for context item handling in BIND
func BenchmarkBuildBindAckResponse_WithMultipleContexts(b *testing.B) {
	// Build a BIND request with multiple contexts
	kmsUUID := [16]byte{0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06}

	firstCtx := CtxItem{
		ContextID:          0,
		TransItems:         1,
		Pad:                0,
		AbstractSyntaxUUID: kmsUUID,
		AbstractSyntaxVer:  1,
		TransferSyntaxUUID: UUIDNDR32,
		TransferSyntaxVer:  2,
	}

	secondCtx := CtxItem{
		ContextID:          1,
		TransItems:         1,
		Pad:                0,
		AbstractSyntaxUUID: kmsUUID,
		AbstractSyntaxVer:  1,
		TransferSyntaxUUID: UUIDTime,
		TransferSyntaxVer:  1,
	}

	var bindBody bytes.Buffer
	binary.Write(&bindBody, binary.LittleEndian, uint16(5840))
	binary.Write(&bindBody, binary.LittleEndian, uint16(5840))
	binary.Write(&bindBody, binary.LittleEndian, uint32(0))
	bindBody.WriteByte(2)
	bindBody.WriteByte(0)
	binary.Write(&bindBody, binary.LittleEndian, uint16(0))
	binary.Write(&bindBody, binary.LittleEndian, &firstCtx)
	binary.Write(&bindBody, binary.LittleEndian, &secondCtx)
	pduData := bindBody.Bytes()

	header := MSRPCHeader{
		VerMajor:       5,
		VerMinor:       0,
		Type:           PacketTypeBind,
		Flags:          FlagFirstFrag | FlagLastFrag | FlagConcMpx,
		Representation: 0x10,
		FragLen:        uint16(MSRPCHeaderSize + len(pduData)),
		AuthLen:        0,
		CallID:         1,
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, &header)
	buf.Write(pduData)
	data := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildBindAckResponse(data, 1688, 1)
	}
}

// Benchmark for parsing bind request with multiple context items
func BenchmarkParseBindRequest_MultipleContexts(b *testing.B) {
	// Create a bind request body with multiple contexts
	bindReq := &BindRequest{
		MaxTFrag:   5840,
		MaxRFrag:   5840,
		AssocGroup: 0,
		CtxNum:     2,
		Reserved:   0,
		Reserved2:  0,
		CtxItems: []CtxItem{
			{
				ContextID:          0,
				TransItems:         1,
				Pad:                0,
				AbstractSyntaxUUID: [16]byte{0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06},
				AbstractSyntaxVer:  1,
				TransferSyntaxUUID: UUIDNDR32,
				TransferSyntaxVer:  2,
			},
			{
				ContextID:          1,
				TransItems:         1,
				Pad:                0,
				AbstractSyntaxUUID: [16]byte{0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06},
				AbstractSyntaxVer:  1,
				TransferSyntaxUUID: UUIDTime,
				TransferSyntaxVer:  1,
			},
		},
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, bindReq.MaxTFrag)
	binary.Write(&buf, binary.LittleEndian, bindReq.MaxRFrag)
	binary.Write(&buf, binary.LittleEndian, bindReq.AssocGroup)
	buf.WriteByte(bindReq.CtxNum)
	buf.WriteByte(bindReq.Reserved)
	binary.Write(&buf, binary.LittleEndian, bindReq.Reserved2)
	for i := range bindReq.CtxItems {
		binary.Write(&buf, binary.LittleEndian, &bindReq.CtxItems[i])
	}
	data := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseBindRequest(data)
	}
}

// Benchmark for complete RPC request-response cycle
func BenchmarkBuildMSRPCResponse_WithVaryingSizes(b *testing.B) {
	sizes := []int{100, 256, 512, 1024}

	for _, size := range sizes {
		kmsData := make([]byte, size)
		req := BuildRPCRequest(kmsData, 1)
		reqHeader, _ := ParseMSRPCRequestHeader(req)

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				BuildMSRPCResponse(reqHeader, kmsData)
			}
		})
	}
}

// Benchmark for UUID comparison
func BenchmarkUUIDComparison(b *testing.B) {
	u1 := UUIDNDR32
	u2 := UUIDNDR64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = u1 == u2
		_ = u1 == UUIDNDR32
	}
}

// Benchmark full RPC packet construction (BIND + REQUEST)
func BenchmarkFullRPCPacketConstruction(b *testing.B) {
	kmsData := make([]byte, 256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Build BIND
		bindReq := BuildBindRequest(uint32(i))
		_ = bindReq

		// Build REQUEST
		rpcReq := BuildRPCRequest(kmsData, uint32(i))
		_ = rpcReq
	}
}
