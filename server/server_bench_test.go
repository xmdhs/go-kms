package server

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/xmdhs/go-kms/rpc"
)

// mockConn is a mock network connection for benchmarking.
type mockConn struct {
	net.Conn
	reader *bytes.Reader
	writer *bytes.Buffer
}

func (m *mockConn) Read(b []byte) (int, error) {
	return m.reader.Read(b)
}

func (m *mockConn) Write(b []byte) (int, error) {
	return m.writer.Write(b)
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func buildTestRPCPacket() []byte {
	// Build a complete RPC request packet
	kmsData := make([]byte, 100)
	rpcData := rpc.BuildRPCRequest(kmsData, 1)
	return rpcData
}

func BenchmarkRecvAllInto(b *testing.B) {
	packet := buildTestRPCPacket()
	conn := &mockConn{
		reader: bytes.NewReader(packet),
		writer: &bytes.Buffer{},
	}
	buf := make([]byte, maxFragLen)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.reader.Reset(packet)
		conn.writer.Reset()
		rpc.RecvAllInto(conn, buf, maxFragLen)
	}
}

func BenchmarkRecvAll(b *testing.B) {
	packet := buildTestRPCPacket()
	conn := &mockConn{
		reader: bytes.NewReader(packet),
		writer: &bytes.Buffer{},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.reader.Reset(packet)
		conn.writer.Reset()
		rpc.RecvAll(conn, maxFragLen)
	}
}

// Benchmark fragment length extraction from RPC header.
func BenchmarkExtractFragLen(b *testing.B) {
	packet := buildTestRPCPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = binary.LittleEndian.Uint16(packet[8:10])
	}
}
