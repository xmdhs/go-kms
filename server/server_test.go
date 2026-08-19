package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xmdhs/go-kms/crypto"
	"github.com/xmdhs/go-kms/kms"
	"github.com/xmdhs/go-kms/rpc"
)

func TestNewKMSServer(t *testing.T) {
	cfg := kms.DefaultServerConfig()
	srv := NewKMSServer(cfg)
	if srv == nil || srv.Config != cfg {
		t.Fatal("NewKMSServer did not store config")
	}
}

func TestListenAndServeListenError(t *testing.T) {
	cfg := kms.DefaultServerConfig()
	cfg.IP = "999.999.999.999"
	cfg.Port = 1
	srv := NewKMSServer(cfg)
	if err := srv.ListenAndServe(); err == nil {
		t.Fatal("expected listen error")
	}
}

func TestListenSuccessAndClose(t *testing.T) {
	cfg := kms.DefaultServerConfig()
	cfg.IP = "127.0.0.1"
	cfg.Port = 0
	srv := NewKMSServer(cfg)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen error = %v", err)
	}
	if srv.listener == nil {
		t.Fatal("listener not set")
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
}

func TestCloseWithoutListener(t *testing.T) {
	srv := NewKMSServer(kms.DefaultServerConfig())
	if err := srv.Close(); err != nil {
		t.Fatalf("Close should be nil without a listener, got %v", err)
	}
}

func TestServeNotListening(t *testing.T) {
	srv := NewKMSServer(kms.DefaultServerConfig())
	if err := srv.Serve(); err == nil {
		t.Fatal("expected 'not listening' error")
	}
}

func TestServeStopsWhenListenerClosed(t *testing.T) {
	cfg := kms.DefaultServerConfig()
	cfg.IP = "127.0.0.1"
	cfg.Port = 0
	srv := NewKMSServer(cfg)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen error = %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
	// Accept now fails fast with ErrClosed -> Serve returns nil.
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve after close = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after listener closed")
	}
}

// mkKMSWire builds a request payload suitable for kms.GenerateKMSResponseData.
func mkKMSWire(t *testing.T, major uint16, isV6 bool) []byte {
	t.Helper()
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
		t.Fatal(err)
	}
	plain := make([]byte, 0, 16+len(kb))
	plain = append(plain, dsalt[:16]...)
	plain = append(plain, kb...)
	ct, err := crypto.KMSEncryptCBC(crypto.PKCS7Pad(plain, 16), esalt, isV6)
	if err != nil {
		t.Fatal(err)
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

// feedAndClose writes feed on the client side then closes it, and waits for the
// server's handleConnection to finish. It drives the "write-only" branch cases.
func feedAndClose(t *testing.T, feed func(w io.Writer)) {
	t.Helper()
	srv := NewKMSServer(kms.DefaultServerConfig())
	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		srv.handleConnection(c1)
		close(done)
	}()
	feed(c2)
	_ = c2.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleConnection did not return")
	}
	_ = c1.Close()
}

func TestHandleConnectionFullFlow(t *testing.T) {
	srv := NewKMSServer(kms.DefaultServerConfig())
	c1, c2 := net.Pipe()
	go srv.handleConnection(c1)

	bind := rpc.BuildBindRequest(1)
	if _, err := c2.Write(bind); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	ack, err := rpc.RecvAll(c2, 512)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if h, err := rpc.ParseMSRPCHeader(ack); err != nil || h.Type != rpc.PacketTypeBindAck {
		t.Fatalf("expected bind ack, got type error=%v", err)
	}

	rd := rpc.BuildRPCRequest(mkKMSWire(t, 5, false), 2)
	if _, err := c2.Write(rd); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := rpc.RecvAll(c2, 512)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if rh, _ := rpc.ParseMSRPCHeader(resp); rh.Type != rpc.PacketTypeResponse {
		t.Fatal("expected response packet")
	}
	_ = c2.Close()
	_ = c1.Close()
}

func TestHandleConnectionBindBadPayload(t *testing.T) {
	feedAndClose(t, func(w io.Writer) {
		data := make([]byte, rpc.MSRPCHeaderSize)
		data[2] = rpc.PacketTypeBind
		binary.LittleEndian.PutUint16(data[8:10], rpc.MSRPCHeaderSize)
		_, _ = w.Write(data)
	})
}

func TestHandleConnectionUnknownType(t *testing.T) {
	feedAndClose(t, func(w io.Writer) {
		data := make([]byte, rpc.MSRPCHeaderSize)
		data[2] = 0x99
		binary.LittleEndian.PutUint16(data[8:10], rpc.MSRPCHeaderSize)
		_, _ = w.Write(data)
	})
}

func TestHandleConnectionFragTooLarge(t *testing.T) {
	feedAndClose(t, func(w io.Writer) {
		data := make([]byte, rpc.MSRPCHeaderSize)
		data[2] = rpc.PacketTypeRequest
		binary.LittleEndian.PutUint16(data[8:10], 600)
		_, _ = w.Write(data)
	})
}

func TestHandleConnectionShortRequestHeader(t *testing.T) {
	// 16-byte request packet -> ParseMSRPCRequestHeader fails (needs 24).
	feedAndClose(t, func(w io.Writer) {
		data := make([]byte, rpc.MSRPCHeaderSize)
		data[2] = rpc.PacketTypeRequest
		binary.LittleEndian.PutUint16(data[8:10], rpc.MSRPCHeaderSize)
		_, _ = w.Write(data)
	})
}

func TestHandleConnectionNilPDU(t *testing.T) {
	// 24-byte request packet with fragLen 24 -> PDUData returns nil.
	feedAndClose(t, func(w io.Writer) {
		data := make([]byte, rpc.MSRPCRequestHeaderSize)
		data[2] = rpc.PacketTypeRequest
		binary.LittleEndian.PutUint16(data[8:10], rpc.MSRPCRequestHeaderSize)
		_, _ = w.Write(data)
	})
}

func TestHandleConnectionKMSGenerationError(t *testing.T) {
	feedAndClose(t, func(w io.Writer) {
		// A request whose PDU is a bad V5 KMS request -> GenerateKMSResponseData errors.
		bad := make([]byte, 12)
		binary.LittleEndian.PutUint16(bad[10:12], 5)
		pkt := rpc.BuildRPCRequest(bad, 3)
		_, _ = w.Write(pkt)
	})
}

func TestHandleConnectionReadEOF(t *testing.T) {
	// Client connects then closes immediately -> io.EOF read branch (no warn log).
	feedAndClose(t, func(w io.Writer) {})
}

func TestServeAcceptsAndResponds(t *testing.T) {
	cfg := kms.DefaultServerConfig()
	cfg.IP = "127.0.0.1"
	cfg.Port = freePort(t)
	srv := NewKMSServer(cfg)
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.ListenAndServe() }()

	addr := net.JoinHostPort(cfg.IP, itoa(cfg.Port))

	// Bind flow (retry dial until the listener is up).
	conn := dialReady(t, addr)
	if _, err := conn.Write(rpc.BuildBindRequest(1)); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	ack, err := rpc.RecvAll(conn, 512)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if h, _ := rpc.ParseMSRPCHeader(ack); h.Type != rpc.PacketTypeBindAck {
		t.Fatal("expected bind ack")
	}
	conn.Close()

	// Request flow.
	conn2 := dialReady(t, addr)
	if _, err := conn2.Write(rpc.BuildRPCRequest(mkKMSWire(t, 5, false), 2)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := rpc.RecvAll(conn2, 512)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if rh, _ := rpc.ParseMSRPCHeader(resp); rh.Type != rpc.PacketTypeResponse {
		t.Fatal("expected response")
	}
	conn2.Close()

	// Closing the listener makes Serve return nil.
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("ListenAndServe = %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ListenAndServe did not return")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

// dialReady repeatedly tries to connect until the server listener is up.
func dialReady(t *testing.T, addr string) net.Conn {
	t.Helper()
	for i := 0; i < 200; i++ {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			return conn
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("dial %s: no listener after retries", addr)
	return nil
}

func TestHandleConnectionWriteError(t *testing.T) {
	// Server replies to a bind, then after the client closes mid-request the
	// response write fails.
	srv := NewKMSServer(kms.DefaultServerConfig())
	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go func() { srv.handleConnection(c1); close(done) }()

	// Bind + read ack so the server reaches the loop again.
	if _, err := c2.Write(rpc.BuildBindRequest(1)); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	if _, err := rpc.RecvAll(c2, 512); err != nil {
		t.Fatalf("read ack: %v", err)
	}

	// Send a request then immediately close before reading the response,
	// forcing the server's response write to fail.
	if _, err := c2.Write(rpc.BuildRPCRequest(mkKMSWire(t, 5, false), 2)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = c2.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleConnection did not return")
	}
	_ = c1.Close()
}
