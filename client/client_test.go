package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/xmdhs/go-kms/crypto"
	"github.com/xmdhs/go-kms/kms"
	"github.com/xmdhs/go-kms/rpc"
)

func TestDefaultClientConfig(t *testing.T) {
	c := DefaultClientConfig()
	if c.IP != "127.0.0.1" || c.Port != 1688 || c.Mode != "Windows8.1" {
		t.Fatalf("unexpected default config: %+v", c)
	}
}

func TestRandomMachineName(t *testing.T) {
	for i := 0; i < 20; i++ {
		n := randomMachineName()
		if len(n) < 8 || len(n) > 15 {
			t.Fatalf("machine name length = %d", len(n))
		}
		for _, c := range n {
			if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", c) {
				t.Fatalf("unexpected char %q in %q", c, n)
			}
		}
	}
}

func TestProductsHaveAllFields(t *testing.T) {
	for _, name := range []string{"WindowsVista", "Windows7", "Windows8", "Windows8.1", "Windows10", "Office2010", "Office2013", "Office2016", "Office2019"} {
		p, ok := Products[name]
		if !ok {
			t.Fatalf("missing product %s", name)
		}
		if p.SkuID == "" || p.AppID == "" || p.KmsCountID == "" {
			t.Fatalf("product %s has empty ids", name)
		}
	}
}

func TestBuildKMSRequest(t *testing.T) {
	req, err := buildKMSRequest(Products["Windows8.1"], "78563412-bc9a-f0de-1122-334455667788", "TESTMACHINE")
	if err != nil {
		t.Fatalf("buildKMSRequest error = %v", err)
	}
	if len(req) < 108 {
		t.Fatalf("request too short: %d", len(req))
	}

	if _, err := buildKMSRequest(Products["Windows8.1"], "bad-cmid", "M"); err == nil {
		t.Fatal("expected error for invalid CMID")
	}
}

func TestBuildClientRequests(t *testing.T) {
	kmsData := bytes.Repeat([]byte{0x01}, 120)

	v4 := buildV4ClientRequest(kmsData)
	if len(v4) < 8 {
		t.Fatal("v4 request too short")
	}

	if _, err := buildV5ClientRequest(kmsData, 1, 5); err != nil {
		t.Fatalf("buildV5ClientRequest error = %v", err)
	}
	if _, err := buildV6ClientRequest(kmsData, 1, 6); err != nil {
		t.Fatalf("buildV6ClientRequest error = %v", err)
	}

	// buildV5V6ClientRequest round-trips the encrypted envelope.
	wire, err := buildV5V6ClientRequest(kmsData, 1, 6, true)
	if err != nil {
		t.Fatalf("buildV5V6 error = %v", err)
	}
	bodyLen := binary.LittleEndian.Uint32(wire[0:4])
	if bodyLen != uint32(4+len(wire)-12) {
		t.Fatalf("body length = %d", bodyLen)
	}
}

// mkReqWire builds a request payload for kms.GenerateKMSResponseData.
func mkReqWire(t *testing.T, major uint16, isV6 bool) []byte {
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

// mkRespWire generates a valid versioned response wire that a fake server
// would wrap and send to the client.
func mkRespWire(t *testing.T, reqWire []byte) []byte {
	t.Helper()
	cfg := kms.DefaultServerConfig()
	data, err := kms.GenerateKMSResponseData(context.Background(), reqWire, cfg)
	if err != nil {
		t.Fatalf("GenerateKMSResponseData error = %v", err)
	}
	return data
}

func TestParseV4ResponseTo(t *testing.T) {
	var out bytes.Buffer

	w := mkReqWire(t, 4, false)
	respWire := mkRespWire(t, w)

	if err := parseV4ResponseTo(respWire, &out); err != nil {
		t.Fatalf("parseV4ResponseTo(valid) error = %v", err)
	}
	if !strings.Contains(out.String(), "KMS Response") {
		t.Fatalf("unexpected output %q", out.String())
	}

	if err := parseV4ResponseTo([]byte{1, 2}, &out); err == nil {
		t.Fatal("expected too-short error")
	}

	// Body length claims more than available.
	short := make([]byte, 12)
	binary.LittleEndian.PutUint32(short[8:12], 1000)
	if err := parseV4ResponseTo(short, &out); err == nil {
		t.Fatal("expected body-too-short error")
	}
}

func TestParseV5V6ResponseTo(t *testing.T) {
	var out bytes.Buffer

	for _, tc := range []struct {
		major uint16
		isV6  bool
	}{
		{5, false},
		{6, true},
	} {
		w := mkReqWire(t, tc.major, tc.isV6)
		respWire := mkRespWire(t, w)
		if err := parseV5V6Response(respWire, tc.isV6, &out); err != nil {
			t.Fatalf("parseV5V6(v%d) error = %v", tc.major, err)
		}
		if !strings.Contains(out.String(), "KMS Response") {
			t.Fatalf("unexpected output %q", out.String())
		}
	}

	if err := parseV5V6Response([]byte{1, 2, 3, 4, 5}, false, &out); err == nil {
		t.Fatal("expected too-short error")
	}

	// remrning too short for salt.
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], 20)
	if err := parseV5V6Response(hdr, false, &out); err == nil {
		t.Fatal("expected missing-salt error")
	}

	// encrypted data claimed too short.
	hdr2 := make([]byte, 16+16)
	binary.LittleEndian.PutUint32(hdr2[0:4], 4) // small body len -> encryptedEnd <= 16
	if err := parseV5V6Response(hdr2, false, &out); err == nil {
		t.Fatal("expected encrypted-too-short error")
	}
}

func TestPrintResponseToBuffer(t *testing.T) {
	var out bytes.Buffer
	resp := &kms.KMSResponse{
		VersionMinor: 1, VersionMajor: 6,
		KMSEpid:              kms.EncodeUTF16LE("aa-epid"),
		ClientMachineID:      kms.RandomUUID(),
		ResponseTime:         555,
		CurrentClientCount:   25,
		VLActivationInterval: 120,
		VLRenewalInterval:    10080,
	}
	printResponse(&out, resp)
	for _, want := range []string{"ePID: aa-epid", "Client Machine ID:", "VL Renewal Interval:"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("printResponse missing %q: %q", want, out.String())
		}
	}
}

func TestParseV4V5V6WrapperToStdout(t *testing.T) {
	// Wrappers that write to os.Stdout are invoked for coverage only.
	w4 := mkRespWire(t, mkReqWire(t, 4, false))
	if err := parseV4Response(w4); err != nil {
		t.Fatalf("parseV4Response error = %v", err)
	}
	w5 := mkRespWire(t, mkReqWire(t, 5, false))
	if err := parseV5Response(w5); err != nil {
		t.Fatalf("parseV5Response error = %v", err)
	}
	w6 := mkRespWire(t, mkReqWire(t, 6, true))
	if err := parseV6Response(w6); err != nil {
		t.Fatalf("parseV6Response error = %v", err)
	}

	var out bytes.Buffer
	if err := parseV5ResponseTo(w5, &out); err != nil {
		t.Fatalf("parseV5ResponseTo error = %v", err)
	}
	if err := parseV6ResponseTo(w6, &out); err != nil {
		t.Fatalf("parseV6ResponseTo error = %v", err)
	}
}

// startFakeServer runs a minimal KMS server speaking RPC bind/request.
func startFakeServer(t *testing.T, cfg *kms.ServerConfig) (port int, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port = ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				data, err := rpc.RecvAll(conn, 512)
				if err != nil {
					return
				}
				h, err := rpc.ParseMSRPCHeader(data)
				if err != nil || h.Type != rpc.PacketTypeBind {
					return
				}
				ack, err := rpc.BuildBindAckResponse(data, port, h.CallID)
				if err != nil {
					return
				}
				if _, err := conn.Write(ack); err != nil {
					return
				}
				rd, err := rpc.RecvAll(conn, 512)
				if err != nil {
					return
				}
				rh, err := rpc.ParseMSRPCRequestHeader(rd)
				if err != nil {
					return
				}
				kr, err := kms.GenerateKMSResponseData(context.Background(), rh.PDUData(rd), cfg)
				if err != nil {
					return
				}
				_, _ = conn.Write(rpc.BuildMSRPCResponse(rh, kr))
			}()
		}
	}()
	return port, func() { ln.Close() }
}

func TestRunWithWriterSuccess(t *testing.T) {
	cfg := kms.DefaultServerConfig()
	for _, mode := range []string{"WindowsVista", "Windows8", "Windows8.1"} {
		t.Run(mode, func(t *testing.T) {
			port, closeFn := startFakeServer(t, cfg)
			defer closeFn()

			var out bytes.Buffer
			clientCfg := &ClientConfig{IP: "127.0.0.1", Port: port, Mode: mode}
			if err := RunWithWriter(clientCfg, &out); err != nil {
				t.Fatalf("RunWithWriter(%s) error = %v", mode, err)
			}
			if !strings.Contains(out.String(), "KMS Response") {
				t.Fatalf("unexpected output %q", out.String())
			}
		})
	}
}

func TestRunWithWriterErrors(t *testing.T) {
	var out bytes.Buffer

	// Unknown mode.
	if err := RunWithWriter(&ClientConfig{IP: "127.0.0.1", Port: 1688, Mode: "Nope"}, &out); err == nil {
		t.Fatal("expected unknown-mode error")
	}

	// Connection failure to a closed port.
	if err := RunWithWriter(&ClientConfig{IP: "127.0.0.1", Port: 1, Mode: "Windows8.1"}, &out); err == nil {
		t.Fatal("expected connection error")
	}

	// Invalid CMID fails during request construction.
	port, closeFn := startFakeServer(t, kms.DefaultServerConfig())
	defer closeFn()
	if err := RunWithWriter(&ClientConfig{IP: "127.0.0.1", Port: port, Mode: "Windows8.1", CMID: "bad"}, &out); err == nil {
		t.Fatal("expected invalid-cmid error")
	}
}

func TestRunWithWriterBadBindAck(t *testing.T) {
	// A server that replies with a non-bind-ack type on the bind phase.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		conn, _ := ln.Accept()
		defer conn.Close()
		_, _ = rpc.RecvAll(conn, 512)
		// Reply with a plain response-type packet -> client rejects.
		h := rpc.MSRPCHeader{VerMajor: 5, Type: rpc.PacketTypeResponse, FragLen: rpc.MSRPCHeaderSize, CallID: 1}
		_, _ = conn.Write(h.Marshal())
		ln.Close()
	}()

	var out bytes.Buffer
	err = RunWithWriter(&ClientConfig{IP: "127.0.0.1", Port: port, Mode: "Windows8.1", CMID: "78563412-bc9a-f0de-1122-334455667788", Machine: "MACHINE"}, &out)
	if err == nil {
		t.Fatal("expected bind-ack error")
	}
}
