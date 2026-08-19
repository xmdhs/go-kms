package rpc

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func TestParseMSRPCHeaderRoundTrip(t *testing.T) {
	h := &MSRPCHeader{
		VerMajor: 5, VerMinor: 0, Type: PacketTypeRequest, Flags: FlagFirstFrag | FlagLastFrag,
		Representation: 0x10, FragLen: 24, AuthLen: 0, CallID: 7,
	}
	data := h.Marshal()
	parsed, err := ParseMSRPCHeader(data)
	if err != nil {
		t.Fatalf("ParseMSRPCHeader error = %v", err)
	}
	if *parsed != *h {
		t.Fatalf("round trip mismatch: %+v vs %+v", parsed, h)
	}

	if _, err := ParseMSRPCHeader(data[:10]); err == nil {
		t.Fatal("expected short header error")
	}
}

func TestPDUDataBoundaries(t *testing.T) {
	// Too short -> nil.
	if got := PDUData(make([]byte, MSRPCHeaderSize)); got != nil {
		t.Fatal("expected nil for header-only input")
	}
	if got := PDUData(make([]byte, MSRPCHeaderSize-1)); got != nil {
		t.Fatal("expected nil for short input")
	}

	// Valid request with call data. The generic PDUData slices from the header
	// end (16) to fragLen, which for a REQUEST includes its extension fields.
	req := BuildRPCRequest([]byte{1, 2, 3, 4}, 9)
	pdu := PDUData(req)
	if !bytes.Equal(pdu, req[16:]) {
		t.Fatalf("pdu = %x, want %x", pdu, req[16:])
	}
	// The actual payload is the last 4 bytes of the request.
	if !bytes.Equal(pdu[len(pdu)-4:], []byte{1, 2, 3, 4}) {
		t.Fatalf("request payload = %x", pdu)
	}

	// AuthLen trims the tail and a fixed 8-byte sec trailer:
	// end = fragLen(28) - authLen(2) - 8 = 18.
	authed := append([]byte(nil), req...)
	binary.LittleEndian.PutUint16(authed[10:12], 2)
	pdu2 := PDUData(authed)
	if pdu2 == nil {
		t.Fatal("expected non-nil authed pdu")
	}
	if !bytes.Equal(pdu2, authed[16:18]) {
		t.Fatalf("authed pdu = %x, want %x", pdu2, authed[16:18])
	}

	// FragLen shorter than the actual data -> truncated.
	trunc := append([]byte(nil), req...)
	binary.LittleEndian.PutUint16(trunc[8:10], MSRPCHeaderSize+2)
	pdu3 := PDUData(trunc)
	if !bytes.Equal(pdu3, trunc[16:18]) {
		t.Fatalf("truncated pdu = %x, want %x", pdu3, trunc[16:18])
	}

	// end > len(data) -> clamp end to the buffer length.
	biggish := append([]byte(nil), req...)
	binary.LittleEndian.PutUint16(biggish[8:10], 1000)
	pduB := PDUData(biggish)
	if !bytes.Equal(pduB, biggish[16:]) {
		t.Fatalf("clamped pdu = %x, want %x", pduB, biggish[16:])
	}

	// Large authLen drives end <= 16 -> nil.
	authedNil := append([]byte(nil), req...)
	binary.LittleEndian.PutUint16(authedNil[10:12], 20)
	if pduN := PDUData(authedNil); pduN != nil {
		t.Fatalf("expected nil when authLen consumes all data, got %x", pduN)
	}
}

func TestMSRPCRequestHeaderParseAndPDU(t *testing.T) {
	req := BuildRPCRequest([]byte{9, 8, 7, 6}, 3)
	h, err := ParseMSRPCRequestHeader(req)
	if err != nil {
		t.Fatalf("ParseMSRPCRequestHeader error = %v", err)
	}
	if h.CallID != 3 || h.OpNum != 0 || h.CtxID != 0 {
		t.Fatalf("unexpected header: %+v", h)
	}
	if got := h.PDUData(req); !bytes.Equal(got, []byte{9, 8, 7, 6}) {
		t.Fatalf("PDUData = %x", got)
	}

	if _, err := ParseMSRPCRequestHeader(req[:10]); err == nil {
		t.Fatal("expected short header error")
	}

	// PDUData on a packet at or below the request-header threshold -> nil.
	emptyReq := &MSRPCRequestHeader{}
	if got := emptyReq.PDUData(make([]byte, MSRPCRequestHeaderSize)); got != nil {
		t.Fatal("expected nil when PDUData input is only a header")
	}

	// Object UUID flag shifts the data offset by an extra 16 bytes.
	payload := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0}
	obj := make([]byte, MSRPCRequestHeaderSize+16+len(payload))
	hdr := MSRPCHeader{
		VerMajor: 5, VerMinor: 0, Type: PacketTypeRequest,
		Flags:          FlagFirstFrag | FlagLastFrag | FlagObjectUUID,
		Representation: 0x10,
		FragLen:        uint16(MSRPCRequestHeaderSize + 16 + len(payload)),
		AuthLen:        0, CallID: 3,
	}
	copy(obj[:16], hdr.Marshal())
	binary.LittleEndian.PutUint32(obj[16:20], uint32(len(payload)))
	copy(obj[MSRPCRequestHeaderSize+16:], payload)
	ho, err := ParseMSRPCRequestHeader(obj)
	if err != nil {
		t.Fatalf("parse object-uuid header error = %v", err)
	}
	if got := ho.PDUData(obj); !bytes.Equal(got, payload) {
		t.Fatalf("object-uuid PDUData = %x, want %x", got, payload)
	}

	// PDU of a full request (reuse the outer payload variable).
	full := BuildRPCRequest(payload, 4)
	hFull, _ := ParseMSRPCRequestHeader(full)
	if got := hFull.PDUData(full); !bytes.Equal(got, payload) {
		t.Fatalf("full request PDUData = %x", got)
	}

	// end > len(fullPacket) -> clamp then return the available payload.
	big := append([]byte(nil), full...)
	binary.LittleEndian.PutUint16(big[8:10], 1000)
	hBig, _ := ParseMSRPCRequestHeader(big)
	if got := hBig.PDUData(big); !bytes.Equal(got, payload) {
		t.Fatalf("clamped request PDUData = %x", got)
	}

	// AuthLen collapses end to <= offset (first offset>=end check).
	authBig := append([]byte(nil), full...)
	binary.LittleEndian.PutUint16(authBig[10:12], 10) // 28-10=18 <= offset 24
	hAuthBig, _ := ParseMSRPCRequestHeader(authBig)
	if got := hAuthBig.PDUData(authBig); got != nil {
		t.Fatalf("expected nil for auth-collapsed PDU, got %x", got)
	}

	// AuthLen shrinks end below offset after the -8 trailer (second check).
	authMid := append([]byte(nil), full...)
	binary.LittleEndian.PutUint16(authMid[10:12], 2) // 28-2-8=18 <= offset 24
	hAuthMid, _ := ParseMSRPCRequestHeader(authMid)
	if got := hAuthMid.PDUData(authMid); got != nil {
		t.Fatalf("expected nil for trailer-shrunk PDU, got %x", got)
	}
}

func TestBuildMSRPCResponse(t *testing.T) {
	req := BuildRPCRequest([]byte{1, 2, 3}, 5)
	h, _ := ParseMSRPCRequestHeader(req)
	resp := BuildMSRPCResponse(h, []byte{0xde, 0xad})
	if len(resp) != MSRPCRespHeaderSize+2 {
		t.Fatalf("response len = %d", len(resp))
	}
	if resp[2] != PacketTypeResponse {
		t.Fatalf("type = %d, want response", resp[2])
	}
	if !bytes.Equal(resp[MSRPCRespHeaderSize:], []byte{0xde, 0xad}) {
		t.Fatal("payload mismatch")
	}
}

func netPipeWriter(t *testing.T, w io.Writer, data []byte) {
	t.Helper()
	go func() {
		_, _ = w.Write(data)
		_ = w.(interface{ Close() error }).Close()
	}()
}

func TestRecvAll(t *testing.T) {
	// Success: full packet.
	packet := BuildRPCRequest([]byte{1, 2, 3, 4}, 1)
	client, server := net.Pipe()
	netPipeWriter(t, server, packet)
	got, err := RecvAll(client, 512)
	if err != nil {
		t.Fatalf("RecvAll error = %v", err)
	}
	client.Close()
	server.Close()
	if len(got) != len(packet) || !bytes.Equal(got, packet) {
		t.Fatalf("RecvAll = %x, want %x", got, packet)
	}

	// FragLen exceeds maxFragLen.
	big := append([]byte(nil), packet...)
	binary.LittleEndian.PutUint16(big[8:10], 600)
	client2, server2 := net.Pipe()
	netPipeWriter(t, server2, big)
	if _, err := RecvAll(client2, 512); err == nil {
		t.Fatal("expected frag-len limit error")
	}
	client2.Close()
	server2.Close()

	// fragLen only covers the header: no body read. (Own copy, to avoid
	// mutating the packet backing array used by earlier cases.)
	hdrOnly := append([]byte(nil), packet[:MSRPCHeaderSize]...)
	binary.LittleEndian.PutUint16(hdrOnly[8:10], MSRPCHeaderSize)
	client3, server3 := net.Pipe()
	netPipeWriter(t, server3, hdrOnly)
	got3, err := RecvAll(client3, 512)
	if err != nil {
		t.Fatalf("RecvAll(header-only) error = %v", err)
	}
	if len(got3) != MSRPCHeaderSize {
		t.Fatalf("header-only len = %d", len(got3))
	}
	client3.Close()
	server3.Close()

	// Unexpected EOF mid-body. (Own copy of the header so fragLen reads 28.)
	trunc := append([]byte(nil), packet[:MSRPCHeaderSize+2]...)
	client4, server4 := net.Pipe()
	netPipeWriter(t, server4, trunc)
	if _, err := RecvAll(client4, 512); err == nil {
		t.Fatal("expected EOF error for truncated body")
	}
	client4.Close()
	server4.Close()

	// Immediate EOF on first read.
	client5, server5 := net.Pipe()
	go server5.Close()
	if _, err := RecvAll(client5, 512); err == nil {
		t.Fatal("expected EOF error")
	}
	client5.Close()
}

func TestParseBindRequest(t *testing.T) {
	req := BuildBindRequest(1)
	body := PDUData(req)
	b, err := ParseBindRequest(body)
	if err != nil {
		t.Fatalf("ParseBindRequest error = %v", err)
	}
	if b.CtxNum != 2 || len(b.CtxItems) != 2 {
		t.Fatalf("unexpected bind: %+v", b)
	}
	// First context advertises the KMS abstract syntax UUID.
	wantAbstract := [16]byte{0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06}
	if b.CtxItems[0].AbstractSyntaxUUID != wantAbstract {
		t.Fatalf("ctx0 abstract uuid = %x", b.CtxItems[0].AbstractSyntaxUUID)
	}

	if _, err := ParseBindRequest(nil); err == nil {
		t.Fatal("expected short bind error")
	}

	// Too many contexts -> context item out of bounds.
	if _, err := ParseBindRequest(body[:12+44+10]); err == nil {
		t.Fatal("expected context item bounds error")
	}
}

func TestBuildBindAckResponse(t *testing.T) {
	req := BuildBindRequest(1)

	// Short request -> header parse error.
	if _, err := BuildBindAckResponse([]byte{1, 2, 3}, 1688, 1); err == nil {
		t.Fatal("expected header error")
	}

	// Valid BIND with NDR32 + Time contexts -> two different result branches.
	resp, err := BuildBindAckResponse(req, 1688, 1)
	if err != nil {
		t.Fatalf("BuildBindAckResponse error = %v", err)
	}
	if resp[2] != PacketTypeBindAck {
		t.Fatalf("type = %d, want bind ack", resp[2])
	}
	// Results: ctx0 (NDR32) accepted, ctx1 (Time) is rejected with (3,3).
	// Absolute offset of ctx_results in a BIND ACK (hard-coded layout):
	// 16 header + 2 maxTF + 2 maxRF + 4 assoc + 2 secAddrLen + 4 "1688"
	// + 1 null + 1 pad + 1 ctx_num + 1 reserved + 2 reserved2 = 36.
	const resultsOffset = 36
	if binary.LittleEndian.Uint16(resp[resultsOffset:resultsOffset+2]) != uint16(ContResultAccept) {
		t.Fatal("ctx0 should be accepted")
	}
	ctx1Off := resultsOffset + CtxItemResultSize
	if binary.LittleEndian.Uint16(resp[ctx1Off:ctx1Off+2]) != uint16(3) {
		t.Fatalf("ctx1 should be rejected, got result %d", binary.LittleEndian.Uint16(resp[ctx1Off:ctx1Off+2]))
	}

	// A request with a PDU body that does not parse as a bind.
	bad := BuildRPCRequest([]byte{0x01}, 1)
	if _, err := BuildBindAckResponse(bad, 1688, 1); err == nil {
		t.Fatal("expected bind parse error")
	}
}

func TestBuildBindAckResponseOtherUUIDBranch(t *testing.T) {
	// Build a bind with a context using a transfer syntax that is neither
	// NDR32 nor Time, exercising the "else" branch.
	bindBody := make([]byte, 12+44)
	binary.LittleEndian.PutUint16(bindBody[0:2], 5840)
	binary.LittleEndian.PutUint16(bindBody[2:4], 5840)
	bindBody[8] = 1 // ctx_num
	// CtxItem layout: ContextID(2) TransItems(1) Pad(1) AbstractUUID(16)
	// AbstractVer(4) TransferUUID(16) TransferVer(4), starting at offset 12.
	otherAbstract := [16]byte{0xde, 0xad, 0xbe, 0xef}
	otherTransfer := [16]byte{0xaa, 0xbb, 0xcc, 0xdd}
	copy(bindBody[12:17], []byte{0, 0, 1, 0, 0}) // ctxid, transitems, pad
	copy(bindBody[16:32], otherAbstract[:])
	binary.LittleEndian.PutUint32(bindBody[32:36], 1)
	copy(bindBody[36:52], otherTransfer[:])
	binary.LittleEndian.PutUint32(bindBody[52:56], 2)

	header := MSRPCHeader{
		VerMajor: 5, VerMinor: 0, Type: PacketTypeBind, Flags: FlagFirstFrag | FlagLastFrag,
		Representation: 0x10, FragLen: uint16(MSRPCHeaderSize + len(bindBody)), AuthLen: 0, CallID: 1,
	}
	full := make([]byte, MSRPCHeaderSize+len(bindBody))
	hdrBytes := header.Marshal()
	copy(full, hdrBytes)
	copy(full[MSRPCHeaderSize:], bindBody)

	if _, err := BuildBindAckResponse(full, 1688, 1); err != nil {
		t.Fatalf("BuildBindAckResponse(other uuid) error = %v", err)
	}
}

func TestBuildBindRequestAndRPCRequest(t *testing.T) {
	req := BuildBindRequest(42)
	if len(req) < MSRPCHeaderSize {
		t.Fatal("bind request too small")
	}
	h, err := ParseMSRPCHeader(req)
	if err != nil {
		t.Fatalf("parse bind header error = %v", err)
	}
	if h.Type != PacketTypeBind || h.CallID != 42 {
		t.Fatalf("unexpected bind header: %+v", h)
	}

	rpcReq := BuildRPCRequest([]byte{1, 1, 1}, 8)
	rh, err := ParseMSRPCRequestHeader(rpcReq)
	if err != nil {
		t.Fatalf("parse rpc request header error = %v", err)
	}
	if rh.Type != PacketTypeRequest || rh.CallID != 8 {
		t.Fatalf("unexpected request header: %+v", rh)
	}
	if !bytes.Equal(rh.PDUData(rpcReq), []byte{1, 1, 1}) {
		t.Fatal("request payload mismatch")
	}
}
