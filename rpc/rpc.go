package rpc

import (
	"encoding/binary"
	"fmt"
)

// MS-RPC packet type constants.
const (
	PacketTypeRequest       = 0x00
	PacketTypePing          = 0x01
	PacketTypeResponse      = 0x02
	PacketTypeFault         = 0x03
	PacketTypeWorking       = 0x04
	PacketTypeNoCall        = 0x05
	PacketTypeReject        = 0x06
	PacketTypeAck           = 0x07
	PacketTypeCLCancel      = 0x08
	PacketTypeFAck          = 0x09
	PacketTypeCancelAck     = 0x0A
	PacketTypeBind          = 0x0B
	PacketTypeBindAck       = 0x0C
	PacketTypeBindNak       = 0x0D
	PacketTypeAlterContext  = 0x0E
	PacketTypeAlterContextR = 0x0F
	PacketTypeAuth3         = 0x10
	PacketTypeShutdown      = 0x11
	PacketTypeCOCancel      = 0x12
	PacketTypeOrphaned      = 0x13
)

// MS-RPC packet flags.
const (
	FlagFirstFrag   = 0x01
	FlagLastFrag    = 0x02
	FlagSupportSign = 0x04
	FlagPendCancel  = 0x04
	FlagReserved    = 0x08
	FlagConcMpx     = 0x10
	FlagDidNotExec  = 0x20
	FlagMaybe       = 0x40
	FlagObjectUUID  = 0x80
)

// Context result codes.
const (
	ContResultAccept     = 0
	ContResultUserReject = 1
	ContResultProvReject = 2
)

// MSRPCHeader is the common header for all MS-RPC PDUs (16 bytes).
type MSRPCHeader struct {
	VerMajor       uint8
	VerMinor       uint8
	Type           uint8
	Flags          uint8
	Representation uint32
	FragLen        uint16
	AuthLen        uint16
	CallID         uint32
}

const MSRPCHeaderSize = 16

func ParseMSRPCHeader(data []byte) (*MSRPCHeader, error) {
	if len(data) < MSRPCHeaderSize {
		return nil, fmt.Errorf("data too short for RPC header: %d", len(data))
	}
	offset := 0
	h := &MSRPCHeader{}
	h.VerMajor = data[offset]
	offset++
	h.VerMinor = data[offset]
	offset++
	h.Type = data[offset]
	offset++
	h.Flags = data[offset]
	offset++
	h.Representation = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	h.FragLen = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	h.AuthLen = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	h.CallID = binary.LittleEndian.Uint32(data[offset : offset+4])
	return h, nil
}

func (h *MSRPCHeader) Marshal() []byte {
	resp := make([]byte, MSRPCHeaderSize)
	offset := 0
	resp[offset] = h.VerMajor
	offset++
	resp[offset] = h.VerMinor
	offset++
	resp[offset] = h.Type
	offset++
	resp[offset] = h.Flags
	offset++
	binary.LittleEndian.PutUint32(resp[offset:offset+4], h.Representation)
	offset += 4
	binary.LittleEndian.PutUint16(resp[offset:offset+2], h.FragLen)
	offset += 2
	binary.LittleEndian.PutUint16(resp[offset:offset+2], h.AuthLen)
	offset += 2
	binary.LittleEndian.PutUint32(resp[offset:offset+4], h.CallID)
	return resp
}

// PDUData extracts the PDU data from a complete RPC packet.
func PDUData(data []byte) []byte {
	if len(data) <= MSRPCHeaderSize {
		return nil
	}
	header, err := ParseMSRPCHeader(data)
	if err != nil {
		return nil
	}
	end := int(header.FragLen) - int(header.AuthLen)
	if header.AuthLen > 0 {
		end -= 8 // sec_trailer
	}
	if end > len(data) {
		end = len(data)
	}
	return data[MSRPCHeaderSize:end]
}

// MSRPCRequestHeader extends MSRPCHeader with request-specific fields.
type MSRPCRequestHeader struct {
	MSRPCHeader
	AllocHint uint32
	CtxID     uint16
	OpNum     uint16
}

const MSRPCRequestHeaderSize = 24

func ParseMSRPCRequestHeader(data []byte) (*MSRPCRequestHeader, error) {
	if len(data) < MSRPCRequestHeaderSize {
		return nil, fmt.Errorf("data too short for RPC request header: %d", len(data))
	}
	offset := 0
	h := &MSRPCRequestHeader{}
	h.VerMajor = data[offset]
	offset++
	h.VerMinor = data[offset]
	offset++
	h.Type = data[offset]
	offset++
	h.Flags = data[offset]
	offset++
	h.Representation = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	h.FragLen = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	h.AuthLen = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	h.CallID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	h.AllocHint = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	h.CtxID = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	h.OpNum = binary.LittleEndian.Uint16(data[offset : offset+2])
	return h, nil
}

func (h *MSRPCRequestHeader) PDUData(fullPacket []byte) []byte {
	if len(fullPacket) <= MSRPCRequestHeaderSize {
		return nil
	}
	// Check for object UUID.
	offset := MSRPCRequestHeaderSize
	if h.Flags&FlagObjectUUID > 0 {
		offset += 16
	}
	end := int(h.FragLen) - int(h.AuthLen)
	if h.AuthLen > 0 {
		end -= 8
	}
	if end > len(fullPacket) {
		end = len(fullPacket)
	}
	if offset >= end {
		return nil
	}
	return fullPacket[offset:end]
}

// MSRPCRespHeader extends MSRPCHeader with response-specific fields.
type MSRPCRespHeader struct {
	MSRPCHeader
	AllocHint   uint32
	CtxID       uint16
	CancelCount uint8
	Padding     uint8
}

const MSRPCRespHeaderSize = 24

func BuildMSRPCResponse(reqHeader *MSRPCRequestHeader, pduData []byte) []byte {
	resp := MSRPCRespHeader{
		MSRPCHeader: MSRPCHeader{
			VerMajor:       reqHeader.VerMajor,
			VerMinor:       reqHeader.VerMinor,
			Type:           PacketTypeResponse,
			Flags:          FlagFirstFrag | FlagLastFrag,
			Representation: reqHeader.Representation,
			FragLen:        uint16(MSRPCRespHeaderSize + len(pduData)),
			AuthLen:        0,
			CallID:         reqHeader.CallID,
		},
		AllocHint:   uint32(len(pduData)),
		CtxID:       reqHeader.CtxID,
		CancelCount: 0,
		Padding:     0,
	}

	respBytes := make([]byte, MSRPCRespHeaderSize)
	offset := 0
	respBytes[offset] = resp.VerMajor
	offset++
	respBytes[offset] = resp.VerMinor
	offset++
	respBytes[offset] = resp.Type
	offset++
	respBytes[offset] = resp.Flags
	offset++
	binary.LittleEndian.PutUint32(respBytes[offset:offset+4], resp.Representation)
	offset += 4
	binary.LittleEndian.PutUint16(respBytes[offset:offset+2], resp.FragLen)
	offset += 2
	binary.LittleEndian.PutUint16(respBytes[offset:offset+2], resp.AuthLen)
	offset += 2
	binary.LittleEndian.PutUint32(respBytes[offset:offset+4], resp.CallID)
	offset += 4
	binary.LittleEndian.PutUint32(respBytes[offset:offset+4], resp.AllocHint)
	offset += 4
	binary.LittleEndian.PutUint16(respBytes[offset:offset+2], resp.CtxID)
	offset += 2
	respBytes[offset] = resp.CancelCount
	offset++
	respBytes[offset] = resp.Padding
	result := make([]byte, MSRPCRespHeaderSize+len(pduData))
	copy(result, respBytes)
	copy(result[MSRPCRespHeaderSize:], pduData)
	return result
}

// BindRequest represents an RPC BIND request body.
type BindRequest struct {
	MaxTFrag   uint16
	MaxRFrag   uint16
	AssocGroup uint32
	CtxNum     uint8
	Reserved   uint8
	Reserved2  uint16
	CtxItems   []CtxItem
}

// CtxItem represents a context item in a BIND request.
type CtxItem struct {
	ContextID          uint16
	TransItems         uint8
	Pad                uint8
	AbstractSyntaxUUID [16]byte
	AbstractSyntaxVer  uint32
	TransferSyntaxUUID [16]byte
	TransferSyntaxVer  uint32
}

const CtxItemSize = 44

func ParseBindRequest(data []byte) (*BindRequest, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("data too short for BIND request")
	}
	offset := 0
	b := &BindRequest{}
	b.MaxTFrag = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	b.MaxRFrag = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	b.AssocGroup = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	b.CtxNum = data[offset]
	offset++
	b.Reserved = data[offset]
	offset++
	b.Reserved2 = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	for i := 0; i < int(b.CtxNum); i++ {
		if offset+CtxItemSize > len(data) {
			return nil, fmt.Errorf("data too short for context item %d", i)
		}
		itemOffset := offset
		item := CtxItem{}
		item.ContextID = binary.LittleEndian.Uint16(data[itemOffset : itemOffset+2])
		itemOffset += 2
		item.TransItems = data[itemOffset]
		itemOffset++
		item.Pad = data[itemOffset]
		itemOffset++
		copy(item.AbstractSyntaxUUID[:], data[itemOffset:itemOffset+16])
		itemOffset += 16
		item.AbstractSyntaxVer = binary.LittleEndian.Uint32(data[itemOffset : itemOffset+4])
		itemOffset += 4
		copy(item.TransferSyntaxUUID[:], data[itemOffset:itemOffset+16])
		itemOffset += 16
		item.TransferSyntaxVer = binary.LittleEndian.Uint32(data[itemOffset : itemOffset+4])
		b.CtxItems = append(b.CtxItems, item)
		offset += CtxItemSize
	}

	return b, nil
}

// CtxItemResult represents a context item result in a BIND ACK.
type CtxItemResult struct {
	Result             uint16
	Reason             uint16
	TransferSyntaxUUID [16]byte
	TransferSyntaxVer  uint32
}

const CtxItemResultSize = 24

// Well-known UUIDs.
var (
	UUIDNDR32 = [16]byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
	UUIDNDR64 = [16]byte{0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36}
	UUIDTime  = [16]byte{0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	UUIDEmpty = [16]byte{}
)

// BuildBindAckResponse creates a BIND ACK response.
func BuildBindAckResponse(reqData []byte, port int, callID uint32) ([]byte, error) {
	header, err := ParseMSRPCHeader(reqData)
	if err != nil {
		return nil, err
	}

	bind, err := ParseBindRequest(PDUData(reqData))
	if err != nil {
		return nil, err
	}

	portStr := fmt.Sprintf("%d", port)
	secondaryAddrLen := uint16(len(portStr) + 1)

	// Calculate padding.
	pad := (4 - ((int(secondaryAddrLen) + 26) % 4)) % 4

	// Build ctx item results.
	var ctxResults []byte
	for i := 0; i < int(bind.CtxNum); i++ {
		tsUUID := bind.CtxItems[i].TransferSyntaxUUID
		var result CtxItemResult
		if tsUUID == UUIDNDR32 {
			result = CtxItemResult{
				Result:             ContResultAccept,
				Reason:             0,
				TransferSyntaxUUID: UUIDNDR32,
				TransferSyntaxVer:  2,
			}
		} else if tsUUID == UUIDTime {
			result = CtxItemResult{
				Result:             3,
				Reason:             3,
				TransferSyntaxUUID: UUIDEmpty,
				TransferSyntaxVer:  0,
			}
		} else {
			result = CtxItemResult{
				Result:             ContResultProvReject,
				Reason:             ContResultProvReject,
				TransferSyntaxUUID: UUIDEmpty,
				TransferSyntaxVer:  0,
			}
		}
		resultBytes := make([]byte, CtxItemResultSize)
		binary.LittleEndian.PutUint16(resultBytes[0:2], result.Result)
		binary.LittleEndian.PutUint16(resultBytes[2:4], result.Reason)
		copy(resultBytes[4:20], result.TransferSyntaxUUID[:])
		binary.LittleEndian.PutUint32(resultBytes[20:24], result.TransferSyntaxVer)
		ctxResults = append(ctxResults, resultBytes...)
	}

	// Calculate total fragment length.
	fragLen := 26 + int(secondaryAddrLen) + pad + 4 + len(ctxResults)

	// Build the response.
	resp := make([]byte, fragLen)
	offset := 0
	resp[offset] = header.VerMajor
	offset++
	resp[offset] = header.VerMinor
	offset++
	resp[offset] = PacketTypeBindAck
	offset++
	resp[offset] = FlagFirstFrag | FlagLastFrag | FlagConcMpx
	offset++
	binary.LittleEndian.PutUint32(resp[offset:offset+4], header.Representation)
	offset += 4
	binary.LittleEndian.PutUint16(resp[offset:offset+2], uint16(fragLen))
	offset += 2
	binary.LittleEndian.PutUint16(resp[offset:offset+2], header.AuthLen)
	offset += 2
	binary.LittleEndian.PutUint32(resp[offset:offset+4], callID)
	offset += 4

	// Bind ACK specific fields.
	binary.LittleEndian.PutUint16(resp[offset:offset+2], bind.MaxTFrag)
	offset += 2
	binary.LittleEndian.PutUint16(resp[offset:offset+2], bind.MaxRFrag)
	offset += 2
	binary.LittleEndian.PutUint32(resp[offset:offset+4], 0x1063bf3f) // assoc_group
	offset += 4

	// Secondary address.
	binary.LittleEndian.PutUint16(resp[offset:offset+2], secondaryAddrLen)
	offset += 2
	copy(resp[offset:], portStr)
	offset += len(portStr)
	resp[offset] = 0 // null terminator
	offset++

	// Padding.
	for range pad {
		resp[offset] = 0
		offset++
	}

	// Context results.
	resp[offset] = bind.CtxNum // ctx_num
	offset++
	resp[offset] = 0           // Reserved
	offset++
	// Reserved2 (already 0)
	offset += 2
	copy(resp[offset:], ctxResults)

	return resp, nil
}

// BuildBindRequest creates a BIND request for the client.
func BuildBindRequest(callID uint32) []byte {
	kmsUUID := [16]byte{0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06}

	// Build bind body directly.
	bindBody := make([]byte, 5840*0+CtxItemSize*2)
	offset := 0
	binary.LittleEndian.PutUint16(bindBody[offset:offset+2], 5840) // max_tfrag
	offset += 2
	binary.LittleEndian.PutUint16(bindBody[offset:offset+2], 5840) // max_rfrag
	offset += 2
	binary.LittleEndian.PutUint32(bindBody[offset:offset+4], 0)    // assoc_group
	offset += 4
	bindBody[offset] = 2                                           // ctx_num
	offset++
	bindBody[offset] = 0                                           // Reserved
	offset++
	// Reserved2
	offset += 2

	// First context item.
	copy(bindBody[offset:offset+2], []byte{0, 0})                  // ContextID
	offset += 2
	bindBody[offset] = 1                                           // TransItems
	offset++
	bindBody[offset] = 0                                           // Pad
	offset++
	copy(bindBody[offset:offset+16], kmsUUID[:])                   // AbstractSyntaxUUID
	offset += 16
	binary.LittleEndian.PutUint32(bindBody[offset:offset+4], 1)    // AbstractSyntaxVer
	offset += 4
	copy(bindBody[offset:offset+16], UUIDNDR32[:])                 // TransferSyntaxUUID
	offset += 16
	binary.LittleEndian.PutUint32(bindBody[offset:offset+4], 2)    // TransferSyntaxVer
	offset += 4

	// Second context item.
	copy(bindBody[offset:offset+2], []byte{1, 0})                  // ContextID
	offset += 2
	bindBody[offset] = 1                                           // TransItems
	offset++
	bindBody[offset] = 0                                           // Pad
	offset++
	copy(bindBody[offset:offset+16], kmsUUID[:])                   // AbstractSyntaxUUID
	offset += 16
	binary.LittleEndian.PutUint32(bindBody[offset:offset+4], 1)    // AbstractSyntaxVer
	offset += 4
	copy(bindBody[offset:offset+16], UUIDTime[:])                  // TransferSyntaxUUID
	offset += 16
	binary.LittleEndian.PutUint32(bindBody[offset:offset+4], 1)    // TransferSyntaxVer
	offset += 4

	pduData := bindBody[:offset]

	// Build full packet.
	totalLen := MSRPCHeaderSize + len(pduData)
	resp := make([]byte, totalLen)
	offset = 0
	resp[offset] = 5                                               // VerMajor
	offset++
	resp[offset] = 0                                               // VerMinor
	offset++
	resp[offset] = PacketTypeBind
	offset++
	resp[offset] = FlagFirstFrag | FlagLastFrag | FlagConcMpx
	offset++
	binary.LittleEndian.PutUint32(resp[offset:offset+4], 0x10)     // Representation
	offset += 4
	binary.LittleEndian.PutUint16(resp[offset:offset+2], uint16(totalLen)) // FragLen
	offset += 2
	binary.LittleEndian.PutUint16(resp[offset:offset+2], 0)        // AuthLen
	offset += 2
	binary.LittleEndian.PutUint32(resp[offset:offset+4], callID)   // CallID
	copy(resp[offset:], pduData)
	return resp
}

// BuildRPCRequest creates an RPC REQUEST packet wrapping the given KMS data.
func BuildRPCRequest(kmsData []byte, callID uint32) []byte {
	totalLen := MSRPCRequestHeaderSize + len(kmsData)
	resp := make([]byte, totalLen)
	offset := 0
	resp[offset] = 5                                               // VerMajor
	offset++
	resp[offset] = 0                                               // VerMinor
	offset++
	resp[offset] = PacketTypeRequest
	offset++
	resp[offset] = FlagFirstFrag | FlagLastFrag
	offset++
	binary.LittleEndian.PutUint32(resp[offset:offset+4], 0x10)     // Representation
	offset += 4
	binary.LittleEndian.PutUint16(resp[offset:offset+2], uint16(totalLen)) // FragLen
	offset += 2
	binary.LittleEndian.PutUint16(resp[offset:offset+2], 0)        // AuthLen
	offset += 2
	binary.LittleEndian.PutUint32(resp[offset:offset+4], callID)   // CallID
	offset += 4
	binary.LittleEndian.PutUint32(resp[offset:offset+4], uint32(len(kmsData))) // AllocHint
	offset += 4
	binary.LittleEndian.PutUint16(resp[offset:offset+2], 0)        // CtxID
	offset += 2
	binary.LittleEndian.PutUint16(resp[offset:offset+2], 0)        // OpNum
	copy(resp[offset:], kmsData)
	return resp
}
