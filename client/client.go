package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"go-kms/crypto"
	"go-kms/kms"
	"go-kms/rpc"
	"go-kms/server"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
	"unicode/utf16"
)

// ClientConfig holds client configuration.
type ClientConfig struct {
	IP      string
	Port    int
	Mode    string
	CMID    string
	Machine string
}

func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		IP:   "127.0.0.1",
		Port: 1688,
		Mode: "Windows8.1",
	}
}

// ProductInfo contains the product details for activation.
type ProductInfo struct {
	SkuID       string
	AppID       string
	KmsCountID  string
	ProtoMajor  uint16
	ProtoMinor  uint16
	ClientCount uint32
}

// Product configurations (from KmsDataBase.xml).
var Products = map[string]ProductInfo{
	"WindowsVista": {
		SkuID: "cfd8ff08-c0d7-452b-9f60-ef5c70c32094", AppID: "55c92734-d682-4d71-983e-d6ec3f16059f",
		KmsCountID: "212a64dc-43b1-4d3d-a30c-2fc69d2095c6", ProtoMajor: 4, ClientCount: 25,
	},
	"Windows7": {
		SkuID: "ae2ee509-1b34-41c0-acb7-6d4650168915", AppID: "55c92734-d682-4d71-983e-d6ec3f16059f",
		KmsCountID: "7fde5219-fbfa-484a-82c9-34d1ad53e856", ProtoMajor: 4, ClientCount: 25,
	},
	"Windows8": {
		SkuID: "458e1bec-837a-45f6-b9d5-925ed5d299de", AppID: "55c92734-d682-4d71-983e-d6ec3f16059f",
		KmsCountID: "3c40b358-5948-45af-923b-53d21fcc7e79", ProtoMajor: 5, ClientCount: 25,
	},
	"Windows8.1": {
		SkuID: "81671aaf-79d1-4eb1-b004-8cbbe173afea", AppID: "55c92734-d682-4d71-983e-d6ec3f16059f",
		KmsCountID: "cb8fc780-2c05-495a-9710-85afffc904d7", ProtoMajor: 6, ClientCount: 25,
	},
	"Windows10": {
		SkuID: "73111121-5571-4dd9-98a7-44d8780b9385", AppID: "55c92734-d682-4d71-983e-d6ec3f16059f",
		KmsCountID: "58e2134f-8e11-4d17-9cb2-91069c151148", ProtoMajor: 6, ClientCount: 25,
	},
	"Office2010": {
		SkuID: "6f327760-8c5c-417c-9b61-836a98287e0c", AppID: "59a52881-a989-479d-af46-f275c6370663",
		KmsCountID: "e85af946-2e25-47b7-83e1-bebcebeac611", ProtoMajor: 4, ClientCount: 5,
	},
	"Office2013": {
		SkuID: "b322da9c-a2e2-4058-9e4e-f59a6970bd69", AppID: "0ff1ce15-a989-479d-af46-f275c6370663",
		KmsCountID: "e6a6f1bf-9d40-40c3-aa9f-c77ba21578c0", ProtoMajor: 5, ClientCount: 5,
	},
	"Office2016": {
		SkuID: "d450596f-894d-49e0-966a-fd39ed4c4c64", AppID: "0ff1ce15-a989-479d-af46-f275c6370663",
		KmsCountID: "85b5f61b-320b-4be3-814a-b76b2bfafc82", ProtoMajor: 6, ClientCount: 5,
	},
	"Office2019": {
		SkuID: "0bc88885-718c-491d-921f-6f214349e79c", AppID: "0ff1ce15-a989-479d-af46-f275c6370663",
		KmsCountID: "617d9eb1-ef36-4f87-bbfb-481cbb3af187", ProtoMajor: 6, ClientCount: 5,
	},
}

// Run executes the KMS client.
func Run(config *ClientConfig) error {
	product, ok := Products[config.Mode]
	if !ok {
		return fmt.Errorf("unknown product mode: %s", config.Mode)
	}

	// Generate CMID if not provided.
	cmid := config.CMID
	if cmid == "" {
		cmid = kms.RandomUUID().String()
	}

	// Generate machine name if not provided.
	machine := config.Machine
	if machine == "" {
		machine = randomMachineName()
	}

	log.Printf("Connecting to %s:%d", config.IP, config.Port)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", config.IP, config.Port), 10*time.Second)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()
	log.Printf("Connection successful")

	// Send RPC BIND.
	bindRequest := rpc.BuildBindRequest(1)
	if _, err := conn.Write(bindRequest); err != nil {
		return fmt.Errorf("failed to send bind request: %w", err)
	}

	// Receive BIND ACK.
	bindAck, err := server.RecvAll(conn)
	if err != nil {
		return fmt.Errorf("failed to receive bind ack: %w", err)
	}

	bindAckHeader, err := rpc.ParseMSRPCHeader(bindAck)
	if err != nil {
		return fmt.Errorf("failed to parse bind ack: %w", err)
	}
	if bindAckHeader.Type != rpc.PacketTypeBindAck {
		return fmt.Errorf("expected bind ack, got type 0x%02x", bindAckHeader.Type)
	}
	log.Printf("RPC bind acknowledged")

	// Build KMS request.
	kmsRequestData, err := buildKMSRequest(product, cmid, machine)
	if err != nil {
		return fmt.Errorf("failed to build KMS request: %w", err)
	}

	// Wrap in version-specific envelope.
	var envelopedData []byte
	switch product.ProtoMajor {
	case 4:
		envelopedData = buildV4ClientRequest(kmsRequestData)
	case 5:
		envelopedData, err = buildV5ClientRequest(kmsRequestData, product.ProtoMinor, product.ProtoMajor)
	case 6:
		envelopedData, err = buildV6ClientRequest(kmsRequestData, product.ProtoMinor, product.ProtoMajor)
	default:
		return fmt.Errorf("unsupported protocol version: %d", product.ProtoMajor)
	}
	if err != nil {
		return fmt.Errorf("failed to build versioned request: %w", err)
	}

	// Send RPC REQUEST.
	rpcRequest := rpc.BuildRPCRequest(envelopedData, 2)
	if _, err := conn.Write(rpcRequest); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Receive response.
	respData, err := server.RecvAll(conn)
	if err != nil {
		return fmt.Errorf("failed to receive response: %w", err)
	}

	respHeader, err := rpc.ParseMSRPCRequestHeader(respData)
	if err != nil {
		return fmt.Errorf("failed to parse response header: %w", err)
	}

	pduData := respHeader.PDUData(respData)
	if pduData == nil {
		return fmt.Errorf("failed to extract response PDU data")
	}

	// Parse the version-specific response.
	switch product.ProtoMajor {
	case 4:
		return parseV4Response(pduData)
	case 5:
		return parseV5Response(pduData)
	case 6:
		return parseV6Response(pduData)
	}

	return nil
}

func buildKMSRequest(product ProductInfo, cmid, machine string) ([]byte, error) {
	skuID := kms.MustUUID(product.SkuID)
	appID := kms.MustUUID(product.AppID)
	kmsCountID := kms.MustUUID(product.KmsCountID)
	clientMachineID := kms.MustUUID(cmid)

	// Encode machine name to UTF-16LE with null terminator.
	machineUTF16 := utf16.Encode([]rune(machine))
	machineBytes := make([]byte, len(machineUTF16)*2+2) // +2 for UTF-16LE null terminator
	for i, v := range machineUTF16 {
		binary.LittleEndian.PutUint16(machineBytes[i*2:], v)
	}
	// machineBytes[len(machineUTF16)*2] and [len(machineUTF16)*2+1] are already 0 (null terminator)

	// Pad to fill 128 bytes total (machineName + null + padding, matching py-kms 'u' format + mnPad).
	paddedMachine := make([]byte, 128)
	copy(paddedMachine, machineBytes)

	now := time.Now().UTC()
	requestTime := kms.TimeToFileTime(now)

	req := &kms.KMSRequest{
		VersionMinor:        product.ProtoMinor,
		VersionMajor:        product.ProtoMajor,
		IsClientVM:          0,
		LicenseStatus:       2, // Grace Period
		GraceTime:           43200 * 2,
		ApplicationID:       appID,
		SKUID:               skuID,
		KMSCountedID:        kmsCountID,
		ClientMachineID:     clientMachineID,
		RequiredClientCount: product.ClientCount,
		RequestTime:         uint64(requestTime),
		MachineNameRaw:      paddedMachine,
	}

	return req.Marshal(), nil
}

func buildV4ClientRequest(kmsData []byte) []byte {
	hash := crypto.V4Hash(kmsData)
	bodyLength := uint32(len(kmsData) + len(hash))
	padding := make([]byte, kms.GetPadding(int(bodyLength)))

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, bodyLength)
	binary.Write(&buf, binary.LittleEndian, bodyLength)
	buf.Write(kmsData)
	buf.Write(hash)
	buf.Write(padding)
	return buf.Bytes()
}

func buildV5ClientRequest(kmsData []byte, versionMinor, versionMajor uint16) ([]byte, error) {
	return buildV5V6ClientRequest(kmsData, versionMinor, versionMajor, false)
}

func buildV6ClientRequest(kmsData []byte, versionMinor, versionMajor uint16) ([]byte, error) {
	return buildV5V6ClientRequest(kmsData, versionMinor, versionMajor, true)
}

func buildV5V6ClientRequest(kmsData []byte, versionMinor, versionMajor uint16, isV6 bool) ([]byte, error) {
	var key []byte
	if isV6 {
		key = crypto.V6Key
	} else {
		key = crypto.V5Key
	}

	esalt := crypto.RandomSalt()
	iv := make([]byte, 16)
	copy(iv, esalt)

	// Decrypt esalt to get dsalt.
	dsalt, err := crypto.AESDecryptCBC(esalt, key, iv, isV6)
	if err != nil {
		return nil, err
	}

	// Build decrypted request: dsalt + kmsRequest.
	var decrypted bytes.Buffer
	decrypted.Write(dsalt[:16])
	decrypted.Write(kmsData)

	// Encrypt.
	padded := crypto.PKCS7Pad(decrypted.Bytes(), 16)
	encIV := make([]byte, 16)
	copy(encIV, esalt)
	encrypted, err := crypto.AESEncryptCBC(padded, key, encIV, isV6)
	if err != nil {
		return nil, err
	}

	// The message IS the ciphertext (no separate esalt prefix).
	// The server treats the first 16 bytes of ciphertext as the "salt" field,
	// matching py-kms behavior where Message.salt = ciphertext[:16].
	bodyLength := uint32(2 + 2 + len(encrypted))

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, bodyLength)
	binary.Write(&buf, binary.LittleEndian, bodyLength)
	binary.Write(&buf, binary.LittleEndian, versionMinor)
	binary.Write(&buf, binary.LittleEndian, versionMajor)
	buf.Write(encrypted)

	return buf.Bytes(), nil
}

func parseV4Response(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("V4 response too short")
	}
	buf := bytes.NewReader(data)
	var bodyLength1 uint32
	var unknown uint32
	var bodyLength2 uint32
	binary.Read(buf, binary.LittleEndian, &bodyLength1)
	binary.Read(buf, binary.LittleEndian, &unknown)
	binary.Read(buf, binary.LittleEndian, &bodyLength2)

	remaining := data[12:]
	if int(bodyLength2) > len(remaining)+16 {
		return fmt.Errorf("V4 response body too short")
	}

	responseData := remaining[:bodyLength2-16]
	resp, err := kms.ParseKMSResponse(responseData)
	if err != nil {
		return fmt.Errorf("failed to parse KMS response: %w", err)
	}

	printResponse(resp)
	return nil
}

func parseV5Response(data []byte) error {
	return parseV5V6Response(data, false)
}

func parseV6Response(data []byte) error {
	return parseV5V6Response(data, true)
}

func parseV5V6Response(data []byte, isV6 bool) error {
	if len(data) < 12 {
		return fmt.Errorf("V5/V6 response too short")
	}

	buf := bytes.NewReader(data)
	var bodyLength1 uint32
	var unknown uint32
	var bodyLength2 uint32
	var versionMinor, versionMajor uint16
	binary.Read(buf, binary.LittleEndian, &bodyLength1)
	binary.Read(buf, binary.LittleEndian, &unknown)
	binary.Read(buf, binary.LittleEndian, &bodyLength2)
	binary.Read(buf, binary.LittleEndian, &versionMinor)
	binary.Read(buf, binary.LittleEndian, &versionMajor)

	remaining := data[16:]
	if len(remaining) < 16 {
		return fmt.Errorf("V5/V6 response missing salt")
	}

	salt := remaining[:16]
	paddingLen := kms.GetPadding(int(bodyLength1))
	encryptedEnd := len(remaining) - paddingLen
	if encryptedEnd <= 16 {
		return fmt.Errorf("V5/V6 response encrypted data too short")
	}
	encrypted := remaining[16:encryptedEnd]

	var key []byte
	if isV6 {
		key = crypto.V6Key
	} else {
		key = crypto.V5Key
	}

	iv := make([]byte, 16)
	copy(iv, salt)
	decrypted, err := crypto.AESDecryptCBC(encrypted, key, iv, isV6)
	if err != nil {
		return fmt.Errorf("failed to decrypt response: %w", err)
	}

	decrypted, err = crypto.PKCS7Unpad(decrypted)
	if err != nil {
		return fmt.Errorf("failed to unpad response: %w", err)
	}

	// Parse the decrypted response.
	resp, err := kms.ParseKMSResponse(decrypted)
	if err != nil {
		return fmt.Errorf("failed to parse KMS response: %w", err)
	}

	printResponse(resp)

	// Wire format response size: VersionMinor(2) + VersionMajor(2) + EPIDLen(4) + Epid(EPIDLen) + ClientMachineID(16) + ResponseTime(8) + CurrentClientCount(4) + VLActivationInterval(4) + VLRenewalInterval(4)
	respLen := 44 + int(resp.EPIDLen)

	if isV6 {
		// V6 has additional fields after the response: keys(16) + hash(32) + hwid(8) + xorSalts(16) + hmac(16)
		hwidOffset := respLen + 16 + 32 // keys(16) + hash(32)
		if len(decrypted) >= hwidOffset+8 {
			hwid := decrypted[hwidOffset : hwidOffset+8]
			log.Printf("  HWID: %X", hwid)
		}
	} else {
		// V5 has additional fields: keys(16) + hash(32)
		// Verify hash.
		if len(decrypted) > respLen+16 {
			randomKeys := decrypted[respLen : respLen+16]
			hashInResp := decrypted[respLen+16 : respLen+48]
			_ = randomKeys

			// The hash should be SHA256 of the randomSalt used by server.
			// We can't verify without knowing the randomSalt, but we can check format.
			if len(hashInResp) == 32 {
				log.Printf("V5 SHA256 hash present (%d bytes)", len(hashInResp))
			}
		}
	}

	return nil
}

func printResponse(resp *kms.KMSResponse) {
	epid := kms.DecodeUTF16LE(resp.KMSEpid)
	log.Printf("=== KMS Response ===")
	log.Printf("  ePID: %s", epid)
	log.Printf("  Client Machine ID: %s", resp.ClientMachineID)
	log.Printf("  Response Time: %s", kms.FileTimeToTime(int64(resp.ResponseTime)))
	log.Printf("  Current Client Count: %d", resp.CurrentClientCount)
	log.Printf("  VL Activation Interval: %d minutes", resp.VLActivationInterval)
	log.Printf("  VL Renewal Interval: %d minutes", resp.VLRenewalInterval)
}

func randomMachineName() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	name := make([]byte, 8+rand.Intn(8))
	for i := range name {
		name[i] = chars[rand.Intn(len(chars))]
	}
	return strings.ToUpper(string(name))
}

// verifyV5Hash is used to verify the V5 response hash (not used in server-only mode).
func verifyV5Hash(randomSalt, hashInResp []byte) bool {
	expected := sha256.Sum256(randomSalt)
	return bytes.Equal(expected[:], hashInResp)
}
