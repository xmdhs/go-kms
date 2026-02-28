package kms

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/xmdhs/go-kms/crypto"
	"github.com/xmdhs/go-kms/logger"
)

// HandleV4Request processes a KMS V4 request.
func HandleV4Request(ctx context.Context, data []byte, config *ServerConfig) ([]byte, error) {
	// Parse V4 request: bodyLength1(4) + bodyLength2(4) + kmsRequest + hash(16) + padding
	if len(data) < 8 {
		return nil, fmt.Errorf("V4 request too short")
	}

	offset := 0
	bodyLength1 := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	offset += 4 // skip bodyLength2

	// The remaining data contains the KMS request + hash + padding.
	remaining := data[offset:]
	if int(bodyLength1) > len(remaining) {
		return nil, fmt.Errorf("V4 body length mismatch")
	}

	// The hash is the last 16 bytes of the body.
	requestData := remaining[:bodyLength1-16]
	// hash := remaining[bodyLength1-16 : bodyLength1]

	kmsRequest, err := ParseKMSRequest(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS request: %w", err)
	}

	response := ServerLogic(ctx, kmsRequest, config)
	responseBytes := response.Marshal()

	// Generate V4 hash.
	theHash := crypto.V4Hash(responseBytes)

	// Build V4 response.
	bodyLength := uint32(len(responseBytes) + len(theHash))
	padding := make([]byte, GetPadding(int(bodyLength)))

	resp := make([]byte, 4+4+4+len(responseBytes)+len(theHash)+len(padding))
	offset = 0
	binary.LittleEndian.PutUint32(resp[offset:], bodyLength)
	offset += 4
	binary.BigEndian.PutUint32(resp[offset:], uint32(0x00000200))
	offset += 4
	binary.LittleEndian.PutUint32(resp[offset:], bodyLength)
	offset += 4
	copy(resp[offset:], responseBytes)
	offset += len(responseBytes)
	copy(resp[offset:], theHash)
	offset += len(theHash)
	copy(resp[offset:], padding)

	logger.Debug(ctx, "KMS V4 response generated")
	return resp, nil
}

// HandleV5Request processes a KMS V5 request.
func HandleV5Request(ctx context.Context, data []byte, config *ServerConfig) ([]byte, error) {
	return handleV5V6Request(ctx, data, config, false)
}

// HandleV6Request processes a KMS V6 request.
func HandleV6Request(ctx context.Context, data []byte, config *ServerConfig) ([]byte, error) {
	return handleV5V6Request(ctx, data, config, true)
}

func handleV5V6Request(ctx context.Context, data []byte, config *ServerConfig, isV6 bool) ([]byte, error) {
	// Parse request header.
	if len(data) < 12 {
		return nil, fmt.Errorf("V5/V6 request too short")
	}

	offset := 0
	bodyLength1 := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	offset += 4 // skip bodyLength2
	versionMinor := binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	versionMajor := binary.LittleEndian.Uint16(data[offset:])
	offset += 2

	// Message data starts after bodyLength1(4) + bodyLength2(4) + versionMinor(2) + versionMajor(2)
	messageData := data[offset:]
	// The ciphertext length is bodyLength - 4 (versionMinor + versionMajor)
	ciphertextLen := int(bodyLength1) - 4
	if len(messageData) < ciphertextLen || ciphertextLen < 16 {
		return nil, fmt.Errorf("V5/V6 message too short: %d (need %d)", len(messageData), ciphertextLen)
	}

	salt := messageData[:16]

	// Decrypt the entire ciphertext using the first 16 bytes (salt) as IV,
	// matching the Python py-kms behavior.
	decrypted, err := crypto.KMSDecryptCBC(messageData[:ciphertextLen], salt, isV6)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt request: %w", err)
	}

	decrypted, err = crypto.PKCS7Unpad(decrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad request: %w", err)
	}

	// Decrypted request: decryptedSalt(16) + kmsRequest
	if len(decrypted) < 16 {
		return nil, fmt.Errorf("decrypted data too short")
	}
	decryptedSalt := decrypted[:16]
	kmsRequestData := decrypted[16:]

	kmsRequest, err := ParseKMSRequest(kmsRequestData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS request: %w", err)
	}

	response := ServerLogic(ctx, kmsRequest, config)
	responseBytes := response.Marshal()

	// Encrypt response.
	randomSalt := crypto.RandomSalt()
	hashResult := sha256.Sum256(randomSalt)

	if isV6 {
		// Build messageBytes: response + randomStuff(16) + hash(32) + hwid + xorSalts(16)
		msgLen := len(responseBytes) + 16 + 32 + len(config.HWID) + 16
		messageBytes := make([]byte, msgLen)
		off := copy(messageBytes, responseBytes)
		// Compute randomStuff directly into messageBytes.
		for i := range 16 {
			messageBytes[off+i] = salt[i] ^ decryptedSalt[i] ^ randomSalt[i]
		}
		off += 16
		copy(messageBytes[off:], hashResult[:])
		off += 32
		copy(messageBytes[off:], config.HWID)
		off += len(config.HWID)
		// Compute xorSalts directly into messageBytes.
		for i := range 16 {
			messageBytes[off+i] = salt[i] ^ decryptedSalt[i]
		}

		// Generate SaltS and DSaltS for HMAC.
		saltS := crypto.RandomSalt()
		dsaltS, err := crypto.KMSDecryptCBC(saltS, saltS, true)
		if err != nil {
			return nil, fmt.Errorf("failed to generate DSaltS: %w", err)
		}

		// HMacMsg = (SaltS ^ DSaltS) + messageBytes
		hmacMsg := make([]byte, 16+len(messageBytes))
		for i := range 16 {
			hmacMsg[i] = saltS[i] ^ dsaltS[i]
		}
		copy(hmacMsg[16:], messageBytes)

		// HMacKey from request time.
		hmacKey := crypto.V6MACKey(kmsRequest.RequestTime)
		hmacDigest := crypto.V6HMAC(hmacKey, hmacMsg)

		// Build full decrypted response: messageBytes + hmacDigest[16:]
		responseDataBuf := make([]byte, len(messageBytes)+16)
		copy(responseDataBuf, messageBytes)
		copy(responseDataBuf[len(messageBytes):], hmacDigest[16:])

		// Encrypt with SaltS as IV.
		padded := crypto.PKCS7Pad(responseDataBuf, 16)
		encryptedResp, err := crypto.KMSEncryptCBC(padded, saltS, true)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt V6 response: %w", err)
		}

		return buildV5V6Response(versionMinor, versionMajor, saltS, encryptedResp), nil
	}

	// V5: responseData = response + randomStuff(16) + hash(32)
	rdLen := len(responseBytes) + 16 + 32
	responseDataBuf := make([]byte, rdLen)
	off := copy(responseDataBuf, responseBytes)
	// Compute randomStuff directly into responseDataBuf.
	for i := range 16 {
		responseDataBuf[off+i] = decryptedSalt[i] ^ salt[i] ^ randomSalt[i]
	}
	off += 16
	copy(responseDataBuf[off:], hashResult[:])

	padded := crypto.PKCS7Pad(responseDataBuf, 16)
	encryptedResp, err := crypto.KMSEncryptCBC(padded, salt, false)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt V5 response: %w", err)
	}

	logger.Debug(ctx, "KMS V5 response generated")
	return buildV5V6Response(versionMinor, versionMajor, salt, encryptedResp), nil
}

func buildV5V6Response(versionMinor, versionMajor uint16, iv, encrypted []byte) []byte {
	bodyLength := uint32(2 + 2 + len(iv) + len(encrypted))
	padding := make([]byte, GetPadding(int(bodyLength)))

	resp := make([]byte, 4+4+4+2+2+len(iv)+len(encrypted)+len(padding))
	offset := 0
	binary.LittleEndian.PutUint32(resp[offset:], bodyLength)
	offset += 4
	binary.BigEndian.PutUint32(resp[offset:], uint32(0x00000200))
	offset += 4
	binary.LittleEndian.PutUint32(resp[offset:], bodyLength)
	offset += 4
	binary.LittleEndian.PutUint16(resp[offset:], versionMinor)
	offset += 2
	binary.LittleEndian.PutUint16(resp[offset:], versionMajor)
	offset += 2
	copy(resp[offset:], iv)
	offset += len(iv)
	copy(resp[offset:], encrypted)
	offset += len(encrypted)
	copy(resp[offset:], padding)

	return resp
}
