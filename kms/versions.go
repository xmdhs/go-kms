package kms

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"go-kms/crypto"
	"log"
)

// HandleV4Request processes a KMS V4 request.
func HandleV4Request(data []byte, config *ServerConfig) ([]byte, error) {
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

	response := ServerLogic(kmsRequest, config)
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

	log.Printf("KMS V4 Response generated")
	return resp, nil
}

// HandleV5Request processes a KMS V5 request.
func HandleV5Request(data []byte, config *ServerConfig) ([]byte, error) {
	return handleV5V6Request(data, config, false)
}

// HandleV6Request processes a KMS V6 request.
func HandleV6Request(data []byte, config *ServerConfig) ([]byte, error) {
	return handleV5V6Request(data, config, true)
}

func handleV5V6Request(data []byte, config *ServerConfig, isV6 bool) ([]byte, error) {
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
	iv := make([]byte, 16)
	copy(iv, salt)
	decrypted, err := crypto.KMSDecryptCBC(messageData[:ciphertextLen], iv, isV6)
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

	response := ServerLogic(kmsRequest, config)
	responseBytes := response.Marshal()

	// Encrypt response.
	randomSalt := crypto.RandomSalt()
	hashResult := sha256.Sum256(randomSalt)

	// Calculate randomStuff = SaltC ^ DSaltC ^ randomSalt
	randomStuff := make([]byte, 16)
	for i := range 16 {
		if isV6 {
			randomStuff[i] = salt[i] ^ decryptedSalt[i] ^ randomSalt[i]
		} else {
			randomStuff[i] = decryptedSalt[i] ^ salt[i] ^ randomSalt[i]
		}
	}

	var responseData bytes.Buffer

	if isV6 {
		// V6: response + keys(16) + hash(32) + hwid(8) + xorSalts(16) + hmac(16)
		xorSalts := make([]byte, 16)
		for i := range 16 {
			xorSalts[i] = salt[i] ^ decryptedSalt[i]
		}

		// Build message part.
		var message bytes.Buffer
		message.Write(responseBytes)
		message.Write(randomStuff)
		message.Write(hashResult[:])
		message.Write(config.HWID)
		message.Write(xorSalts)
		messageBytes := message.Bytes()

		// Generate SaltS and DSaltS for HMAC.
		saltS := crypto.RandomSalt()
		ivS := make([]byte, 16)
		copy(ivS, saltS)
		dsaltS, err := crypto.KMSDecryptCBC(saltS, ivS, true)
		if err != nil {
			return nil, fmt.Errorf("failed to generate DSaltS: %w", err)
		}

		// HMacMsg = (SaltS ^ DSaltS) + message
		hmacMsg := make([]byte, 16)
		for i := range 16 {
			hmacMsg[i] = saltS[i] ^ dsaltS[i]
		}
		hmacMsg = append(hmacMsg, messageBytes...)

		// HMacKey from request time.
		hmacKey := crypto.V6MACKey(kmsRequest.RequestTime)
		hmacDigest := crypto.V6HMAC(hmacKey, hmacMsg)

		// Build full decrypted response.
		responseData.Write(messageBytes)
		responseData.Write(hmacDigest[16:]) // Last 16 bytes of HMAC

		// Encrypt with SaltS as IV.
		padded := crypto.PKCS7Pad(responseData.Bytes(), 16)
		ivEnc := make([]byte, 16)
		copy(ivEnc, saltS)
		encryptedResp, err := crypto.KMSEncryptCBC(padded, ivEnc, true)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt V6 response: %w", err)
		}

		return buildV5V6Response(versionMinor, versionMajor, saltS, encryptedResp), nil
	}

	// V5: response + keys(16) + hash(32)
	responseData.Write(responseBytes)
	responseData.Write(randomStuff)
	responseData.Write(hashResult[:])

	padded := crypto.PKCS7Pad(responseData.Bytes(), 16)
	ivEnc := make([]byte, 16)
	copy(ivEnc, salt)
	encryptedResp, err := crypto.KMSEncryptCBC(padded, ivEnc, false)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt V5 response: %w", err)
	}

	ver := 5
	if isV6 {
		ver = 6
	}
	log.Printf("KMS V%d Response generated", ver)
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
