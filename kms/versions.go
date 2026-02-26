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

	buf := bytes.NewReader(data)
	var bodyLength1, bodyLength2 uint32
	binary.Read(buf, binary.LittleEndian, &bodyLength1)
	binary.Read(buf, binary.LittleEndian, &bodyLength2)

	// The remaining data contains the KMS request + hash + padding.
	remaining := data[8:]
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

	var resp bytes.Buffer
	binary.Write(&resp, binary.LittleEndian, bodyLength)               // bodyLength1
	binary.Write(&resp, binary.BigEndian, uint32(0x00000200))          // unknown (big-endian per py-kms)
	binary.Write(&resp, binary.LittleEndian, bodyLength)               // bodyLength2
	resp.Write(responseBytes)
	resp.Write(theHash)
	resp.Write(padding)

	log.Printf("KMS V4 Response generated")
	return resp.Bytes(), nil
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

	buf := bytes.NewReader(data)
	var bodyLength1, bodyLength2 uint32
	var versionMinor, versionMajor uint16
	binary.Read(buf, binary.LittleEndian, &bodyLength1)
	binary.Read(buf, binary.LittleEndian, &bodyLength2)
	binary.Read(buf, binary.LittleEndian, &versionMinor)
	binary.Read(buf, binary.LittleEndian, &versionMajor)

	// Message data starts after bodyLength1(4) + bodyLength2(4) + versionMinor(2) + versionMajor(2)
	messageData := data[12:]
	// The ciphertext length is bodyLength - 4 (versionMinor + versionMajor)
	ciphertextLen := int(bodyLength1) - 4
	if len(messageData) < ciphertextLen || ciphertextLen < 16 {
		return nil, fmt.Errorf("V5/V6 message too short: %d (need %d)", len(messageData), ciphertextLen)
	}

	salt := messageData[:16]

	// Select key.
	var key []byte
	if isV6 {
		key = crypto.V6Key
	} else {
		key = crypto.V5Key
	}

	// Decrypt the entire ciphertext using the first 16 bytes (salt) as IV,
	// matching the Python py-kms behavior.
	iv := make([]byte, 16)
	copy(iv, salt)
	decrypted, err := crypto.AESDecryptCBC(messageData[:ciphertextLen], key, iv, isV6)
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
	for i := 0; i < 16; i++ {
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
		for i := 0; i < 16; i++ {
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
		dsaltS, err := crypto.AESDecryptCBC(saltS, key, ivS, true)
		if err != nil {
			return nil, fmt.Errorf("failed to generate DSaltS: %w", err)
		}

		// HMacMsg = (SaltS ^ DSaltS) + message
		hmacMsg := make([]byte, 16)
		for i := 0; i < 16; i++ {
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
		encryptedResp, err := crypto.AESEncryptCBC(padded, key, ivEnc, true)
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
	encryptedResp, err := crypto.AESEncryptCBC(padded, key, ivEnc, false)
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

	var resp bytes.Buffer
	binary.Write(&resp, binary.LittleEndian, bodyLength)         // bodyLength1
	binary.Write(&resp, binary.BigEndian, uint32(0x00000200))    // unknown (big-endian per py-kms)
	binary.Write(&resp, binary.LittleEndian, bodyLength)         // bodyLength2
	binary.Write(&resp, binary.LittleEndian, versionMinor)
	binary.Write(&resp, binary.LittleEndian, versionMajor)
	resp.Write(iv)
	resp.Write(encrypted)
	resp.Write(padding)

	return resp.Bytes()
}
