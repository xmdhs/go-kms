package server

import (
	"encoding/binary"
	"fmt"
	"go-kms/kms"
	"go-kms/rpc"
	"io"
	"log"
	"net"
)

// KMSServer is a TCP server that handles KMS activation requests.
type KMSServer struct {
	Config   *kms.ServerConfig
	listener net.Listener
}

func NewKMSServer(config *kms.ServerConfig) *KMSServer {
	return &KMSServer{Config: config}
}

func (s *KMSServer) ListenAndServe() error {
	addr := fmt.Sprintf("%s:%d", s.Config.IP, s.Config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener
	log.Printf("KMS Server listening on %s", addr)
	log.Printf("HWID: %X", s.Config.HWID)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *KMSServer) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *KMSServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("Connection accepted: %s", remoteAddr)

	for {
		// Read a complete RPC message using frag_len from the header.
		data, err := RecvAll(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from %s: %v", remoteAddr, err)
			}
			break
		}
		if len(data) == 0 {
			log.Printf("No data received from %s", remoteAddr)
			break
		}

		// Parse RPC header to determine packet type.
		header, err := rpc.ParseMSRPCHeader(data)
		if err != nil {
			log.Printf("Failed to parse RPC header: %v", err)
			break
		}

		var response []byte

		switch header.Type {
		case rpc.PacketTypeBind:
			log.Printf("RPC bind request received from %s", remoteAddr)
			response, err = rpc.BuildBindAckResponse(data, s.Config.Port, header.CallID)
			if err != nil {
				log.Printf("Failed to build bind ack: %v", err)
				break
			}
			log.Printf("RPC bind acknowledged")

		case rpc.PacketTypeRequest:
			log.Printf("Activation request received from %s", remoteAddr)
			reqHeader, err := rpc.ParseMSRPCRequestHeader(data)
			if err != nil {
				log.Printf("Failed to parse request header: %v", err)
				break
			}

			pduData := reqHeader.PDUData(data)
			if pduData == nil {
				log.Printf("Failed to extract PDU data")
				break
			}

			kmsResponseData, err := kms.GenerateKMSResponseData(pduData, s.Config)
			if err != nil {
				log.Printf("Failed to generate KMS response: %v", err)
				break
			}

			response = rpc.BuildMSRPCResponse(reqHeader, kmsResponseData)
			log.Printf("Responded to activation request")

		default:
			log.Printf("Unknown RPC packet type: 0x%02x", header.Type)
			break
		}

		if response == nil {
			break
		}

		_, err = conn.Write(response)
		if err != nil {
			log.Printf("Error writing to %s: %v", remoteAddr, err)
			break
		}

		// After responding to a request (not bind), close connection.
		if header.Type == rpc.PacketTypeRequest {
			break
		}
	}

	log.Printf("Connection closed: %s", remoteAddr)
}

// RecvAll reads from conn until we have a complete RPC message.
func RecvAll(conn net.Conn) ([]byte, error) {
	// First read the header to get fragment length.
	headerBuf := make([]byte, rpc.MSRPCHeaderSize)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return nil, err
	}

	fragLen := binary.LittleEndian.Uint16(headerBuf[8:10])
	if fragLen <= rpc.MSRPCHeaderSize {
		return headerBuf, nil
	}

	remaining := make([]byte, int(fragLen)-rpc.MSRPCHeaderSize)
	if _, err := io.ReadFull(conn, remaining); err != nil {
		return nil, err
	}

	return append(headerBuf, remaining...), nil
}
