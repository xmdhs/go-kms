package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xmdhs/go-kms/kms"
	"github.com/xmdhs/go-kms/logger"
	"github.com/xmdhs/go-kms/rpc"

	r "math/rand/v2"
)

// KMSServer is a TCP server that handles KMS activation requests.
type KMSServer struct {
	Config   *kms.ServerConfig
	listener net.Listener
}

// maxFragLen is the maximum allowed RPC fragment length to prevent DoS via oversized allocations.
const maxFragLen = 1024

var connBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, maxFragLen)
		return &buf
	},
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
	logger.Info(context.Background(), "KMS Server listening", "address", addr)
	logger.Info(context.Background(), "HWID", "hwid", hex.EncodeToString(s.Config.HWID))

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Warn(context.Background(), "Failed to accept connection", "error", err)
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
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	remoteAddr := conn.RemoteAddr().String()

	// Generate a unique request ID for this connection.
	requestID := r.Int()
	ctx := logger.WithRequestID(context.Background(), requestID)

	logger.Info(ctx, "Connection accepted", "remote_addr", remoteAddr)

	// Reuse a pooled buffer for all reads on this connection.
	bufp := connBufPool.Get().(*[]byte)
	defer connBufPool.Put(bufp)

	for {
		// Read a complete RPC message using frag_len from the header.
		data, err := recvAllInto(conn, *bufp)
		if err != nil {
			if err != io.EOF {
				logger.Warn(ctx, "Error reading from connection", "remote_addr", remoteAddr, "error", err)
			}
			break
		}
		if len(data) == 0 {
			logger.Debug(ctx, "No data received", "remote_addr", remoteAddr)
			break
		}

		// Parse RPC header to determine packet type.
		header, err := rpc.ParseMSRPCHeader(data)
		if err != nil {
			logger.Warn(ctx, "Failed to parse RPC header", "error", err)
			break
		}

		var response []byte

		switch header.Type {
		case rpc.PacketTypeBind:
			logger.Debug(ctx, "RPC bind request received", "remote_addr", remoteAddr)
			response, err = rpc.BuildBindAckResponse(data, s.Config.Port, header.CallID)
			if err != nil {
				logger.Error(ctx, "Failed to build bind ack", "error", err)
				break
			}
			logger.Debug(ctx, "RPC bind acknowledged")

		case rpc.PacketTypeRequest:
			logger.Info(ctx, "Activation request received", "remote_addr", remoteAddr)
			reqHeader, err := rpc.ParseMSRPCRequestHeader(data)
			if err != nil {
				logger.Error(ctx, "Failed to parse request header", "error", err)
				break
			}

			pduData := reqHeader.PDUData(data)
			if pduData == nil {
				logger.Error(ctx, "Failed to extract PDU data")
				break
			}

			kmsResponseData, err := kms.GenerateKMSResponseData(ctx, pduData, s.Config)
			if err != nil {
				logger.Error(ctx, "Failed to generate KMS response", "error", err)
				break
			}

			response = rpc.BuildMSRPCResponse(reqHeader, kmsResponseData)
			logger.Info(ctx, "Activation request responded")

		default:
			logger.Warn(ctx, "Unknown RPC packet type", "type", fmt.Sprintf("0x%02x", header.Type))
		}

		if response == nil {
			break
		}

		_, err = conn.Write(response)
		if err != nil {
			logger.Warn(ctx, "Error writing to connection", "remote_addr", remoteAddr, "error", err)
			break
		}

		// After responding to a request (not bind), close connection.
		if header.Type == rpc.PacketTypeRequest {
			break
		}
	}

	logger.Info(ctx, "Connection closed", "remote_addr", remoteAddr)
}

// recvAllInto reads a complete RPC message into the provided buffer (zero-allocation read).
func recvAllInto(conn net.Conn, buf []byte) ([]byte, error) {
	if _, err := io.ReadFull(conn, buf[:rpc.MSRPCHeaderSize]); err != nil {
		return nil, err
	}

	fragLen := binary.LittleEndian.Uint16(buf[8:10])
	if fragLen > maxFragLen {
		return nil, fmt.Errorf("fragment length %d exceeds maximum allowed %d", fragLen, maxFragLen)
	}
	if fragLen <= rpc.MSRPCHeaderSize {
		return buf[:rpc.MSRPCHeaderSize], nil
	}

	if _, err := io.ReadFull(conn, buf[rpc.MSRPCHeaderSize:fragLen]); err != nil {
		return nil, err
	}
	return buf[:fragLen], nil
}

// RecvAll reads from conn until we have a complete RPC message.
func RecvAll(conn net.Conn) ([]byte, error) {
	// First read the header to get fragment length.
	headerBuf := make([]byte, rpc.MSRPCHeaderSize)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return nil, err
	}

	fragLen := binary.LittleEndian.Uint16(headerBuf[8:10])
	if fragLen > maxFragLen {
		return nil, fmt.Errorf("fragment length %d exceeds maximum allowed %d", fragLen, maxFragLen)
	}
	if fragLen <= rpc.MSRPCHeaderSize {
		return headerBuf, nil
	}

	// Single allocation for the full message.
	buf := make([]byte, fragLen)
	copy(buf, headerBuf)
	if _, err := io.ReadFull(conn, buf[rpc.MSRPCHeaderSize:]); err != nil {
		return nil, err
	}
	return buf, nil
}
