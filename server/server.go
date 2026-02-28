package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
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
	logger.LogAttrs(context.Background(), slog.LevelInfo, "KMS Server listening", slog.String("address", addr))
	logger.LogAttrs(context.Background(), slog.LevelInfo, "HWID", slog.String("hwid", hex.EncodeToString(s.Config.HWID)))

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.LogAttrs(context.Background(), slog.LevelWarn, "Failed to accept connection", slog.Any("error", err))
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

	logger.LogAttrs(ctx, slog.LevelInfo, "Connection accepted", slog.String("remote_addr", remoteAddr))

	// Reuse a pooled buffer for all reads on this connection.
	bufp := connBufPool.Get().(*[]byte)
	defer connBufPool.Put(bufp)

	for {
		// Read a complete RPC message using frag_len from the header.
		data, err := recvAllInto(conn, *bufp)
		if err != nil {
			if err != io.EOF {
				logger.LogAttrs(ctx, slog.LevelWarn, "Error reading from connection", slog.String("remote_addr", remoteAddr), slog.Any("error", err))
			}
			break
		}
		if len(data) == 0 {
			logger.LogAttrs(ctx, slog.LevelDebug, "No data received", slog.String("remote_addr", remoteAddr))
			break
		}

		// Parse RPC header to determine packet type.
		header, err := rpc.ParseMSRPCHeader(data)
		if err != nil {
			logger.LogAttrs(ctx, slog.LevelWarn, "Failed to parse RPC header", slog.Any("error", err))
			break
		}

		var response []byte

		switch header.Type {
		case rpc.PacketTypeBind:
			logger.LogAttrs(ctx, slog.LevelDebug, "RPC bind request received", slog.String("remote_addr", remoteAddr))
			response, err = rpc.BuildBindAckResponse(data, s.Config.Port, header.CallID)
			if err != nil {
				logger.LogAttrs(ctx, slog.LevelError, "Failed to build bind ack", slog.Any("error", err))
				break
			}
			logger.LogAttrs(ctx, slog.LevelDebug, "RPC bind acknowledged")

		case rpc.PacketTypeRequest:
			logger.LogAttrs(ctx, slog.LevelInfo, "Activation request received", slog.String("remote_addr", remoteAddr))
			reqHeader, err := rpc.ParseMSRPCRequestHeader(data)
			if err != nil {
				logger.LogAttrs(ctx, slog.LevelError, "Failed to parse request header", slog.Any("error", err))
				break
			}

			pduData := reqHeader.PDUData(data)
			if pduData == nil {
				logger.LogAttrs(ctx, slog.LevelError, "Failed to extract PDU data")
				break
			}

			kmsResponseData, err := kms.GenerateKMSResponseData(ctx, pduData, s.Config)
			if err != nil {
				logger.LogAttrs(ctx, slog.LevelError, "Failed to generate KMS response", slog.Any("error", err))
				break
			}

			response = rpc.BuildMSRPCResponse(reqHeader, kmsResponseData)
			logger.LogAttrs(ctx, slog.LevelInfo, "Activation request responded")

		default:
			logger.LogAttrs(ctx, slog.LevelWarn, "Unknown RPC packet type", slog.String("type", fmt.Sprintf("0x%02x", header.Type)))
		}

		if response == nil {
			break
		}

		_, err = conn.Write(response)
		if err != nil {
			logger.LogAttrs(ctx, slog.LevelWarn, "Error writing to connection", slog.String("remote_addr", remoteAddr), slog.Any("error", err))
			break
		}

		// After responding to a request (not bind), close connection.
		if header.Type == rpc.PacketTypeRequest {
			break
		}
	}

	logger.LogAttrs(ctx, slog.LevelInfo, "Connection closed", slog.String("remote_addr", remoteAddr))
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
