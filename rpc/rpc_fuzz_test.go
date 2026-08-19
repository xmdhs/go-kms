package rpc

import (
	"net"
	"reflect"
	"testing"
)

// assertSubSlice fails if sub does not point into base's backing array.
func assertSubSlice(t *testing.T, base, sub []byte) {
	t.Helper()
	if len(sub) == 0 {
		return
	}
	baseStart := reflect.ValueOf(base).Pointer()
	subStart := reflect.ValueOf(sub).Pointer()
	if subStart < baseStart || subStart+uintptr(len(sub)) > baseStart+uintptr(len(base)) {
		t.Fatalf("%d-byte result escapes the %d-byte input buffer", len(sub), len(base))
	}
}

func FuzzParseMSRPCHeader(f *testing.F) {
	f.Add(BuildBindRequest(1))
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ParseMSRPCHeader(data)
		if err != nil {
			return
		}
		// Marshal/parse must be lossless on the fixed 16-byte layout.
		re, err := ParseMSRPCHeader(h.Marshal())
		if err != nil || *re != *h {
			t.Fatalf("header round trip unstable: %+v vs %+v (err=%v)", re, h, err)
		}
	})
}

func FuzzParseMSRPCRequestHeader(f *testing.F) {
	f.Add(BuildRPCRequest([]byte{1, 2, 3}, 1))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ParseMSRPCRequestHeader(data)
		if err != nil {
			return
		}
		// PDUData must hand back a view of the input, never an escape or a copy.
		assertSubSlice(t, data, h.PDUData(data))
	})
}

func FuzzParseBindRequest(f *testing.F) {
	f.Add(BuildBindRequest(1))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := ParseBindRequest(data)
		if err != nil {
			return
		}
		// One context item is parsed per ctx_num, no more, no fewer.
		if len(b.CtxItems) != int(b.CtxNum) {
			t.Fatalf("parsed %d ctx items for ctx_num=%d", len(b.CtxItems), b.CtxNum)
		}
	})
}

func FuzzPDUData(f *testing.F) {
	f.Add(BuildRPCRequest([]byte{9, 8, 7}, 2))
	f.Add(BuildBindRequest(1))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		// PDUData must hand back a view of the input, never an escape or a copy.
		assertSubSlice(t, data, PDUData(data))
	})
}

func FuzzRecvAll(f *testing.F) {
	f.Add(BuildBindRequest(1))
	f.Add(BuildRPCRequest([]byte{1, 2, 3, 4}, 2))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		c1, c2 := net.Pipe()
		go func() {
			_, _ = c2.Write(data)
			_ = c2.Close()
		}()
		_, _ = RecvAll(c1, 512)
		_ = c1.Close()
	})
}
