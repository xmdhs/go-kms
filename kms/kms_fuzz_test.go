package kms

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

func FuzzUUIDFromString(f *testing.F) {
	f.Add("78563412-bc9a-f0de-1122-334455667788")
	f.Add("78563412bc9af0de1122334455667788")
	f.Add("")
	f.Add("not-a-uuid")
	f.Add("00000000-0000-0000-0000-000000000000")
	f.Fuzz(func(t *testing.T, s string) {
		u, err := UUIDFromString(s)
		if err != nil {
			return
		}
		// A parsed UUID stringifies to canonical form and must re-parse
		// idempotently.
		u2, err := UUIDFromString(u.String())
		if err != nil || u2 != u {
			t.Fatalf("UUID round trip unstable: %q -> %v -> %q", s, u, u.String())
		}
	})
}

func FuzzParseKMSRequest(f *testing.F) {
	f.Add(buildValidRequestData())
	f.Add([]byte{})
	f.Add(make([]byte, 108))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseKMSRequest(data)
		if err != nil {
			return
		}
		// Marshal must reproduce the input exactly: every field is parsed
		// verbatim and MachineNameRaw passes through as a tail slice.
		if !bytes.Equal(r.Marshal(), data) {
			t.Fatalf("KMSRequest marshal mismatch: got %x want %x", r.Marshal(), data)
		}
	})
}

func FuzzParseKMSResponse(f *testing.F) {
	resp := &KMSResponse{
		VersionMinor: 1, VersionMajor: 6, KMSEpid: EncodeUTF16LE("epid"),
		ClientMachineID: RandomUUID(), ResponseTime: 1,
		CurrentClientCount: 25, VLActivationInterval: 120, VLRenewalInterval: 10080,
	}
	f.Add(resp.Marshal())
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseKMSResponse(data)
		if err != nil {
			return
		}
		r2, err := ParseKMSResponse(r.Marshal())
		if err != nil {
			t.Fatalf("re-parse of marshal failed: %v", err)
		}
		// Fixed tail fields must survive the marshal round trip. KMSEpid is
		// intentionally not compared: Marshal appends a fresh null terminator,
		// so trailing bytes can legitimately differ.
		if r2.VersionMinor != r.VersionMinor || r2.VersionMajor != r.VersionMajor ||
			r2.ClientMachineID != r.ClientMachineID || r2.ResponseTime != r.ResponseTime ||
			r2.CurrentClientCount != r.CurrentClientCount ||
			r2.VLActivationInterval != r.VLActivationInterval ||
			r2.VLRenewalInterval != r.VLRenewalInterval {
			t.Fatalf("KMSResponse round trip unstable: %+v vs %+v", r2, r)
		}
	})
}

func FuzzParseGenericRequestHeader(f *testing.F) {
	f.Add(make([]byte, 12))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseGenericRequestHeader(data) // must never panic
	})
}

func FuzzGenerateKMSResponseData(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	f.Add(makeV5V6WireData(buildValidRequestData(), 5, false))
	f.Add(makeV5V6WireData(buildValidRequestData(), 6, true))
	f.Fuzz(func(t *testing.T, data []byte) {
		resp, err := GenerateKMSResponseData(context.Background(), data, &ServerConfig{})
		if err != nil {
			return
		}
		if len(resp) < 12 {
			t.Fatalf("response too short: %d bytes", len(resp))
		}
		if len(data) < 12 {
			t.Fatal("unexpected success for a header shorter than 12 bytes")
		}
		switch major := binary.LittleEndian.Uint16(data[10:12]); major {
		case 4, 5, 6:
			// Known versions only succeed when the payload decrypts with the
			// protocol keys, which arbitrary fuzz input cannot do.
		default:
			// Unknown protocol versions must return the fixed error envelope.
			if len(resp) != 12 || binary.LittleEndian.Uint32(resp[8:12]) != 0xC004F042 {
				t.Fatalf("unknown-version response = %x, want 12-byte envelope with status 0xC004F042", resp)
			}
		}
	})
}
