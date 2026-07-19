package audit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	ledgerChecksumDomain = "knote.audit.ledger-header.v1"
	frameChecksumDomain  = "knote.audit.ledger-frame.v1"
	headChecksumDomain   = "knote.audit.ledger-head.v1"
	maxMetadataPayload   = 4 << 10
	checksumSize         = 32

	ledgerEnvelopeOverhead = 8 + 4 + checksumSize
	frameEnvelopeOverhead  = 8 + 8 + 4 + checksumSize
)

var (
	ledgerMagic = [8]byte{'K', 'N', 'A', 'U', 'D', 'L', '0', '1'}
	frameMagic  = [8]byte{'K', 'N', 'A', 'U', 'D', 'F', '0', '1'}
	headMagic   = [8]byte{'K', 'N', 'A', 'U', 'D', 'H', '0', '1'}
)

type ledgerHeader struct {
	FormatVersion string                 `json:"format_version"`
	Scope         protocol.TenantScope   `json:"scope"`
	GenesisDigest protocol.ContentDigest `json:"genesis_digest"`
}

type durableHead struct {
	FormatVersion string                 `json:"format_version"`
	Scope         protocol.TenantScope   `json:"scope"`
	RecordCount   uint64                 `json:"record_count"`
	LedgerSize    uint64                 `json:"ledger_size"`
	LastDigest    protocol.ContentDigest `json:"last_digest"`
}

func encodeLedgerHeader(header ledgerHeader) ([]byte, error) {
	return encodeMetadataEnvelope(ledgerMagic, ledgerChecksumDomain, header)
}

func decodeLedgerHeader(reader io.Reader) (ledgerHeader, uint64, error) {
	var header ledgerHeader
	size, err := decodeMetadataEnvelope(reader, ledgerMagic, ledgerChecksumDomain, &header)
	if err != nil {
		return ledgerHeader{}, 0, err
	}
	if header.FormatVersion != formatVersion {
		return ledgerHeader{}, 0, integrityError("unsupported ledger format", nil)
	}
	if err := header.Scope.Validate(); err != nil {
		return ledgerHeader{}, 0, integrityError("invalid ledger tenant scope", err)
	}
	genesis, err := GenesisDigest(header.Scope)
	if err != nil || header.GenesisDigest != genesis {
		return ledgerHeader{}, 0, integrityError("ledger genesis digest mismatch", err)
	}
	return header, size, nil
}

func encodeHead(head durableHead) ([]byte, error) {
	return encodeMetadataEnvelope(headMagic, headChecksumDomain, head)
}

func decodeHead(data []byte) (durableHead, error) {
	var head durableHead
	read := bytes.NewReader(data)
	consumed, err := decodeMetadataEnvelope(read, headMagic, headChecksumDomain, &head)
	if err != nil {
		return durableHead{}, err
	}
	if consumed != uint64(len(data)) || read.Len() != 0 {
		return durableHead{}, integrityError("durable head has trailing bytes", nil)
	}
	if head.FormatVersion != formatVersion {
		return durableHead{}, integrityError("unsupported durable head format", nil)
	}
	if err := head.Scope.Validate(); err != nil {
		return durableHead{}, integrityError("invalid durable head tenant scope", err)
	}
	if head.RecordCount == 0 || head.LedgerSize == 0 {
		return durableHead{}, integrityError("durable head does not identify a record", nil)
	}
	if err := head.LastDigest.Validate(); err != nil {
		return durableHead{}, integrityError("invalid durable head digest", err)
	}
	return head, nil
}

func encodeMetadataEnvelope(magic [8]byte, domain string, value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > maxMetadataPayload {
		return nil, fmt.Errorf("metadata payload exceeds the durable limit")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(payload)))
	digest := checksum(domain, magic[:], size[:], payload)
	encoded := make([]byte, 0, ledgerEnvelopeOverhead+len(payload))
	encoded = append(encoded, magic[:]...)
	encoded = append(encoded, size[:]...)
	encoded = append(encoded, payload...)
	encoded = append(encoded, digest[:]...)
	return encoded, nil
}

func decodeMetadataEnvelope(
	reader io.Reader,
	wantMagic [8]byte,
	domain string,
	destination any,
) (uint64, error) {
	var prefix [12]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return 0, integrityError("truncated metadata envelope", err)
	}
	if !bytes.Equal(prefix[:8], wantMagic[:]) {
		return 0, integrityError("metadata envelope magic mismatch", nil)
	}
	payloadSize := binary.BigEndian.Uint32(prefix[8:])
	if payloadSize == 0 || payloadSize > maxMetadataPayload {
		return 0, integrityError("invalid metadata payload length", nil)
	}
	payload := make([]byte, payloadSize)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, integrityError("truncated metadata payload", err)
	}
	var storedChecksum [checksumSize]byte
	if _, err := io.ReadFull(reader, storedChecksum[:]); err != nil {
		return 0, integrityError("truncated metadata checksum", err)
	}
	wantChecksum := checksum(domain, prefix[:8], prefix[8:], payload)
	if storedChecksum != wantChecksum {
		return 0, integrityError("metadata checksum mismatch", nil)
	}
	if err := decodeCanonicalJSON(payload, destination); err != nil {
		return 0, err
	}
	return uint64(ledgerEnvelopeOverhead) + uint64(payloadSize), nil
}

func encodeFrame(sequence uint64, reference protocol.AuditRecordReference) ([]byte, error) {
	if sequence == 0 {
		return nil, fmt.Errorf("frame sequence must be greater than zero")
	}
	payload, err := encodeReference(reference)
	if err != nil {
		return nil, err
	}
	var sequenceBytes [8]byte
	var size [4]byte
	binary.BigEndian.PutUint64(sequenceBytes[:], sequence)
	binary.BigEndian.PutUint32(size[:], uint32(len(payload)))
	digest := checksum(frameChecksumDomain, frameMagic[:], sequenceBytes[:], size[:], payload)
	encoded := make([]byte, 0, frameEnvelopeOverhead+len(payload))
	encoded = append(encoded, frameMagic[:]...)
	encoded = append(encoded, sequenceBytes[:]...)
	encoded = append(encoded, size[:]...)
	encoded = append(encoded, payload...)
	encoded = append(encoded, digest[:]...)
	return encoded, nil
}

type decodedFrame struct {
	Sequence  uint64
	Reference protocol.AuditRecordReference
	Size      uint64
}

func decodeFrame(reader io.Reader) (decodedFrame, bool, error) {
	var prefix [20]byte
	n, err := io.ReadFull(reader, prefix[:])
	if err == io.EOF && n == 0 {
		return decodedFrame{}, false, nil
	}
	if err != nil {
		return decodedFrame{}, false, integrityError("truncated record frame", err)
	}
	if !bytes.Equal(prefix[:8], frameMagic[:]) {
		return decodedFrame{}, false, integrityError("record frame magic mismatch", nil)
	}
	sequence := binary.BigEndian.Uint64(prefix[8:16])
	if sequence == 0 {
		return decodedFrame{}, false, integrityError("record frame sequence is zero", nil)
	}
	payloadSize := binary.BigEndian.Uint32(prefix[16:])
	if payloadSize == 0 || payloadSize > maxRecordPayload {
		return decodedFrame{}, false, integrityError("invalid record frame length", nil)
	}
	payload := make([]byte, payloadSize)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return decodedFrame{}, false, integrityError("truncated record frame payload", err)
	}
	var storedChecksum [checksumSize]byte
	if _, err := io.ReadFull(reader, storedChecksum[:]); err != nil {
		return decodedFrame{}, false, integrityError("truncated record frame checksum", err)
	}
	wantChecksum := checksum(frameChecksumDomain, prefix[:8], prefix[8:16], prefix[16:], payload)
	if storedChecksum != wantChecksum {
		return decodedFrame{}, false, integrityError("record frame checksum mismatch", nil)
	}
	reference, err := decodeReference(payload)
	if err != nil {
		return decodedFrame{}, false, err
	}
	return decodedFrame{
		Sequence: sequence, Reference: reference,
		Size: uint64(frameEnvelopeOverhead) + uint64(payloadSize),
	}, true, nil
}

func decodeCanonicalJSON(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return integrityError("decode canonical metadata", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return integrityError("canonical metadata has trailing values", err)
	}
	canonical, err := json.Marshal(destination)
	if err != nil {
		return integrityError("re-encode canonical metadata", err)
	}
	if !bytes.Equal(payload, canonical) {
		return integrityError("metadata payload is not canonical", nil)
	}
	return nil
}
