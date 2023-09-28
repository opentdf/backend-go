package tdf3

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"

	tdfCrypto "github.com/opentdf/backend-go/internal/crypto"
)

const segmentSize int = 1024 * 1024

type IntegrityInformation struct {
	EncryptedSegmentSizeDefault int       `json:"encryptedSegmentSizeDefault"`
	RootSignature               Signature `json:"rootSignature"`
	SegmentHashAlg              string    `json:"segmentHashAlg"`
	SegmentSizeDefault          int       `json:"segmentSizeDefault"`
	Segments                    []Segment `json:"segments"`
}

type Segment struct {
	EncryptedSegmentSize int    `json:"encryptedSegmentSize"`
	Hash                 []byte `json:"hash"`
	SegmentSize          int    `json:"segmentSize,omitempty"`
}

type Signature struct {
	Alg string `json:"alg"`
	Sig []byte `json:"sig"`
}

func (i *IntegrityInformation) BuildRootSignature(key []byte) error {
	sig, err := getRootSignature(i.Segments, key)
	if err != nil {
		return errors.New("error building root signature")
	}
	i.RootSignature = *sig
	return nil
}
func getRootSignature(segments []Segment, key []byte) (*Signature, error) {
	var rootSignature = new(Signature)
	rootSignature.Alg = "HS256"

	var toSign []byte
	for _, segment := range segments {
		// Combine all segments to be signed
		toSign = append(toSign, segment.Hash...)
	}
	rootSignature.Sig = tdfCrypto.Sign(crypto.SHA256, toSign, key)

	return rootSignature, nil
}

func (s *Segment) Build(content []byte, key []byte) {
	s.SegmentSize = segmentSize
	s.EncryptedSegmentSize = len(content)
	hexBuf := make([]byte, hex.EncodedLen(len(content[len(content)-16:])))
	hex.Encode(hexBuf, content[len(content)-16:])
	s.Hash = hexBuf
}

func (i *IntegrityInformation) Validate(key []byte) error {
	sig, err := getRootSignature(i.Segments, key)
	if err != nil {
		return errors.Join(errors.New("error validating root signature"), err)
	}

	if !bytes.Equal(sig.Sig, i.RootSignature.Sig) {
		return fmt.Errorf("invalid root signature %s != %s", hex.EncodeToString(sig.Sig), hex.EncodeToString(i.RootSignature.Sig))
	}
	return nil
}
