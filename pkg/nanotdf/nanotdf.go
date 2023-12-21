package nanotdf

import (
	"encoding/binary"
	"io"
)

type NanoTDF struct {
	Magic              [3]byte
	Kas                *Nanotdf_ResourceLocator
	Binding            *Nanotdf_BindingCfg
	SigCfg             *Nanotdf_SignatureConfig
	Policy             *Nanotdf_Policy
	EphemeralPublicKey *Nanotdf_EccKey
}

type Nanotdf_ResourceLocator struct {
	Protocol Nanotdf_UrlProtocol
	Len      uint8
	Body     string
}

func (Nanotdf_ResourceLocator) isPolicyBody() {}

type Nanotdf_BindingCfg struct {
	UseEcdsaBinding bool
	Padding         uint8
	BindingBody     Nanotdf_EccMode
}

type Nanotdf_SignatureConfig struct {
	HasSignature  bool
	SignatureMode Nanotdf_EccMode
	Cipher        Nanotdf_CipherMode
}

type PolicyBody interface {
	isPolicyBody() // marker method to ensure interface implementation
}

type Nanotdf_Policy struct {
	Mode    uint8
	Body    PolicyBody
	Binding *Nanotdf_EccSignature
}

type Nanotdf_RemotePolicy struct {
	Url *Nanotdf_ResourceLocator
}

func (Nanotdf_RemotePolicy) isPolicyBody() {}

type Nanotdf_EmbeddedPolicy struct {
	Len  uint16
	Body string
}

func (Nanotdf_EmbeddedPolicy) isPolicyBody() {}

type Nanotdf_EccSignature struct {
	Value []byte
}

type Nanotdf_EccKey struct {
	Key []byte
}

type Nanotdf_UrlProtocol uint8

const (
	Nanotdf_UrlProtocol__Http   Nanotdf_UrlProtocol = 0
	Nanotdf_UrlProtocol__Https  Nanotdf_UrlProtocol = 1
	Nanotdf_UrlProtocol__Shared Nanotdf_UrlProtocol = 255
)

type Nanotdf_EccMode uint8

const (
	Nanotdf_EccMode__Secp256r1 Nanotdf_EccMode = 0
	Nanotdf_EccMode__Secp384r1 Nanotdf_EccMode = 1
	Nanotdf_EccMode__Secp521r1 Nanotdf_EccMode = 2
	Nanotdf_EccMode__Secp256k1 Nanotdf_EccMode = 3
)

type Nanotdf_CipherMode int

const (
	Nanotdf_CipherMode__Aes256gcm64Bit  Nanotdf_CipherMode = 0
	Nanotdf_CipherMode__Aes256gcm96Bit  Nanotdf_CipherMode = 1
	Nanotdf_CipherMode__Aes256gcm104Bit Nanotdf_CipherMode = 2
	Nanotdf_CipherMode__Aes256gcm112Bit Nanotdf_CipherMode = 3
	Nanotdf_CipherMode__Aes256gcm120Bit Nanotdf_CipherMode = 4
	Nanotdf_CipherMode__Aes256gcm128Bit Nanotdf_CipherMode = 5
)

type Nanotdf_PolicyType uint8

const (
	Nanotdf_PolicyType__RemotePolicy                           = 0
	Nanotdf_PolicyType__EmbeddedPolicyPainText                 = 1
	Nanotdf_PolicyType__EmbeddedPolicyEncrypted                = 2
	Nanotdf_PolicyType__EmbeddedPolicyEncryptedPolicyKeyAccess = 3
)

func deserializeBindingCfg(b byte) *Nanotdf_BindingCfg {
	cfg := Nanotdf_BindingCfg{}
	cfg.UseEcdsaBinding = (b >> 7 & 0x01) == 1
	cfg.Padding = 0
	cfg.BindingBody = Nanotdf_EccMode((b >> 4) & 0x07)

	return &cfg
}

func deserializeSignatureCfg(b byte) *Nanotdf_SignatureConfig {
	cfg := Nanotdf_SignatureConfig{}
	cfg.HasSignature = (b >> 7 & 0x01) == 1
	cfg.SignatureMode = Nanotdf_EccMode((b >> 4) & 0x07)
	cfg.Cipher = Nanotdf_CipherMode(b & 0x0F)

	return &cfg
}

func readPolicyBody(reader io.Reader, mode uint8) (PolicyBody, error) {
	switch mode {
	case 0:
		var resourceLocator Nanotdf_ResourceLocator
		if err := binary.Read(reader, binary.BigEndian, &resourceLocator.Protocol); err != nil {
			return nil, err
		}
		if err := binary.Read(reader, binary.BigEndian, &resourceLocator.Len); err != nil {
			return nil, err
		}
		body := make([]byte, resourceLocator.Len)
		if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
			return nil, err
		}
		resourceLocator.Body = string(body)
		return Nanotdf_RemotePolicy{Url: &resourceLocator}, nil
	default:
		var embeddedPolicy Nanotdf_EmbeddedPolicy
		if err := binary.Read(reader, binary.BigEndian, &embeddedPolicy.Len); err != nil {
			return nil, err
		}
		body := make([]byte, embeddedPolicy.Len)
		if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
			return nil, err
		}
		embeddedPolicy.Body = string(body)
		return Nanotdf_EmbeddedPolicy(embeddedPolicy), nil
	}
}

func readEphemeralPublicKey(reader io.Reader, curve Nanotdf_EccMode) (*Nanotdf_EccKey, error) {
	var numberOfBytes uint8
	switch curve {
	case Nanotdf_EccMode__Secp256r1:
		numberOfBytes = 33
	case Nanotdf_EccMode__Secp384r1:
		numberOfBytes = 49
	case Nanotdf_EccMode__Secp521r1:
		numberOfBytes = 67
	}
	buffer := make([]byte, numberOfBytes)
	if err := binary.Read(reader, binary.BigEndian, &buffer); err != nil {
		return nil, err
	}
	return &Nanotdf_EccKey{Key: buffer}, nil
}

func ReadNanoTDFHeader(reader io.Reader) (*NanoTDF, error) {

	var nanoTDF NanoTDF

	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.Magic); err != nil {
		return nil, err
	}

	nanoTDF.Kas = &Nanotdf_ResourceLocator{}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.Kas.Protocol); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.Kas.Len); err != nil {
		return nil, err
	}
	body := make([]byte, nanoTDF.Kas.Len)
	if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
		return nil, err
	}
	nanoTDF.Kas.Body = string(body)

	var bindingByte uint8
	if err := binary.Read(reader, binary.BigEndian, &bindingByte); err != nil {
		return nil, err
	}
	nanoTDF.Binding = deserializeBindingCfg(bindingByte)

	var signatureByte uint8
	if err := binary.Read(reader, binary.BigEndian, &signatureByte); err != nil {
		return nil, err
	}
	nanoTDF.SigCfg = deserializeSignatureCfg(signatureByte)

	nanoTDF.Policy = &Nanotdf_Policy{}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.Policy.Mode); err != nil {
		return nil, err
	}
	policyBody, err := readPolicyBody(reader, nanoTDF.Policy.Mode)
	if err != nil {
		return nil, err
	}

	nanoTDF.Policy.Body = policyBody

	nanoTDF.Policy.Binding = &Nanotdf_EccSignature{}
	nanoTDF.Policy.Binding.Value = make([]byte, 8)
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.Policy.Binding.Value); err != nil {
		return nil, err
	}

	nanoTDF.EphemeralPublicKey = &Nanotdf_EccKey{}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.EphemeralPublicKey.Key); err != nil {
		return nil, err
	}
	nanoTDF.EphemeralPublicKey, err = readEphemeralPublicKey(reader, nanoTDF.Binding.BindingBody)

	return &nanoTDF, nil
}
