package nanotdf

import (
	"bytes"
	"encoding/gob"
	"os"
	"testing"
)

// nanotdfEqual compares two NanoTDF structures for equality.
func nanoTDFEqual(a, b *NanoTDF) bool {
	// Compare Magic field
	if a.Magic != b.Magic {
		return false
	}

	// Compare Kas field
	if a.Kas.Protocol != b.Kas.Protocol || a.Kas.Len != b.Kas.Len || a.Kas.Body != b.Kas.Body {
		return false
	}

	// Compare Binding field
	if a.Binding.UseEcdsaBinding != b.Binding.UseEcdsaBinding || a.Binding.Padding != b.Binding.Padding || a.Binding.BindingBody != b.Binding.BindingBody {
		return false
	}

	// Compare SigCfg field
	if a.SigCfg.HasSignature != b.SigCfg.HasSignature || a.SigCfg.SignatureMode != b.SigCfg.SignatureMode || a.SigCfg.Cipher != b.SigCfg.Cipher {
		return false
	}

	// Compare Policy field
	if a.Policy.Mode != b.Policy.Mode || !policyBodyEqual(a.Policy.Body, b.Policy.Body) || !eccSignatureEqual(a.Policy.Binding, b.Policy.Binding) {
		return false
	}

	// Compare EphemeralPublicKey field
	if !bytes.Equal(a.EphemeralPublicKey.Key, b.EphemeralPublicKey.Key) {
		return false
	}

	// If all comparisons passed, the structures are equal
	return true
}

// policyBodyEqual compares two PolicyBody instances for equality.
func policyBodyEqual(a, b PolicyBody) bool {
	// Compare based on the concrete type of PolicyBody
	switch a := a.(type) {
	case Nanotdf_RemotePolicy:
		b, ok := b.(Nanotdf_RemotePolicy)
		if !ok {
			return false
		}
		return remotePolicyEqual(a, b)
	case Nanotdf_EmbeddedPolicy:
		b, ok := b.(Nanotdf_EmbeddedPolicy)
		if !ok {
			return false
		}
		return embeddedPolicyEqual(a, b)
	default:
		// Handle other types as needed
		return false
	}
}

// remotePolicyEqual compares two Nanotdf_RemotePolicy instances for equality.
func remotePolicyEqual(a, b Nanotdf_RemotePolicy) bool {
	// Compare Url field
	if a.Url.Protocol != b.Url.Protocol || a.Url.Len != b.Url.Len || a.Url.Body != b.Url.Body {
		return false
	}
	return true
}

// embeddedPolicyEqual compares two Nanotdf_EmbeddedPolicy instances for equality.
func embeddedPolicyEqual(a, b Nanotdf_EmbeddedPolicy) bool {
	// Compare Len and Body fields
	return a.Len == b.Len && a.Body == b.Body
}

// eccSignatureEqual compares two Nanotdf_EccSignature instances for equality.
func eccSignatureEqual(a, b *Nanotdf_EccSignature) bool {
	// Compare Value field
	return bytes.Equal(a.Value, b.Value)
}

func init() {
	// Register the Nanotdf_RemotePolicy type with gob
	gob.Register(&Nanotdf_RemotePolicy{})
}

func TestReadNanoTDFHeader(t *testing.T) {
	// Prepare a sample NanoTDF structure
	nanoTDF := NanoTDF{
		Magic: [3]byte{'L', '1', 'L'},
		Kas: &Nanotdf_ResourceLocator{
			Protocol: Nanotdf_UrlProtocol__Https,
			Len:      14,
			Body:     "kas.virtru.com",
		},
		Binding: &Nanotdf_BindingCfg{
			UseEcdsaBinding: true,
			Padding:         0,
			BindingBody:     Nanotdf_EccMode__Secp256r1,
		},
		SigCfg: &Nanotdf_SignatureConfig{
			HasSignature:  true,
			SignatureMode: Nanotdf_EccMode__Secp256r1,
			Cipher:        Nanotdf_CipherMode__Aes256gcm64Bit,
		},
		Policy: &Nanotdf_Policy{
			Mode: Nanotdf_PolicyType__RemotePolicy,
			Body: Nanotdf_RemotePolicy{
				Url: &Nanotdf_ResourceLocator{
					Protocol: Nanotdf_UrlProtocol__Https,
					Len:      21,
					Body:     "kas.virtru.com/policy",
				},
			},
			Binding: &Nanotdf_EccSignature{
				Value: []byte{181, 228, 19, 166, 2, 17, 229, 241},
			},
		},
		EphemeralPublicKey: &Nanotdf_EccKey{
			Key: []byte{123, 34, 52, 160, 205, 63, 54, 255, 123, 186, 109,
				143, 232, 223, 35, 246, 44, 157, 9, 53, 111, 133,
				130, 248, 169, 207, 21, 18, 108, 138, 157, 164, 108},
		},
	}

	// Serialize the sample NanoTDF structure into a byte slice using gob
	file, err := os.Open("nanotdfspec.ntdf")
	if err != nil {
		t.Fatalf("Cannot open NanoTDF file: %v", err)
	}
	defer file.Close()

	result, err := ReadNanoTDFHeader(file)
	if err != nil {
		t.Fatalf("Error while reading NanoTDF header: %v", err)
	}

	// Compare the result with the original NanoTDF structure
	if !nanoTDFEqual(result, &nanoTDF) {
		t.Error("Result does not match the expected NanoTDF structure.")
	}
}
