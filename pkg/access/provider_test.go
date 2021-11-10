package access

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
)

func TestProvider(t *testing.T) {
	publicKey := getPublicKey(t, "access-provider-000")
	privateKey := getPrivateKey(t, "access-provider-000")
	certificate := getCertificate(t, "access-provider-000")
	provider := Provider{
		URI: url.URL{
			Scheme: "https",
			Host:   "access-provider-000.com",
		},
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
		Certificate: certificate,
		Attributes: []Attribute{
			{
				URI: url.URL{
					Scheme: "https",
					Host:   "access-provider-000.com",
					Path:   "/tdf/3/attribute/medical/2/approve",
				},
				PublicKey: publicKey,
				ProviderURI: url.URL{
					Scheme: "https",
					Host:   "access-provider-000.com",
					Path:   "/tdf/3/attribute/",
				},
				SchemaVersion: schemaVersion,
			},
		},
	}
	t.Log(provider)
	bytes, err := json.Marshal(provider)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(bytes))
}

func TestProviderServeHTTP(t *testing.T) {
	uri, err := url.Parse("entity-provider-000.com")
	if err != nil {
		t.Fatal(err)
	}
	provider := Provider{
		URI:         *uri,
		PrivateKey:  getPrivateKey(t, "entity-provider-000"),
		PublicKey:   getPublicKey(t, "entity-provider-000"),
		Certificate: getCertificate(t, "entity-provider-000"),
	}
	es := httptest.NewServer(&provider)
	defer es.Close()
	res, err := http.Get(es.URL)
	if err != nil {
		t.Fatal(err)
	}
	eo, err := ioutil.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", eo)
}

func getCertificate(t *testing.T, name string) x509.Certificate {
	bytes := loadBytes(t, name+"-certificate.pem")
	block, x := pem.Decode(bytes)
	if block == nil {
		t.Fatal(x)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return *certificate
}

func getPrivateKey(t *testing.T, name string) rsa.PrivateKey {
	bytes := loadBytes(t, name+"-private.pem")
	block, x := pem.Decode(bytes)
	if block == nil {
		t.Fatal(x)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return *privateKey
}

func getPublicKey(t *testing.T, name string) rsa.PublicKey {
	key := getPrivateKey(t, name)
	return key.PublicKey
}

func loadBytes(t *testing.T, name string) []byte {
	path := filepath.Join("testdata", name) // relative path
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}
