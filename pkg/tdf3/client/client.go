package client

import (
	"archive/zip"
	"bufio"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"dario.cat/mergo"
	"github.com/google/uuid"
	tdfCrypto "github.com/opentdf/backend-go/internal/crypto"
	"github.com/opentdf/backend-go/internal/kas"
	"github.com/opentdf/backend-go/pkg/tdf3"
)

const (
	payloadProtocolDefault string = "zip"
	segmentSizeDefault     int    = 1024 * 1024
	manifestFileName       string = "0.manifest.json"
)

type Client struct {
	kas     []*kas.Client
	PrivKey []byte
	PubKey  []byte
}

type TDFClientOptions struct {
	KasEndpoint []string
	PrivKey     []byte
	PubKey      []byte
	HttpClient  *http.Client
}

type TDFCreateOptions struct {
	Attributes         []tdf3.Attribute
	CryptoAlgorithm    tdfCrypto.CryptoAlgorithm
	EncryptedMetadata  []byte
	Dissem             []string
	IsPayloadEncrypted bool
	PayloadProtocol    string
	SegmentSize        int
	KeySplitType       string
	HashAlgorithm      crypto.Hash
}

func NewTDFClient(ops ...TDFClientOptions) (*Client, error) {
	client := &Client{}
	if len(ops) > 0 {
		client.PrivKey = ops[0].PrivKey
		client.PubKey = ops[0].PubKey

		for _, endpoint := range ops[0].KasEndpoint {
			var (
				kasUrl *url.URL
				err    error
			)

			kasUrl, err = url.Parse(endpoint)
			if err != nil {
				return nil, err
			}

			if ops[0].HttpClient == nil {
				ops[0].HttpClient = http.DefaultClient
			}

			kc, err := kas.NewClient(kas.KasClientOptions{
				Endpoint:   kasUrl,
				HttpClient: ops[0].HttpClient,
			})
			if err != nil {
				return nil, err
			}
			client.kas = append(client.kas, kc)
		}
	}

	// Set defaults for options not set
	clientDefaults(client)
	return client, nil
}

func clientDefaults(client *Client) {

}

func (client *Client) Create(plainText io.Reader, writer io.Writer, options *TDFCreateOptions) error {
	var (
		tdf tdf3.TDF
	)

	// Set IsPayloadEncrypted to true by default
	defaultOptions := &TDFCreateOptions{
		Attributes:      make([]tdf3.Attribute, 0),
		CryptoAlgorithm: tdfCrypto.AES256GCM,
		Dissem:          make([]string, 0),
		PayloadProtocol: payloadProtocolDefault,
		SegmentSize:     segmentSizeDefault,
		KeySplitType:    "split",
		HashAlgorithm:   crypto.SHA256,
	}

	// Override default options with user options
	err := mergo.Merge(defaultOptions, options, mergo.WithOverride)
	if err != nil {
		return err
	}
	options = defaultOptions
	fmt.Println(defaultOptions)

	// Create new crypto provider
	cryptoProvider, err := tdfCrypto.NewCryptoClient(options.CryptoAlgorithm)
	if err != nil {
		return err
	}

	/*
	 Describe Payload Object
	*/
	// Allow different types of payloads when supported
	tdf.Payload.Type = "reference"
	// Location of payload whether thats in zip or remote (only zip supported for now)
	tdf.Payload.URL = "0.payload"
	tdf.Payload.Protocol = options.PayloadProtocol
	if options.IsPayloadEncrypted {
		tdf.Payload.IsEncrypted = true
	} else {
		tdf.Payload.IsEncrypted = false
	}
	// We should poke at Method. Still don't understand where this is used.
	tdf.EncryptionInformation.Method.Algorithm = options.CryptoAlgorithm.String()
	// What does streamable mean?
	tdf.EncryptionInformation.Method.Streamable = true
	// I don't think IV is needed or used
	tdf.EncryptionInformation.Method.IV = []byte("")

	// zipBuf := new(bytes.Buffer)
	tdfZip := zip.NewWriter(writer)

	buf := make([]byte, options.SegmentSize)
	var segments []tdf3.Segment
	chunkCount := 0

	// Define payload file in zip
	payload := &zip.FileHeader{
		Name:   fmt.Sprintf("%d.payload", 0),
		Method: zip.Store,
	}

	chunkWriter, err := tdfZip.CreateHeader(payload)
	if err != nil {
		return err
	}

	// Wrap io.Reader in bufio.Reader
	bufReader := bufio.NewReader(plainText)
	// Chunk the payload and encrypt into segments
	for {
		n, err := bufReader.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		// Detect mime type from first chunk
		if chunkCount == 0 {
			tdf.Payload.MimeType = http.DetectContentType(buf[:n])
		}
		if n == 0 {
			break
		}

		// Encrypt segment
		cipherText, err := cryptoProvider.Encrypt(buf[:n])
		if err != nil {
			return err
		}

		// Build new segment
		segment := tdf3.Segment{}

		segment.Build(cipherText, cryptoProvider.Key())
		segments = append(segments, segment)

		chunkWriter.Write(cipherText)

		chunkCount++

	}

	/*
		Build integrity information
	*/
	tdf.EncryptionInformation.IntegrityInformation.Segments = segments
	tdf.EncryptionInformation.IntegrityInformation.SegmentHashAlg = "GMAC"
	tdf.EncryptionInformation.IntegrityInformation.SegmentSizeDefault = options.SegmentSize
	//
	tdf.EncryptionInformation.IntegrityInformation.EncryptedSegmentSizeDefault = cryptoProvider.EncryptedSegmentSizeDefault(options.SegmentSize)

	err = tdf.EncryptionInformation.IntegrityInformation.BuildRootSignature(cryptoProvider.Key())
	if err != nil {
		return err
	}

	//TODO: Build Policy Object
	policy := &tdf3.Policy{}
	// Why do we need a UUID if the policy isn't stored remotely?
	policy.UUID = uuid.New()
	policy.Body.DataAttributes = options.Attributes
	policy.Body.Dissem = options.Dissem

	jsonPolicy, err := json.Marshal(policy)
	if err != nil {
		return err
	}

	tdf.EncryptionInformation.Policy = jsonPolicy
	b64Policy := base64.StdEncoding.EncodeToString(jsonPolicy)
	keySplits, err := tdfCrypto.KeySplit(options.KeySplitType, cryptoProvider.Key(), len(client.kas))
	if err != nil {
		return err
	}
	// Key Access Object Creation
	for i, kao := range client.kas {
		var encryptedMetatDataCipherText []byte

		keyAccess := &tdf3.KeyAccess{}
		keyAccess.Type = "wrapped"
		keyAccess.URL = kao.Endpoint.String()
		keyAccess.Protocol = "kao"

		keyAccess.WrappedKey, err = kao.LocalRewrap(keySplits[i])
		if err != nil {
			return err
		}
		keyAccess.PolicyBinding = tdfCrypto.Sign(options.HashAlgorithm, []byte(b64Policy), keySplits[i])

		// Encrypted Meta Data
		if len(options.EncryptedMetadata) != 0 {
			var metadata tdf3.Metadata
			// Generate nonce or what some people call the iv
			metaDataCryptoProvider, err := tdfCrypto.NewCryptoClientWithKey(options.CryptoAlgorithm, keySplits[i])
			if err != nil {
				return err
			}

			metadata.Algorithm = metaDataCryptoProvider.Algorithm()

			// Encrypt segment
			metadata.CipherText, err = metaDataCryptoProvider.Encrypt(options.EncryptedMetadata)
			if err != nil {
				return err
			}

			// We shouldn't store IV like this
			metadata.IV = metadata.CipherText[:12]

			encryptedMetatDataCipherText, err = json.Marshal(metadata)
			if err != nil {
				return err
			}
		}

		keyAccess.EncryptedMetadata = encryptedMetatDataCipherText
		tdf.EncryptionInformation.KeyAccess = append(tdf.EncryptionInformation.KeyAccess, *keyAccess)
	}

	// We only split type for now. Not sure what it actually means
	tdf.EncryptionInformation.Type = options.KeySplitType

	manifestHeader := &zip.FileHeader{
		Name:   manifestFileName,
		Method: zip.Store,
	}
	manifestWriter, err := tdfZip.CreateHeader(manifestHeader)
	if err != nil {
		return err
	}
	tdfb, err := json.Marshal(tdf)
	if err != nil {
		return err
	}
	_, err = manifestWriter.Write(tdfb)
	if err != nil {
		return err
	}

	err = tdfZip.Close()
	if err != nil {
		return err
	}
	return nil
}

// We should probably accept an IO Writer Interface here as well
func (client *Client) GetContent(reader io.ReaderAt, size int64, writer io.Writer) error {
	tdfZip, err := zip.NewReader(reader, size)
	if err != nil {
		return err
	}

	// We need to work with the manifest from the zip archive
	tdf, err := client.GetManifest(reader, size)
	if err != nil {
		return err
	}

	/*
		Start of KAS ReWrap Request to get data key that actually encrypts the content
	*/

	// Build kas rewrap request object

	privateKey, err := tdfCrypto.ParsePrivateKey(client.PrivKey)
	if err != nil {
		return err
	}

	var splits = make([][]byte, len(tdf.EncryptionInformation.KeyAccess)-1)
	// Get Split Keys
	for k, kao := range tdf.EncryptionInformation.KeyAccess {
		// Need to figure out how to handle other types
		if kao.Type == "wrapped" {
			var (
				rewrapRequest = new(kas.RequestBody)
			)
			rewrapRequest.KeyAccess = kao
			rewrapRequest.ClientPublicKey = string(client.PubKey)
			rewrapRequest.Policy = tdf.EncryptionInformation.Policy
			rewrapResponse, err := client.kas[k].RemoteRewrap(rewrapRequest, privateKey)
			// Get Wrapped Key
			if err != nil {
				return err
			}

			// Unwrap our key from KAS
			split, err := tdfCrypto.DecryptOAEP(privateKey.(*rsa.PrivateKey), rewrapResponse.EntityWrappedKey)
			if err != nil {
				return err
			}
			splits = append(splits, split)
		}
	}
	// Merge key splits back together
	payloadKey, err := tdfCrypto.KeyMerge(tdf.EncryptionInformation.Type, splits)
	if err != nil {
		return err
	}

	// Before we try to decrypt we need to valid the integrity of the rootSignature
	if err := tdf.EncryptionInformation.IntegrityInformation.Validate(payloadKey); err != nil {
		return err
	}
	alg, err := tdfCrypto.GetCryptoAlgorithm(tdf.EncryptionInformation.Method.Algorithm)
	if err != nil {
		return err
	}
	cryptoProvider, err := tdfCrypto.NewCryptoClientWithKey(alg, payloadKey)
	if err != nil {
		return err
	}

	// Open Payload File
	payload, err := tdfZip.Open(tdf.Payload.URL)
	if err != nil {
		return err
	}
	defer payload.Close()

	for _, segment := range tdf.EncryptionInformation.IntegrityInformation.Segments {
		// Read the next chunk
		chunk := make([]byte, segment.EncryptedSegmentSize)

		_, err := payload.Read(chunk)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		plainText, err := cryptoProvider.Decrypt(chunk)
		if err != nil {
			return errors.Join(errors.New("failed to decrypt segment"), err)
		}
		_, err = writer.Write(plainText)
		if err != nil {
			return err
		}
	}

	return nil
}

func (client *Client) GetManifest(reader io.ReaderAt, size int64) (tdf3.TDF, error) {
	var tdf tdf3.TDF
	tdfZip, err := zip.NewReader(reader, size)
	if err != nil {
		return tdf, err
	}

	// Find the file in the zip archive based on its name.
	var targetFile *zip.File
	for _, file := range tdfZip.File {
		if file.Name == manifestFileName {
			targetFile = file
			break
		}
	}
	if targetFile == nil {
		return tdf, errors.New("manifest.json not found")
	}
	targetFileReader, err := targetFile.Open()
	if err != nil {
		return tdf, err
	}
	defer targetFileReader.Close()
	content, err := io.ReadAll(targetFileReader)
	if err != nil {
		return tdf, err
	}

	err = json.Unmarshal(content, &tdf)
	if err != nil {
		return tdf, err
	}

	return tdf, nil
}

// this is a hack for hackathon
func (client *Client) GetEncryptedMetaData(reader io.ReaderAt, size int64) ([]byte, error) {

	// We need to work with the manifest from the zip archive
	tdf, err := client.GetManifest(reader, size)
	if err != nil {
		return nil, err
	}

	privateKey, err := tdfCrypto.ParsePrivateKey(client.PrivKey)
	if err != nil {
		return nil, err
	}

	var splits = make([][]byte, len(tdf.EncryptionInformation.KeyAccess)-1)
	for k, kao := range tdf.EncryptionInformation.KeyAccess {
		// Need to figure out how to handle other types
		if kao.Type == "wrapped" {
			var (
				rewrapRequest = new(kas.RequestBody)
			)
			rewrapRequest.KeyAccess = kao
			rewrapRequest.ClientPublicKey = string(client.PubKey)
			rewrapRequest.Policy = tdf.EncryptionInformation.Policy
			rewrapResponse, err := client.kas[k].RemoteRewrap(rewrapRequest, privateKey)
			// Get Wrapped Key
			if err != nil {
				return nil, err
			}

			// Unwrap our key from KAS
			split, err := tdfCrypto.DecryptOAEP(privateKey.(*rsa.PrivateKey), rewrapResponse.EntityWrappedKey)
			if err != nil {
				return nil, err
			}
			splits = append(splits, split)
		}
	}
	// Merge key splits back together
	payloadKey, err := tdfCrypto.KeyMerge(tdf.EncryptionInformation.Type, splits)
	if err != nil {
		return nil, err
	}

	// Before we try to decrypt we need to valid the integrity of the rootSignature
	if err := tdf.EncryptionInformation.IntegrityInformation.Validate(payloadKey); err != nil {
		return nil, err
	}

	for _, kao := range tdf.EncryptionInformation.KeyAccess {
		if kao.EncryptedMetadata != nil {
			var metadata *tdf3.Metadata
			err = json.Unmarshal(kao.EncryptedMetadata, &metadata)
			if err != nil {
				return nil, err
			}
			alg, err := tdfCrypto.GetCryptoAlgorithm(tdf.EncryptionInformation.Method.Algorithm)
			if err != nil {
				return nil, err
			}
			metaDataCryptoProvider, err := tdfCrypto.NewCryptoClientWithKey(alg, payloadKey)
			if err != nil {
				return nil, err
			}

			pt, err := metaDataCryptoProvider.Decrypt(metadata.CipherText)
			if err != nil {
				return nil, errors.Join(errors.New("failed to decrypt encrypted metadata"), err)
			}
			return pt, nil
		}
	}

	return nil, errors.New("no encrypted metadata found")
}
