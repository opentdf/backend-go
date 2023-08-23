package plugins

import (
	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2/jwt"
	"log"
	"os"
	"time"
)

type AuditHooks interface {
	AuditHook()
	ErrAuditHook()
}

type EventType string
type TransactionType string

const (
	AccessDeniedEvent EventType = "access_denied"
	DecryptEvent      EventType = "decrypt"
	TesTinEvent       EventType = "testint"
)

const (
	CreateTransaction      TransactionType = "create"
	CreateErrorTransaction TransactionType = "create_error"
)

type TdfAttributes struct {
	dissem []string
	attrs  []string
}

type ActorAttributes struct {
	npe     bool
	actorId string
	attrs   []string
}

type AuditLog struct {
	id                   string
	transactionId        string
	transactionTimestamp string
	tdfId                string
	tdfName              string
	ownerId              string
	transactionType      TransactionType
	ownerOrganizationId  string
	eventType            EventType
	tdfAttributes        TdfAttributes
	actorAttributes      ActorAttributes
}

type dataAttributes interface {
	exportRaw() []string
}

type Policy struct {
	uuid string
}

type DataJson struct {
	policy    Policy
	keyAccess struct {
		header string
	}
}

type Dissem struct {
	list []string
}

type AuditHookReturnValue struct {
	uuid           string
	dissem         Dissem
	dataAttributes dataAttributes
}

// mock dependencies
func (p Policy) constructFromRawCanonical(pl Policy) Policy {
	return pl
}

type policyInfo struct {
}

type eccMode struct {
}

type symmetricAndPayloadConfig struct {
}

func (p policyInfo) parse(eccMode string, payloadConfig string, header string) (string, string) {
	return payloadConfig, header
}

func (s1 symmetricAndPayloadConfig) parse(s string) (string, string) {
	return s, s
}

func (receiver eccMode) parse(s string) (string, string) {
	return s, s
}

var SymmetricAndPayloadConfig = symmetricAndPayloadConfig{}
var ECCMode = eccMode{}
var PolicyInfo = policyInfo{}

// mock dependencies

var OrgId = os.Getenv("CONFIG_ORG_ID")
var policy = Policy{uuid: uuid.NewString()}

func AuditHook(returnValue AuditHookReturnValue) AuditHookReturnValue {
	log.SetPrefix("AuditHook: ")
	log.Println("OrgId", OrgId)
	res := returnValue
	policy := returnValue

	auditLog := AuditLog{
		id:                   uuid.NewString(),
		transactionId:        uuid.NewString(), // TODO
		transactionTimestamp: time.Now().Format(time.RFC3339Nano),
		tdfId:                policy.uuid,
		tdfName:              "",
		ownerId:              "",
		ownerOrganizationId:  OrgId,
		transactionType:      CreateTransaction,
		eventType:            DecryptEvent,
		tdfAttributes: TdfAttributes{
			dissem: []string{},
			attrs:  []string{},
		},
		actorAttributes: ActorAttributes{
			npe:     true,
			actorId: "",
			attrs:   []string{},
		},
	}

	log.Println("Raw auditLog", auditLog)

	for _, attr := range policy.dataAttributes.exportRaw() {
		auditLog.tdfAttributes.attrs = append(auditLog.tdfAttributes.attrs, attr)
	}
	auditLog.tdfAttributes.dissem = policy.dissem.list
	auditLog = ExtractInfoFromAuthToken(auditLog, "token")

	log.Println("Processed auditLog", auditLog)
	return res
}

func ErrAuditHook(err string, data string) {
	log.SetPrefix("ErrAuditHook: ")
	log.Println("OrgId", OrgId)

	if err != "AuthorizationError" {
		log.Println("Access Denied with", err)
		log.Fatal("Access Denied")
	}

	auditLog := AuditLog{
		id:                   uuid.NewString(),
		transactionId:        uuid.NewString(), // TODO
		transactionTimestamp: time.Now().Format(time.RFC3339Nano),
		tdfId:                "",
		tdfName:              "",
		ownerId:              "",
		ownerOrganizationId:  OrgId,
		transactionType:      CreateErrorTransaction,
		eventType:            AccessDeniedEvent,
		tdfAttributes: TdfAttributes{
			dissem: []string{},
			attrs:  []string{},
		},
		actorAttributes: ActorAttributes{
			npe:     true,
			actorId: "",
			attrs:   []string{},
		},
	}

	if "signedRequestToken" != data {
		log.Println("Rewrap success without signedRequestToken - should never get here")
		return
	}
	//decoded_request = jwt.decode(
	//	data["signedRequestToken"],
	//	options={"verify_signature": False},
	//algorithms=["RS256", "ES256", "ES384", "ES512"],
	//leeway=30,
	//)
	//requestBody = decoded_request["requestBody"]
	//json_string = requestBody.replace("'", '"')
	//dataJson = json.loads(json_string)
	//dataJson := data
	dataJson := DataJson{}

	// TODO
	if dataJson.policy.uuid == "ec:secp256r1" {
		// nano
		auditLog = ExtractPolicyDataFromNano(auditLog, dataJson, "", "")
		return
	}
	auditLog = ExtractPolicyDataFromTdf3(auditLog, dataJson)
	log.Println("AuditLog", auditLog)
}

func ExtractPolicyDataFromTdf3(auditLog AuditLog, dataJson DataJson) AuditLog {
	log.SetPrefix("ExtractPolicyDataFromTdf3: ")
	log.SetPrefix("ExtractPolicyDataFromTdf3: ")
	canonicalPolicy := dataJson.policy
	originalPolicy := policy.constructFromRawCanonical(canonicalPolicy)
	auditLog.tdfId = originalPolicy.uuid

	policy := AuditHookReturnValue{}
	for _, attr := range policy.dataAttributes.exportRaw() {
		auditLog.tdfAttributes.attrs = append(auditLog.tdfAttributes.attrs, attr)
	}
	auditLog.tdfAttributes.dissem = policy.dissem.list
	return auditLog
}

func ExtractPolicyDataFromNano(auditLog AuditLog, dataJson DataJson, context string, keyMaster string) AuditLog {
	log.SetPrefix("ExtractPolicyDataFromNano: ")

	header := dataJson.keyAccess.header

	eccMode, header := ECCMode.parse(header)
	payloadConfig, header := SymmetricAndPayloadConfig.parse(header)
	policyInfo, header := PolicyInfo.parse(eccMode, payloadConfig, header)

	//	private_key_bytes = key_master.get_key("KAS-EC-SECP256R1-PRIVATE").private_bytes(
	//		serialization.Encoding.DER,
	//		serialization.PrivateFormat.PKCS8,
	//		serialization.NoEncryption(),
	//	)
	//	decryptor = ecc_mode.curve.create_decryptor(
	//		header[0 : ecc_mode.curve.public_key_byte_length], private_key_bytes
	//	)
	//
	//	symmetric_cipher = payload_config.symmetric_cipher(
	//		decryptor.symmetric_key, b"\0" * (3 if legacy_wrapping else 12)
	//)
	//	policy_data = policy_info.body.data
	//
	//	policy_data_as_byte = base64.b64encode(
	//		symmetric_cipher.decrypt(
	//			policy_data[0 : len(policy_data) - payload_config.symmetric_tag_length],
	//			policy_data[-payload_config.symmetric_tag_length :],
	//		)
	//	)
	//	original_policy = Policy.construct_from_raw_canonical(
	//		policy_data_as_byte.decode("utf-8")
	//	)
	//

	policy := AuditHookReturnValue{}
	for _, attr := range policy.dataAttributes.exportRaw() {
		auditLog.tdfAttributes.attrs = append(auditLog.tdfAttributes.attrs, attr)
	}
	auditLog.tdfAttributes.dissem = policy.dissem.list

	return auditLog
}

func ExtractInfoFromAuthToken(auditLog AuditLog, token string) AuditLog {
	log.SetPrefix("ExtractInfoFromAuthToken: ")

	secret := []byte("itsa16bytesecret")
	tokenString := `eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..jg45D9nmr6-8awml.z-zglLlEw9MVkYHi-Znd9bSwc-oRGbqKzf9WjXqZxno.kqji2DiZHZmh-1bLF6ARPw`
	tok, err := jwt.ParseEncrypted(tokenString)

	if err != nil {
		log.Fatal(err)
	}

	decodedToken := jwt.Claims{}
	if err := tok.Claims(secret, &decodedToken); err != nil {
		log.Fatal(err)
	}
	log.Println(decodedToken)
	auditLog.ownerId = decodedToken.Subject

	//if decoded_auth.get("tdf_claims").get("entitlements"):
	//	attributes = set()
	//	# just put all entitlements into one list, dont seperate by entity for now
	//	for item in decoded_auth.get("tdf_claims").get("entitlements"):
	//		for attribute in item.get("entity_attributes"):
	//			attributes.add(attribute.get("attribute"))
	//	audit_log["actorAttributes"]["attrs"] = list(attributes)
	//	if decoded_auth.get("azp"):
	//		audit_log["actorAttributes"]["actorId"] = decoded_auth.get("azp")

	return auditLog
}
