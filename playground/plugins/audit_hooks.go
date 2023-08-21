package main

import (
	"fmt"
	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2/jwt"
	"log"
	"os"
	"time"
)

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

type Dissem struct {
	list []string
}

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

type ReturnValue struct {
	uuid           string
	dissem         Dissem
	dataAttributes dataAttributes
}

type Policy struct {
	uuid string
}

func (p Policy) constructFromRawCanonical(pl Policy) Policy {
	return pl
}

var policy = Policy{uuid: uuid.NewString()}

var OrgId = os.Getenv("CONFIG_ORG_ID")

func AuditHook(functionName string, returnValue ReturnValue) ReturnValue {
	log.SetPrefix("AuditHook: ")

	res := returnValue
	policy := returnValue
	claims := returnValue

	log.Println("res, policy, claims", res, policy, claims)

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

	log.Println("raw auditLog", auditLog)

	for _, attr := range policy.dataAttributes.exportRaw() {
		auditLog.tdfAttributes.attrs = append(auditLog.tdfAttributes.attrs, attr)
	}

	auditLog.tdfAttributes.dissem = policy.dissem.list
	auditLog = extractInfoFromAuthToken(auditLog, "token")

	log.Println(auditLog)

	return res
}

func errAuditHook(functionName string, err string, data string) {
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

	auditLog = extractInfoFromAuthToken(auditLog, "token")

	//# wrap in try except -- should not fail since succeeded before
	//if "signedRequestToken" not in data:
	//logger.error(
	//	"Rewrap success without signedRequestToken - should never get here"
	//)
	//else:
	//decoded_request = jwt.decode(
	//	data["signedRequestToken"],
	//	options={"verify_signature": False},
	//algorithms=["RS256", "ES256", "ES384", "ES512"],
	//leeway=30,
	//)
	//requestBody = decoded_request["requestBody"]
	//json_string = requestBody.replace("'", '"')
	//dataJson = json.loads(json_string)
	//if dataJson.get("algorithm", "rsa:2048") == "ec:secp256r1":
	//# nano
	//audit_log = extract_policy_data_from_nano(
	//audit_log, dataJson, context, key_master
	//)
	//else:
	//# tdf3

	dataJson := DataJson{}
	auditLog = ExtractPolicyDataFromTdf3(auditLog, dataJson)
	log.Println("AuditLog", auditLog)
	//except Exception as e:
	//logger.error(f"Error on err_audit_hook - unable to log audit: {str(e)}")
}

type DataJson struct {
	policy Policy
}

func ExtractPolicyDataFromTdf3(auditLog AuditLog, dataJson DataJson) AuditLog {
	log.SetPrefix("ExtractPolicyDataFromTdf3: ")
	canonicalPolicy := dataJson.policy
	originalPolicy := policy.constructFromRawCanonical(canonicalPolicy)
	auditLog.tdfId = originalPolicy.uuid

	policy := ReturnValue{}
	for _, attr := range policy.dataAttributes.exportRaw() {
		auditLog.tdfAttributes.attrs = append(auditLog.tdfAttributes.attrs, attr)
	}
	auditLog.tdfAttributes.dissem = policy.dissem.list
	return auditLog
}

func ExtractPolicyDataFromNano(auditLog AuditLog, dataJson string, context string, keyMaster string) AuditLog {
	log.SetPrefix("ExtractPolicyDataFromNano: ")

	//	header = base64.b64decode(dataJson["keyAccess"]["header"])
	//	legacy_wrapping = (
	//		os.environ.get("LEGACY_NANOTDF_IV") == "1"
	//	) and packaging.version.parse(
	//		context.get("virtru-ntdf-version") or "0.0.0"
	//	) < packaging.version.parse(
	//		"0.0.1"
	//	)
	//
	//	(ecc_mode, header) = ECCMode.parse(ResourceLocator.parse(header[3:])[1])
	//	# extract payload config from header.
	//	(payload_config, header) = SymmetricAndPayloadConfig.parse(header)
	//	# extract policy from header.
	//	(policy_info, header) = PolicyInfo.parse(ecc_mode, payload_config, header)
	//
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
	policy := ReturnValue{}
	for _, attr := range policy.dataAttributes.exportRaw() {
		auditLog.tdfAttributes.attrs = append(auditLog.tdfAttributes.attrs, attr)
	}
	auditLog.tdfAttributes.dissem = policy.dissem.list
	return auditLog
}

func extractInfoFromAuthToken(auditLog AuditLog, token string) AuditLog {
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

func main() {
	auditLog := AuditLog{
		id:                   uuid.NewString(),
		transactionId:        uuid.NewString(), // TODO
		transactionTimestamp: time.Now().Format(time.RFC3339Nano),
		tdfId:                "",
		tdfName:              "",
		ownerId:              "",
		ownerOrganizationId:  OrgId,
		transactionType:      CreateTransaction,
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
	fmt.Println(auditLog.ownerId)
	newAuditLog := extractInfoFromAuthToken(auditLog, "token")
	fmt.Println(newAuditLog.ownerId)
	//AuditHook("functionName", returnValue)
}
