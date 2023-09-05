package plugins

import (
	"fmt"
	"os"
)

type Params struct {
	authority string
}

type AttrDefs struct {
	authorityNamespace string
	authority          string
	values             []string
	order              []string
}

func _translateOtdfAttrDefs(attrdefs []AttrDefs) {
	//KAS has an (undocumented) format for attribute definitions
	//that differs from the one OpenTDF uses by two (2) property names
	//so just append those duplicate properties to the dict and
	//call it a day - the schema emitted by the AA shouldn't be
	//tightly coupled to KAS processing and it's not worth maintaining
	//separate serverside handlers for this.
	//
	//	You might ask why this plugin/kas data model isn't just changed to use the
	//new route/handler.
	//
	//	Well, that's because the new handler does non-optional pagination and JWT auth,
	//and KAS isn't set up to do the former, and doesn't need to do the latter (E-W traffic)

	for _, attr := range attrdefs {
		if attr.authority != "" {
			attr.authorityNamespace = attr.authority
		}

		if len(attr.order) > 0 {
			attr.values = attr.order
		}
	}
}

type OpenTDFAttrAuthorityPlugin struct {
	_host    string
	_headers struct{}
	_timeout int
}

func (receiver OpenTDFAttrAuthorityPlugin) fetchDefinitionFromAuthorityByNs(namespace string) {
	caCertPath := os.Getenv("CA_CERT_PATH")
	clientCertPath := os.Getenv("CLIENT_CERT_PATH")
	clientKeyPath := os.Getenv("CLIENT_KEY_PATH")

	uri := fmt.Sprintf("%s/v1/attrName", receiver._host)

	params := Params{
		authority: namespace,
	}

	fmt.Println(caCertPath, clientCertPath, clientKeyPath, uri, params)

}

func (receiver OpenTDFAttrAuthorityPlugin) fetchAttributes() {

}

func (receiver OpenTDFAttrAuthorityPlugin) update() {

}

func (receiver OpenTDFAttrAuthorityPlugin) healthz() {

}

// softhsm2-util --show-slots
// pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-private.pem --type privkey --id 1 --label development-rsa-kas
// openssl rsa -in kas-private.pem -check
