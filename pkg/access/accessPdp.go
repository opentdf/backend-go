package access

import (
	"log"
	accesspdp "github.com/virtru/access-pdp/pdp"
	attrs "github.com/virtru/access-pdp/attributes"
	"go.uber.org/zap"
	"context"
)

func canAccess(entityID string, policy Policy, claims ClaimsObject, attrDefs []attrs.AttributeDefinition) bool {
	if checkDissems(policy.Body.Dissem, entityID) && checkAttributes(policy.Body.DataAttributes, claims.Entitlements, attrDefs) {
		return true
	} else {
		return false
	}
}

func checkDissems(dissems []string, entityID string) bool {
	if len(dissems)==0 || contains(dissems, entityID) {
		return true
	} else {
		return false
		// logger.debug(f"Entity {entity_id} is not on dissem list {dissem.list}")
        // raise AuthorizationError("Entity is not on dissem list.")
	}
}

func checkAttributes(dataAttrs []Attribute, entitlements []Entitlement, attrDefs []attrs.AttributeDefinition) bool {
	zapLog, _ := zap.NewDevelopment()

	// convert data and entitty attrs to attrs.AttributeInstance
	log.Println("Converting data attrs to instances")
	dataAttrInstances := convertAttrsToAttrInstances(dataAttrs)
	entityAttrMap := convertEntitlementsToEntityAttrMap(entitlements)

	accessPDP := accesspdp.NewAccessPDP(zapLog.Sugar())

	decisions, err := accessPDP.DetermineAccess(dataAttrInstances, entityAttrMap, attrDefs, context.Background())
	if err != nil {
		log.Panic(err)
	}
	// check the decisions
	for _, decision := range decisions {
		if !decision.Access {
			return false
		}
	}
	return true
}

func convertAttrsToAttrInstances(attributes []Attribute) []attrs.AttributeInstance {
	log.Println("Converting to attr instances")
	var instances []attrs.AttributeInstance
	for _, attr := range attributes {
		log.Printf("%+v", attr)
		instance, err := attrs.ParseInstanceFromURI(attr.URI)
		if err != nil {
			log.Fatal(err)
		}
		instances = append(instances, instance)
	}
	return instances
}

func convertEntitlementsToEntityAttrMap(entitlements []Entitlement) map[string][]attrs.AttributeInstance {
	log.Println("Converting to entity map")
	entityAttrMap := make(map[string][]attrs.AttributeInstance)
	for _, entitlement := range entitlements {
		entityAttrMap[entitlement.EntityID] = convertAttrsToAttrInstances(entitlement.EntityAttributes)
	}
	return entityAttrMap
}

func contains(s []string, e string) bool {
    for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}

