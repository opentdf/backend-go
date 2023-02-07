package access

import (
	"log"
	accesspdp "github.com/virtru/access-pdp/pdp"
	attrs "github.com/virtru/access-pdp/attributes"
	"go.uber.org/zap"
	"context"
	"errors"
)

func canAccess(entityID string, policy Policy, claims ClaimsObject, attrDefs []attrs.AttributeDefinition) (bool, error) {
	dissemAccess, err := checkDissems(policy.Body.Dissem, entityID)
	if err != nil {
		// logger.Warn("Error in dissem access decision")
		log.Println("Error in dissem access decision")
		return false, err
	}
	attrAccess, err := checkAttributes(policy.Body.DataAttributes, claims.Entitlements, attrDefs)
	if err != nil {
		// logger.Warn("Error in attributes access decision")
		log.Println("Error in attributes access decision")
		return false, err
	}
	if dissemAccess && attrAccess {
		return true, nil
	} else {
		return false, nil
	}
}

func checkDissems(dissems []string, entityID string) (bool, error) {
	if entityID == "" {
		err := errors.New("No entityID recieved in dissems access decision")
		return false, err
	}
	if len(dissems)==0 || contains(dissems, entityID) {
		return true, nil
	} else {
		return false, nil
		// logger.debug(f"Entity {entity_id} is not on dissem list {dissem.list}")
        // raise AuthorizationError("Entity is not on dissem list.")
	}
}

func checkAttributes(dataAttrs []Attribute, entitlements []Entitlement, attrDefs []attrs.AttributeDefinition) (bool, error) {
	zapLog, _ := zap.NewDevelopment()

	// convert data and entitty attrs to attrs.AttributeInstance
	log.Println("Converting data attrs to instances")
	dataAttrInstances, err := convertAttrsToAttrInstances(dataAttrs)
	if err != nil {
		// logger.Warn("Error converting data attributes to AttributeInstance")
		log.Printf("Error converting data attributes to AttributeInstance")
		return false, err
	}
	entityAttrMap, err := convertEntitlementsToEntityAttrMap(entitlements)
	if err != nil {
		// logger.Warn("Error converting entitlements to entity attribute map")
		log.Printf("Error converting entitlements to entity attribute map")
		return false, err
	}

	accessPDP := accesspdp.NewAccessPDP(zapLog.Sugar())

	decisions, err := accessPDP.DetermineAccess(dataAttrInstances, entityAttrMap, attrDefs, context.Background())
	if err != nil {
		// logger.Warn("Error recieved from accessPDP")
		log.Printf("Error recieved from accessPDP")
		return false, err
	}
	// check the decisions
	for _, decision := range decisions {
		if !decision.Access {
			return false, nil
		}
	}
	return true, nil
}

func convertAttrsToAttrInstances(attributes []Attribute) ([]attrs.AttributeInstance, error) {
	log.Println("Converting to attr instances")
	var instances []attrs.AttributeInstance
	for _, attr := range attributes {
		log.Printf("%+v", attr)
		instance, err := attrs.ParseInstanceFromURI(attr.URI)
		if err != nil {
			// logger.Warn("Error parsing AttributeInstance from URI")
			log.Printf("Error parsing AttributeInstance from URI")
			return nil, err
		}
		instances = append(instances, instance)
	}
	return instances, nil
}

func convertEntitlementsToEntityAttrMap(entitlements []Entitlement) (map[string][]attrs.AttributeInstance, error) {
	log.Println("Converting to entity map")
	entityAttrMap := make(map[string][]attrs.AttributeInstance)
	for _, entitlement := range entitlements {
		instances, err := convertAttrsToAttrInstances(entitlement.EntityAttributes)
		if err != nil {
			// logger.Warn("Error converting entity attributes to AttributeInstance")
			log.Printf("Error converting entity attributes to AttributeInstance")
			return nil, err
		}
		entityAttrMap[entitlement.EntityID] = instances
	}
	return entityAttrMap, nil
}

func contains(s []string, e string) bool {
    for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}

