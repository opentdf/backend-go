package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
)

// validate manifest.json
// well-formed JSON
// validate against spec version
// validate all values in manifest
// check integrity of signatures, JWT
// validate URLs can be found

func Valid(m []byte) error {
	if !json.Valid(m) {
		return errors.New("JSON invalid")
	}
	var manifest Object
	err := json.Unmarshal(m, &manifest)
	if err != nil {
		return err
	}
	fmt.Println(manifest)
	return err
}
