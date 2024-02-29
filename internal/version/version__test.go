package version

import (
	"reflect"
	"testing"
)

func TestName(t *testing.T) {
	result := GetVersion()

	if reflect.TypeOf(result.Version).String() != "string" {
		t.Errorf("Expected string response")
	}

	if reflect.TypeOf(result.VersionLong).String() != "string" {
		t.Errorf("Expected string response")
	}
}
