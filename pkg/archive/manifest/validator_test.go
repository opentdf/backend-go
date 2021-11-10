package manifest

import (
	"io/ioutil"
	"testing"
)

func TestValid(t *testing.T) {
	f, err := ioutil.ReadFile("testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	err = Valid(f)
	if err != nil {
		t.Fatal(err)
	}
	err = Valid([]byte("invalid-json"))
	if err == nil {
		t.Fail()
	}
	t.Log(err)
	t.Log("Valid")
}
