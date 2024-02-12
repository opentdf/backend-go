package main

import (
	"fmt"
	"net/http"
	"os"
	"reflect"
	"testing"
)

func TestCreateLogger(t *testing.T) {
	output, err := CreateLogger()

	if err != nil {
		t.Errorf("Expected no error")
	}

	res, _ := os.Stat(LogFileName)

	if res.Name() != LogFileName {
		t.Errorf("Expected file %s created", LogFileName)
	}

	if reflect.TypeOf(output).String() != "*slog.Logger" {
		t.Errorf("Expected *slog.Logger returned")
	}

	err1 := os.Remove(LogFileName)
	if err1 != nil {
		panic(err1)
	}
}

func TestAuditHook(t *testing.T) {
	var g a
	handler := g.AuditHook(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	fmt.Println("handler", reflect.TypeOf(handler).String())

	if reflect.TypeOf(handler).String() != "http.HandlerFunc" {
		t.Errorf("Expected http.HandlerFunc returned")
	}

	err1 := os.Remove(LogFileName)
	if err1 != nil {
		panic(err1)
	}
}

func TestErrAuditHook(t *testing.T) {
	output := ErrAuditHook("AuthorizationError")

	if reflect.TypeOf(output).String() != "main.AuditLog" {
		t.Errorf("Expected AuditLog response")
	}
}

func TestExtractPolicyDataFromTdf3(t *testing.T) {
	auditLog := AuditLog{}
	dataJson := DataJson{}
	output := ExtractPolicyDataFromTdf3(auditLog, dataJson)

	if reflect.TypeOf(output).String() != "main.AuditLog" {
		t.Errorf("Expected AuditLog response")
	}
}

func TestExtractPolicyDataFromNano(t *testing.T) {
	auditLog := AuditLog{}
	dataJson := DataJson{}
	output := ExtractPolicyDataFromNano(auditLog, dataJson, "context", "keyMaster")

	if reflect.TypeOf(output).String() != "main.AuditLog" {
		t.Errorf("Expected AuditLog response")
	}
}

func TestExtractInfoFromAuthToken(t *testing.T) {
	auditLog := AuditLog{}
	output := ExtractInfoFromAuthToken(auditLog, "token")

	if reflect.TypeOf(output).String() != "main.AuditLog" {
		t.Errorf("Expected AuditLog response")
	}
}
