package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func mockHandler(w http.ResponseWriter, r *http.Request) {}

func TestUpdateValidEntity(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("entity", "mockId")
	rr := httptest.NewRecorder()

	Update(mockHandler)(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestUpdateBlockedEntity(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("entity", "blockedId")
	rr := httptest.NewRecorder()

	Update(mockHandler)(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusForbidden)
	}

	expectedBody := "Access denied"
	if body := rr.Body.String(); body != expectedBody {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expectedBody)
	}
}

func TestUpdateRandomId(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("entity", "randomId")
	rr := httptest.NewRecorder()

	// Call the Update function with a mock handler
	Update(mockHandler)(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusForbidden)
	}
}

func TestUpsertValidEntity(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("entity", "mockId")
	rr := httptest.NewRecorder()

	Upsert(mockHandler)(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestUpsertBlockedEntity(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("entity", "blockedId")
	rr := httptest.NewRecorder()

	Upsert(mockHandler)(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusForbidden)
	}

	expectedBody := "Access denied"
	if body := rr.Body.String(); body != expectedBody {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expectedBody)
	}
}

func TestUpsertRandomId(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("entity", "randomId")
	rr := httptest.NewRecorder()

	// Call the Update function with a mock handler
	Upsert(mockHandler)(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusForbidden)
	}
}
