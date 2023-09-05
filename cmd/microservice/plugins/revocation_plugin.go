package main

import (
	"fmt"
	"net/http"
	"slices"
)

type b string

type entity struct {
	userId string
}

var Revocation b

func update(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//Entity := r.Header.Get("entity")
		mockEntity := entity{userId: "mockId"}
		if !match(mockEntity) {
			w.WriteHeader(http.StatusUnauthorized)
			_, err := fmt.Fprint(w, "Missing Authorization header")
			if err != nil {
				panic(err)
			}
		}

		next(w, r)
	}
}

func upsert(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//Entity := r.Header.Get("entity")
		mockEntity := entity{userId: "mockId"}
		if !match(mockEntity) {
			w.WriteHeader(http.StatusUnauthorized)
			_, err := fmt.Fprint(w, "Missing Authorization header")
			if err != nil {
				panic(err)
			}
		}

		next(w, r)
	}
}

func match(entity entity) bool {
	allows := []string{""}
	blocks := []string{""}

	if slices.Contains(blocks, entity.userId) {
		return false
	}

	if slices.Contains(allows, "*") {
		return true
	}

	return slices.Contains(allows, entity.userId)
}
