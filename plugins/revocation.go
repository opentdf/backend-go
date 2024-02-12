package main

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
)

type b string

type entity struct {
	userId string
}

var Revocation b

//var allowlistEnv = os.Getenv("EO_ALLOW_LIST")
//var blockListEnv = os.Getenv("EO_BLOCK_LIST")

var allowlistEnv = "mockId,anotherId"
var blockListEnv = "blockedId"

func Update(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		Entity := r.Header.Get("entity")
		mockEntity := entity{userId: Entity}
		if !match(mockEntity) {
			w.WriteHeader(http.StatusForbidden)
			_, err := fmt.Fprint(w, "Access denied")
			if err != nil {
				panic(err)
			}
		}

		next(w, r)
	}
}

func Upsert(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		Entity := r.Header.Get("entity")
		mockEntity := entity{userId: Entity}
		if !match(mockEntity) {
			w.WriteHeader(http.StatusForbidden)
			_, err := fmt.Fprint(w, "Access denied")
			if err != nil {
				panic(err)
			}
		}

		next(w, r)
	}
}

func match(entity entity) bool {
	fmt.Println("entity", entity.userId)

	allows := strings.Split(allowlistEnv, ",")
	blocks := strings.Split(blockListEnv, ",")

	fmt.Println("allows", allows)
	fmt.Println("blocks", blocks)

	if slices.Contains(blocks, entity.userId) {
		return false
	}

	if slices.Contains(allows, "*") {
		return true
	}

	return slices.Contains(allows, entity.userId)
}
