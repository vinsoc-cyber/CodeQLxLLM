// Recovered handler — panic caught by deferred recover
package main

import (
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("recovered: %v", rec)
			http.Error(w, "internal error", 500)
		}
	}()
	if r.URL.Path == "/crash" {
		panic("boom")
	}
	w.Write([]byte("ok"))
}
