package main

import (
	"io"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	_ = data
}
