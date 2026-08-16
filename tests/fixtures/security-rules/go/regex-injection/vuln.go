package main

import (
	"net/http"
	"regexp"
)

func h(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("p")
	regexp.Compile(p)
}
