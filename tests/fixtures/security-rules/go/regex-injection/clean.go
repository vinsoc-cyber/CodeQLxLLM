package main

import (
	"net/http"
	"regexp"
)

func h(w http.ResponseWriter, r *http.Request) {
	_ = r
	regexp.MustCompile("^[a-z]+$")
}
