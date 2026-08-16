package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func upload(w http.ResponseWriter, r *http.Request) {
	_, header, _ := r.FormFile("file")
	dst, _ := os.Create(filepath.Join("/uploads", header.Filename))
	defer dst.Close()
}
