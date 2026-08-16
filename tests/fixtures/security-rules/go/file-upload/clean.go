package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
)

func upload(w http.ResponseWriter, r *http.Request) {
	_, _, _ = r.FormFile("file")
	buf := make([]byte, 16)
	rand.Read(buf)
	name := hex.EncodeToString(buf)
	dst, _ := os.Create(filepath.Join("/uploads", name))
	defer dst.Close()
}
