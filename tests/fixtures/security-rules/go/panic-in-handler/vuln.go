// CWE-248: handler panics without defer recover
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/crash" {
		panic("boom") // unrecovered
	}
	w.Write([]byte("ok"))
}
