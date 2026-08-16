package main

import "os"

func setup() error {
	return os.Chmod("/usr/local/bin/tool", 0o4755)
}
