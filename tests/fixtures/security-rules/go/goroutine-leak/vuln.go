// CWE-405: goroutine writes to unbuffered channel without receiver guard
package main

import "fmt"

func leaker() {
	ch := make(chan int)
	go func() {
		ch <- 42
		fmt.Println("done") // unreachable if no receiver
	}()
	// no receive — goroutine leaks
}
