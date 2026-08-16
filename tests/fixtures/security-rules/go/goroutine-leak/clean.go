// Buffered channel — goroutine completes without a receiver
package main

import "fmt"

func bounded() {
	ch := make(chan int, 1)
	go func() {
		ch <- 42
		fmt.Println("done")
	}()
	v := <-ch
	fmt.Println(v)
}
