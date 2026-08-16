// CWE-704: unsafe.Pointer cast for type punning between unrelated types
package main

import "unsafe"

func punned(buf []byte) uint32 {
	return *(*uint32)(unsafe.Pointer(&buf[0]))
}
