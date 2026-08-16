// encoding/binary — safe, portable
package main

import "encoding/binary"

func parsed(buf []byte) uint32 {
	return binary.LittleEndian.Uint32(buf)
}
