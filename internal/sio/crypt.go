package sio

import (
	"crypto/hmac"
	"hash"
)

// EraseKey zeroes the bytes of a key, removing it from casual memory viewing.
// It mattered more in Plan 9 and Inferno because allocated
// arrays weren't guaranteed to be zero (unless mallocz was used),
// and if they reused space from a key, might accidentally leak the value.
// It probably doesn't really matter with Go, except for archaic core files.
func EraseKey(a []byte) {
	for i := range a {
		a[i] = 0
	}
}

// HMAC applies h to buf with the given key, returning the MAC.
func HMAC(h func() hash.Hash, buf []byte, key []byte) []byte {
	mac := hmac.New(h, key)
	mac.Write(buf)
	return mac.Sum(nil)
}
