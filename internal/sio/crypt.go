package sio

// EraseKey removes a key from casual memory viewing.
func EraseKey(a []byte) {
	for i := range a {
		a[i] = 0
	}
}
