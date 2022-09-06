// sio provides functions to read and write strings, and in-band diagnostic messages
// on a record-oriented stream. It also includes some primitives needed by several components.
package sio

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"io"

	"github.com/forsyth/auth/internal/ssl"
)

// ReadString returns the next string read from fd, relying on SSL/TLS to provide a record-oriented
// stream, so it will read and return a complete record. By convention, a string starting "!"
// introduces an error message, to be returned to the caller.
func ReadString(fd io.Reader) (string, error) {
	buf := make([]byte, ssl.MaxMsg)
	n, err := fd.Read(buf[:])
	if err != nil {
		return "", err
	}
	s := string(buf[0:n])
	//fmt.Printf("-> %s\n", s)
	if s[0] == '!' {
		return "", errors.New(s[1:])
	}
	return s, nil
}

// WriteString writes a string to stream f, returning any error (discarding the uninteresting byte count).
func WriteString(f io.Writer, s string) error {
	_, err := io.WriteString(f, s)
	return err
}

// WriteError sends a diagnostic to the remote, flagged as such, and also returns it locally as an error.
func WriteError(fd io.Writer, s string) error {
	fmt.Fprintf(fd, "!%s", s) // if it doesn't work, local error s has priority, since we'll stop
	return errors.New(s)
}

// Enc64 returns a buffer encoded in base 64.
func Enc64(buf []byte) string {
	return base64.StdEncoding.EncodeToString(buf)
}

// Dec64 decodes a buffer represented in base64, and returns it as a big.Int.
func Dec64(s string) (*big.Int, error) {
	a, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	i := new(big.Int)
	i.SetBytes(a)
	return i, nil
}
