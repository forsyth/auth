package secstore

import (
	"errors"
	"fmt"
	"io"
)

// readstr returns the next string read from fd, relying on SSL/TLS to provide a record-oriented
// stream, so it will read and return a complete record. By convention, a string starting "!"
// introduces an error message, to be returned to the caller.
func readString(fd io.Reader) (string, error) {
	buf := make([]byte, MaxMsg)
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

// writeString writes a string to stream f, returning any error (discarding the uninteresting byte count).
func writeString(f io.Writer, s string) error {
	_, err := io.WriteString(f, s)
	return err
}

// writeError sends a diagnostic to the remote, flagged as such, and also returns it locally as an error.
func writeError(fd io.Writer, s string) error {
	fmt.Fprintf(fd, "!%s", s) // if it doesn't work, local error s has priority, since we'll stop
	return errors.New(s)
}
