package secstore

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strconv"
	"time"
)

// DirEntry describes a file stored by secstore.
type DirEntry struct {
	Name    string    // file name
	Size    uint64    // file size in bytes
	ModTime time.Time // time last stored
	Hash    []byte    // hash of contents, typically sha1 (tell by length)
}

// Files returns a list of the files in the user's secstore.
func Files(conn net.Conn) ([]DirEntry, error) {
	file, err := GetFile(conn, ".", 0)
	if err != nil {
		return nil, fmt.Errorf("error reading secstore directory: %w", err)
	}
	var files []DirEntry
	scanner := bufio.NewScanner(bytes.NewReader(file))
	for scanner.Scan() {
		s := scanner.Text()
		// cursed format for directory entries
		// factotum\t2552 Dec  9 13:04:49 GMT 2005 n9wSk45SPDxgljOIflGQoXjOkjs=
		i := 0
		for ; i < len(s) && s[i] != '\t' && s[i] != ' '; i++ { // name can have trailing spaces, stop at first
		}
		name := s[0:i]
		for ; i < len(s) && (s[i] == ' ' || s[i] == '\t'); i++ { // start of size
		}
		j := i
		for ; j < len(s) && s[j] != ' '; j++ { // end of size
		}
		size, err := strconv.ParseUint(s[i:j], 10, 64)
		if err != nil {
			size = 0
		}
		for i = j; i < len(s) && s[i] == ' '; i++ { // start of date
		}
		mtime, _ := time.Parse("Jan _2 15:04:05 MST 2006", s[i:i+24]) // UnixDate without weekday
		//fmt.Printf("mtime: %q %s %v\n", s[i: i+24], mtime, err)
		i += 24 + 1                                  // start of hash
		for j = i; j < len(s) && s[j] != '\n'; j++ { // end of hash
		}
		sha1, err := dec64(s[i:j])
		if err != nil {
			sha1 = nil
		}
		files = append(files, DirEntry{
			Name:    name,
			Size:    size,
			ModTime: mtime,
			Hash:    sha1.Bytes(),
		})
	}
	return files, nil
}

// Getfile fetches a file "name" from the user's secstore, returning its
// contents, which will normally be encrypted by the user's file key.
func GetFile(conn net.Conn, name string, maxsize uint64) ([]byte, error) {
	if maxsize == 0 {
		maxsize = MaxFileSize
	}
	_, err := fmt.Fprintf(conn, "GET %s\n", name)
	if err != nil {
		return nil, fmt.Errorf("can't write request: %w", err)
	}
	s, err := readString(conn)
	if err != nil {
		return nil, fmt.Errorf("can't get file: %w", err)
	}
	nb, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("secstore sent invalid file size: %q (%w)", s, err)
	}
	// strange convention, given available !error syntax
	switch {
	case nb == -1:
		return nil, fmt.Errorf("remote file %q does not exist", name)
	case nb == -3 || uint64(nb) > maxsize:
		return nil, fmt.Errorf("implausible file size %d for %q", nb, name)
	case nb < 0:
		return nil, fmt.Errorf("GET refused for %q", name)
	}
	file := make([]byte, nb)
	for nr := int64(0); nr < nb; {
		n, err := conn.Read(file[nr:nb])
		if err != nil {
			return nil, fmt.Errorf("error reading %q: %w", name, err)
		}
		if n == 0 {
			return nil, fmt.Errorf("empty file chunk reading %q at offset %d", name, nr)
		}
		nr += int64(n)
	}
	return file, nil
}

// PutFile adds or updates a file "name" in the user's secstore,
// where data provides the new contents, which should be previously encrypted.
func PutFile(conn net.Conn, name string, data []byte) error {
	if len(data) > MaxFileSize {
		return fmt.Errorf("%q: file too long", name)
	}
	_, err := fmt.Fprintf(conn, "PUT %s\n", name)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(conn, "%d", len(data))
	if err != nil {
		return err
	}
	for o := 0; o < len(data); {
		n := len(data) - o
		if n > MaxMsg {
			n = MaxMsg
		}
		_, err = conn.Write(data[o : o+n])
		if err != nil {
			return err
		}
		o += n
	}
	return nil
}

// Remove removes a file from the user's secstore.
func Remove(conn net.Conn, name string) error {
	_, err := fmt.Fprintf(conn, "RM %s\n", name)
	if err != nil {
		// TO DO: should have ack
		return fmt.Errorf("can't remove %q: %w", name, err)
	}
	return nil
}
