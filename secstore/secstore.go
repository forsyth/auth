package secstore

//
// interact with the Plan 9 secstore
//

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
)

// need keyring equivalents: AESbsize, AESstate, DigestState, IPint
// SSL
// random
// base64 encoding

const MaxFileSize = 128 * 1024 // arbitrary default, same as Plan 9
const MaxMsg = 4096

const VERSION = "secstore"

// Version returns the secstore version and algorithm, to be sent to the peer.
func Version() string {
	return fmt.Sprintf("%s\tPAK\n", VERSION)
}

/*
	init:		fn();
	privacy:	fn(): int;
	cansecstore:	fn(addr: string, user: string): int;
	mkseckey:	fn(pass: string): array of byte;
	connect:		fn(addr: string, user: string, pwhash: array of byte): (ref Dial->Connection, string, string);
	dial:		fn(addr: string): ref Dial->Connection;
	auth:		fn(conn: ref Dial->Connection, user: string, pwhash: array of byte): (string, string);
	sendpin:	fn(conn: ref Dial->Connection, pin: string): int;
	files:		fn(conn: ref Dial->Connection): list of (string, int, string, string, array of byte);
	getfile:	fn(conn: ref Dial->Connection, filename: string, maxsize: int): array of byte;
	remove:	fn(conn: ref Dial->Connection, filename: string): int;
	putfile:	fn(conn: ref Dial->Connection, filename: string, data: array of byte): int;
	bye:		fn(conn: ref Dial->Connection);

	mkfilekey:	fn(pass: string): array of byte;
	decrypt:	fn(a: array of byte, key: array of byte): array of byte;
	encrypt:	fn(a: array of byte, key: array of byte): array of byte;
	erasekey:	fn(a: array of byte);

	lines:	fn(file: array of byte): list of array of byte;
*/

// readstr returns the next string read from fd, relying on SSL/TLS to provide a record-oriented
// stream, so it will read and return a complete record.
func readstr(fd io.Reader) (string, error) {
	buf := make([]byte, 500)
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

// writerr sends a diagnostic to the remote, flagged as such, and returns it locally as an error.
func writerr(fd io.Writer, s string) error {
	fmt.Fprintf(fd, "!%s", s)
	return errors.New(s)
}

// mkSecrets converts a session key to a pair of encryption keys, one for each direction.
func mkSecrets(sigma []byte, direction int) [2][]byte {
	var secretin, secretout []byte
	if direction != 0 {
		secretout = hmac_sha1(sigma, []byte("one"))
		secretin = hmac_sha1(sigma, []byte("two"))
	} else {
		secretout = hmac_sha1(sigma, []byte("two"))
		secretin = hmac_sha1(sigma, []byte("one"))
	}
	return [2][]byte{secretin, secretout}
}

func KeyHash(s string) []byte {
	key := []byte(s)
	state := sha1.New()
	state.Write(key)
	erasekey(key)
	return state.Sum(nil)
}
