// Package secstore interacts with a Plan 9 secstore service:
// authenticating a user, listing, fetching, storing and removing encrypted files.
package secstore

import (
	"crypto/sha1"
	"fmt"
	"net"

	"github.com/forsyth/auth/internal/ssl"
)

const MaxFileSize = 128 * 1024 // arbitrary default, same as Plan 9
const MaxMsg = 4096

const VERSION = "secstore"

// Version returns the secstore version and algorithm, to be sent to the peer.
func Version() string {
	return fmt.Sprintf("%s\tPAK\n", VERSION)
}

/*
	mkseckey:	fn(pass: string): array of byte;
	connect:		fn(addr: string, user: string, pwhash: array of byte): (ref Dial->Connection, string, string);
	dial:		fn(addr: string): ref Dial->Connection;
	auth:		fn(conn: ref Dial->Connection, user: string, pwhash: array of byte): (string, string);
	files:		fn(conn: ref Dial->Connection): list of (string, int, string, string, array of byte);
	getfile:	fn(conn: ref Dial->Connection, filename: string, maxsize: int): array of byte;
	remove:	fn(conn: ref Dial->Connection, filename: string): int;
	putfile:	fn(conn: ref Dial->Connection, filename: string, data: array of byte): int;
	bye:		fn(conn: ref Dial->Connection);

	mkfilekey:	fn(pass: string): array of byte;
	decrypt:	fn(a: array of byte, key: array of byte): array of byte;
	encrypt:	fn(a: array of byte, key: array of byte): array of byte;
	erasekey:	fn(a: array of byte);
*/

// EncryptionKeys converts a session key to a pair of encryption keys, one for each direction.
func EncryptionKeys(sigma []byte, direction int) [2][]byte {
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

// KeyHash return the SHA1 hash of a password.
func KeyHash(s string) []byte {
	key := []byte(s)
	state := sha1.New()
	state.Write(key)
	erasekey(key)
	return state.Sum(nil)
}

// Dial connects to the secstore at the given network address,
// pushes an SSL instance (initially in clear), and returns the resulting connection.
func Dial(network, addr string) (*ssl.Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return ssl.Client(conn), nil
}

// Auth authenticates the connection for the given user and password hash,
// engages line encryption using the negotiated session key,
// and returns the peer name and an optional demand for further
// authentication. Currently the only demand is "need pin", which requires
// SendPin to be applied to the connection to send the PIN.
// On successful return, the connection is ready to receive secstore commands.
func Auth(conn *ssl.Conn, user string, pwhash []byte) (string, string, error) {
	pak, err := Client(conn, Version(), user, pwhash)
	if err != nil {
		return "", "", fmt.Errorf("failed to authenticate: %w", err)
	}
	keys := EncryptionKeys(pak.Session, 0)
	err = conn.StartCipher(keys[0], keys[1])
	if err != nil {
		return pak.Peer, "", fmt.Errorf("pushing SSL: %w", err)
	}
	s, err := readString(conn)
	if err != nil {
		return pak.Peer, "", fmt.Errorf("connection read error: %w", err)
	}
	if s == "STA" {
		return pak.Peer, "need pin", nil
	}
	if s != "OK" {
		return pak.Peer, "", fmt.Errorf("unexpected response: %q", s)
	}
	return pak.Peer, "", nil
}

// Connect connects to a secstore service at the given network and address, and
// returns (conn, sname, diag, err). On success,
// the connection is authenticated to the given user, using the password as hashed by KeyHash.
// The connection can then be used for secstore commands, typically via Files, GetFile, PutFIle etc.
// Connect also returns the remote server's name for itself, as exchanged using the
// key-exchange protocol, typically just "secstore". If diag is not "", it contains a demand
// for an extra level of authentication, currently only "need pin". See Auth for what to do.
func Connect(network, addr string, user string, pwhash []byte) (*ssl.Conn, string, string, error) {
	conn, err := Dial(network, addr)
	if err != nil {
		return nil, "", "", err
	}
	sname, diag, err := Auth(conn, user, pwhash)
	return conn, sname, diag, nil
}

// CanSecstore checks whether secstore exists at the remote, and has a given user.
// The remote might sensibly be configured not to reveal whether a user exists or not.
func CanSecstore(network string, addr string, user string) error {
	conn, err := Dial(network, addr)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	_, err = fmt.Fprintf(conn, "%s\nC=%s\nm=0\n", Version(), user)
	if err != nil {
		return fmt.Errorf("error writing version/alg: %w", err)
	}
	// a little strange, but the convention is a !message reply that readstr converts to an error
	s, err := readString(conn)
	if err == nil {
		return fmt.Errorf("unexpected reply from secstore: %q", s)
	}
	if err.Error() != "account exists" {
		return fmt.Errorf("error from secstore: %w", err)
	}
	return nil
}

// SendPin sends the remote the PIN it has demanded as an extra check.
func SendPin(conn net.Conn, pin string) error {
	err := writeString(conn, "STA"+pin)
	if err != nil {
		return fmt.Errorf("error writing pin: %w", err)
	}
	s, err := readString(conn)
	if err != nil {
		return fmt.Errorf("error reading pin reply: %w", err)
	}
	if s != "OK" {
		return fmt.Errorf("remote rejected pin: %s", s)
	}
	return nil
}

// Bye writes a closing message to attempt a graceful close, and closes the connection.
// Errors are ignored as by now uninteresting. Note that if calling Bye causes Close to be called twice,
// the effect is "undefined" by interface Closer, an annoying property.
func Bye(conn net.Conn) {
	if conn == nil {
		return
	}
	writeString(conn, "BYE")
	conn.Close()
}
