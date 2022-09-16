// Package secstore interacts with a Plan 9 secstore service:
// authenticating a user, listing, fetching, storing and removing encrypted files.
package secstore

import (
	"errors"
	"fmt"
	"net"

	"github.com/forsyth/auth/internal/pak"
	"github.com/forsyth/auth/internal/sio"
	"github.com/forsyth/auth/internal/ssl"
)

const MaxFileSize = 128 * 1024 // arbitrary default, same as Plan 9
const MaxMsg = ssl.MaxMsg
const Port = "5356"

var (
	ErrNoAuth = errors.New("connection not suitable for authentication")
)

// connState is the connection state
type connState int

const (
	connected connState = iota // connected, with SSL pushed
	broken                     // failed authentication
	ready                      // successfully authenticated, ready for use
	closed                     // closed (to prevent two calls to network Close)
)

// Secstore provides a set of operations on a remote secstore.
type Secstore struct {
	conn    *ssl.Conn
	Peer    string    // name asserted by other side
	NeedPIN bool      // must obtain and send 2FA
	state   connState // avoid calling conn.Close twice
}

// Version returns the secstore version and algorithm, to be sent to the peer.
func Version() string {
	return fmt.Sprintf("%s\tPAK\n", pak.VERSION)
}

// Privacy enables whatever memory privacy mode the OS provides.
func Privacy() {
	// don't know yet
}

// Dial connects to the secstore at the given network address,
// pushes an SSL instance (initially in clear), and returns the resulting connection,
// which must be authenticated before use (see the Auth method).
func Dial(network, addr string) (*Secstore, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return &Secstore{conn: ssl.Client(conn), Peer: "", NeedPIN: false, state: connected}, nil
}

// Auth authenticates the Secstore connection for the given user and password hash,
// engages line encryption using the negotiated session key,
// setting the peer name and an optional demand for further
// authentication (Secstore.NeedPIN), which if true requires
// the SendPIN method to be invoked to provide the PIN.
// The connection can then be used for secstore commands, typically via Files, GetFile, PutFIle etc.
// Connect also returns the remote server's name for itself, as exchanged using the
// key-exchange protocol, typically just "secstore".
// If the Secstore.NeedPIN is true, the caller must get the extra authentication value
// and provide it using SendPIN.
func (sec *Secstore) Auth(user string, pwhash []byte) error {
	if sec.state != connected {
		return ErrNoAuth
	}
	sec.state = broken
	pk, err := pak.Client(sec.conn, Version(), user, pwhash)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	sec.Peer = pk.Peer
	keys := EncryptionKeys(pk.Session, 0)
	err = sec.conn.StartCipher(keys[0], keys[1])
	if err != nil {
		return fmt.Errorf("pushing SSL: %w", err)
	}
	s, err := sio.ReadString(sec.conn)
	if err != nil {
		return fmt.Errorf("connection read error: %w", err)
	}
	if s == "STA" {
		sec.state = ready
		sec.NeedPIN = true
		return nil
	}
	if s != "OK" {
		return fmt.Errorf("unexpected response: %q", s)
	}
	sec.state = ready
	return nil
}

// CanSecstore checks whether secstore exists at the remote, and has a given user.
// The remote might sensibly be configured not to reveal whether a user exists or not.
func CanSecstore(network string, addr string, user string) error {
	sec, err := Dial(network, addr)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	_, err = fmt.Fprintf(sec.conn, "%s\nC=%s\nm=0\n", Version(), user)
	if err != nil {
		return fmt.Errorf("error writing version/alg: %w", err)
	}
	// a little strange, but the convention is a !message reply that readstr converts to an error
	s, err := sio.ReadString(sec.conn)
	if err == nil {
		return fmt.Errorf("unexpected reply from secstore: %q", s)
	}
	if err.Error() != "account exists" {
		return fmt.Errorf("error from secstore: %w", err)
	}
	return nil
}

// SendPIN sends the remote the PIN it has demanded as an extra check.
func (sec *Secstore) SendPIN(pin string) error {
	err := sio.WriteString(sec.conn, "STA"+pin)
	if err != nil {
		return fmt.Errorf("error writing pin: %w", err)
	}
	s, err := sio.ReadString(sec.conn)
	if err != nil {
		return fmt.Errorf("error reading pin reply: %w", err)
	}
	if s != "OK" {
		return fmt.Errorf("remote rejected pin: %s", s)
	}
	return nil
}

// Close writes a closing message to attempt a graceful close, and closes the underlying connection.
// Errors are ignored as by now uninteresting. Close ensures the underlying connection is not
// closed twice, since that's "undefined" by interface Closer (an annoying property).
func (sec *Secstore) Close() {
	if sec.state == closed {
		return
	}
	sio.WriteString(sec.conn, "BYE")
	sec.conn.Close()
	sec.state = closed
}
