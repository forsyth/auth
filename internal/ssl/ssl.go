package ssl

import (
	"crypto/rc4"
	"crypto/sha1"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// delimited, authenticated, encrypted connection

// MaxMsg limits the record size. Larger messages are truncated.
const MaxMsg = 4096

// Conn represents one of these SSL connections.
type Conn struct {
	fd	net.Conn	// underlying network connection
	in, out	connState
	buf	[MaxMsg]byte	// hold encrypted output block
}

// connState represents the state of one direction.
type connState struct {
	lk	sync.Mutex
	secret	[sha1.Size]byte
	seqno	uint32
	rc4	*rc4.Cipher	// non-nil if in encrypted mode
}

// Cklient returns an SSL connection that applies SSL to the transport fd.
func Client(fd net.Conn) *Conn {
	// initially it's not encrypted
	return &Conn {
		fd: fd,
	}
}

// StartCipher engages digesting and encryption on the link, using 128-bit keys.
func (ssl *Conn) StartCipher(inkey, outkey []byte) error {
	if len(inkey) < 16 || len(outkey) < 16 {
		return errors.New("key too short")
	}
	c1, err := rc4.NewCipher(inkey[0: 16])
	if err != nil {
		return err
	}
	c2, err := rc4.NewCipher(outkey[0:16])
	if err != nil {
		return err
	}
	ssl.in.lk.Lock()
	copy(ssl.in.secret[:], inkey)
	ssl.in.rc4 = c1
	ssl.in.lk.Unlock()
	ssl.out.lk.Lock()
	copy(ssl.out.secret[:], outkey)
	ssl.out.rc4 = c2
	ssl.out.lk.Unlock()
	return nil
}

func hash(secret []byte, data []byte, seqno uint32, d []byte) {
	sha := sha1.New()
	var seq [4]byte
	seq[0] = byte(seqno >> 24)
	seq[1] = byte(seqno >> 16)
	seq[2] = byte(seqno >> 8)
	seq[3] = byte(seqno)
	sha.Write(secret)
	sha.Write(data)
	sha.Write(seq[:])
	copy(d, sha.Sum(nil))
	//fmt.Printf("hash: %d secret %#v data %#v digest %#v\n", seqno, secret, data, d)
}

func verify(secret []byte, data []byte, seqno uint32, d []byte) bool {
	var digest [sha1.Size]byte
	hash(secret, data, seqno, digest[:])
	return subtle.ConstantTimeCompare(digest[:], d) != 0
}

// Read reads data from the connection, following the net.Conn.Read conventions.
func (ssl *Conn) Read(buf []byte) (int, error) {
	ssl.in.lk.Lock()
	defer ssl.in.lk.Unlock()
	var count [2]byte
	nr, err := io.ReadFull(ssl.fd, count[:])
	if err != nil {
		return 0, fmt.Errorf("received short count %d: %w", nr, err)
	}
	if (count[0] & 0x80) == 0 {
		return 0, errors.New("received invalid count")
	}
	n := int(count[0] & 0x7F) << 8 | int(count[1])	// SSL-style count, no pad
	if ssl.in.rc4 != nil {
		var digest [sha1.Size]byte
		n -= len(digest)
		if n <= 0 {
			return 0, errors.New("received short length")
		}
		nr, err := io.ReadFull(ssl.fd, digest[:])
		if err != nil {
			return 0, fmt.Errorf("missing digest: got %d: %w", nr, err)
		}
		nr, err = io.ReadFull(ssl.fd, buf[0:n])
		if err != nil {
			return 0, fmt.Errorf("missing data: got %d: %w", nr, err)
		}
		ssl.in.rc4.XORKeyStream(digest[:], digest[:])
		ssl.in.rc4.XORKeyStream(buf[0:n], buf[0:n])
		if !verify(ssl.in.secret[:], buf[0:n], ssl.in.seqno, digest[:]) {
			return 0, errors.New("read integrity check failed")
		}
	} else {
		if n <= 0 || n > len(buf) {
			return 0, fmt.Errorf("read implausible record length: %d", count)
		}
		nr, err := io.ReadFull(ssl.fd, buf[0: n])
		if err != nil {
			return 0, fmt.Errorf("read expected %d bytes, got %d: %w", count, nr, err)
		}
	}
	ssl.in.seqno++
	return n, nil
}

// Write writes data to the connection, following the net.Conn.Write conventions.
func (ssl *Conn) Write(buf []byte) (int, error) {
	ssl.out.lk.Lock()
	defer ssl.out.lk.Unlock()
	var count [2]byte
	var digest [sha1.Size]byte
	n := len(buf)
	if n == 0 || n > MaxMsg {
		return 0, fmt.Errorf("invalid write size: %d", n)
	}
	if ssl.out.rc4 != nil {
		n += sha1.Size
	}
	count[0] = byte(0x80 | (n>>8))
	count[1] = byte(n)
	nw, err := ssl.fd.Write(count[:])
	if err != nil {
		return 0, fmt.Errorf("error writing count: %w", err)
	}
	if nw !=2 {
		return 0, errors.New("short write of count")
	}
	if ssl.out.rc4 != nil {
		enc := ssl.buf[0: len(buf)]
		hash(ssl.out.secret[:], buf, ssl.out.seqno, digest[:])
		ssl.out.rc4.XORKeyStream(digest[:], digest[:])
		ssl.out.rc4.XORKeyStream(enc, buf)
		_, err = ssl.fd.Write(digest[:])
		if err != nil {
			return 0, fmt.Errorf("error writing digest: %w", err)
		}
		_, err = ssl.fd.Write(enc)
		if err != nil {
			return 0, fmt.Errorf("error writing encrypted record: %w", err)
		}
	} else {
		nw, err = ssl.fd.Write(buf)
		if err != nil {
			return nw, fmt.Errorf("error writing message: %d written: %w", nw, err)
		}
	}
	ssl.out.seqno++
	return len(buf), nil
}

// Close closes the connection.
func (ssl *Conn) Close() error {
	return ssl.fd.Close()
}

// The remaining functions implement the rest of the net.Conn interface.

// LocalAddr returns the local network address, if known.
func (ssl *Conn) LocalAddr() net.Addr {
	return ssl.fd.LocalAddr()
}

// RemoteAddr returns the remote network address, if known.
func (ssl *Conn) RemoteAddr() net.Addr {
	return ssl.fd.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
func (ssl *Conn) SetDeadline(t time.Time) error {
	return ssl.fd.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (ssl *Conn) SetReadDeadline(t time.Time) error {
	return ssl.fd.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (ssl *Conn) SetWriteDeadline(t time.Time) error {
	return ssl.fd.SetWriteDeadline(t)
}
