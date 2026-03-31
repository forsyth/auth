// Package authsrv implements declarations and primitive elements for Plan 9's
// original authentication system, similar to those defined by
// Plan 9's /sys/include/auth.h, /sys/include/authsrv.h and implemented by /sys/src/libauthsrv.
// They allow communication with a Plan 9 authentication server, using protocols
// described in authsrv(6). Specifically, it provides encoding of messages carrying a ticket request, ticket,
// authenticator or password change request.
// Like Plan 9's original implementation, it uses DES-based keys and encryption,
// which is obviously now outdated.
// The newer scheme provided by 9front remains to be implemented.
package authsrv

// this is a near transliteration of Plan 9 source /sys/src/libauthsrv, subject to the MIT licence

import (
	"crypto/des"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
)

const (
	ANAMELEN  = 28 // maximum size of name in previous proto
	AERRLEN   = 64 // maximum size of errstr in previous proto
	DOMLEN    = 48 // length of an authentication domain name
	DESKEYLEN = 7  // length of a des Key for encrypt/decrypt
	CHALLEN   = 8  // length of a plan9 sk1 challenge
	NETCHLEN  = 16 // max network challenge length (used in AS protocol)
	SECRETLEN = 32 // max length of a Secret
)

// encryption numberings (anti-replay)
const (
	AuthTreq   = 1  // ticket request
	AuthChal   = 2  // challenge box request
	AuthPass   = 3  // change password
	AuthOK     = 4  // fixed length reply follows
	AuthErr    = 5  // error follows
	AuthMod    = 6  // modify user
	AuthApop   = 7  // apop authentication for pop3
	AuthOKvar  = 9  // variable length reply follows
	AuthChap   = 10 // chap authentication for ppp
	AuthMSchap = 11 // MS chap authentication for ppp
	AuthCram   = 12 // CRAM verification for IMAP (RFC2195 & rfc2104)
	AuthHttp   = 13 // http domain login
	AuthVNC    = 14 // VNC server login (deprecated)

	AuthTs = 64 // ticket encrypted with server's Key
	AuthTc = 65 // ticket encrypted with client's Key
	AuthAs = 66 // server generated authenticator
	AuthAc = 67 // client generated authenticator
	AuthTp = 68 // ticket encrypted with client's Key for password change
	AuthHr = 69 // http reply
)

type TicketReq struct {
	RType   byte
	AuthID  string // [ANAMELEN]	server's encryption ID
	AuthDom string // [DOMLEN]	server's authentication domain
	Chal    []byte // [CHALLEN]	challenge from server
	HostID  string // [ANAMELEN]		host's encryption ID
	UID     string // [ANAMELEN]	UID of requesting user on host
}

const TICKREQLEN = 3*ANAMELEN + CHALLEN + DOMLEN + 1

type Ticket struct {
	Num      byte   // replay protection
	Chal     []byte // [CHALLEN] server challenge
	ClientID string // [ANAMELEN]	UID on client
	ServerID string // [ANAMELEN]	UID on server
	Key      []byte // [DESKEYLEN]	nonce DES Key
}

const TICKETLEN = CHALLEN + 2*ANAMELEN + DESKEYLEN + 1

type Authenticator struct {
	Num  byte   // replay protection
	Chal []byte // [CHALLEN] server challenge
	ID   uint32 // authenticator ID , ++'d with each auth
}

const AUTHENTLEN = CHALLEN + 4 + 1

type PasswordReq struct {
	Num          byte
	Old          []byte // [ANAMELEN]
	New          []byte // [ANAMELEN]
	ChangeSecret byte
	Secret       []byte // [SECRETLEN] new secret
}

const PASSREQLEN = 2*ANAMELEN + 1 + 1 + SECRETLEN

func put4(a []byte, v uint32) {
	binary.LittleEndian.PutUint32(a, v)
}

func get4(a []byte) uint32 {
	return binary.LittleEndian.Uint32(a[0:])
}

func puts(a []byte, s string, n int) {
	b := []byte(s)
	l := len(b)
	if l >= n {
		b = b[0: n]
		l = n - 1
	}
	copy(a, b)
	for ; l < n; l++ {
		a[l] = 0
	}
}

func gets(a []byte, n int) string {
	for i := range n {
		if a[i] == 0 {
			return string(a[0:i])
		}
	}
	return string(a[0:n])
}

func geta(a []byte, n int) []byte {
	b := make([]byte, n)
	copy(b, a[0:n])
	return b
}

func puta(a []byte, src []byte, n int) {
	if len(src) > n {
		panic("value too long for fixed field")
	}
	copy(a, src)
}

// Pack returns the wire form of an authenticator.
// The optional key is used to encrypt the result first.
func (f *Authenticator) Pack(key []byte) []byte {
	p := make([]byte, AUTHENTLEN)
	p[0] = f.Num
	puta(p[1:], f.Chal, CHALLEN)
	put4(p[1+CHALLEN:], f.ID)
	if key != nil {
		encrypt(key, p, len(p))
	}
	return p
}

// UnpackAuthenticator returns an authenticator given a wire form.
// The optional key is used to decrypt the data first.
func UnpackAuthenticator(a []byte, key []byte) (*Authenticator, int, error) {
	if len(a) < AUTHENTLEN {
		return nil, 0, io.ErrShortBuffer
	}
	if key != nil {
		decrypt(key, a, AUTHENTLEN)
	}
	f := new(Authenticator)
	f.Num = a[0]
	f.Chal = geta(a[1:], CHALLEN)
	f.ID = get4(a[1+CHALLEN:])
	return f, AUTHENTLEN, nil
}

// Pack returns the wire form of a password request.
// The optional key is used to encrypt the result first.
func (f *PasswordReq) Pack(key []byte) []byte {
	a := make([]byte, PASSREQLEN)
	a[0] = f.Num
	puta(a[1:], f.Old, ANAMELEN)
	puta(a[1+ANAMELEN:], f.New, ANAMELEN)
	a[1+2*ANAMELEN] = f.ChangeSecret
	puta(a[1+2*ANAMELEN+1:], f.Secret, SECRETLEN)
	if key != nil {
		encrypt(key, a, len(a))
	}
	return a
}

// UnpackPasswordReq returns a password change request given the wire form.
// The optional key is used to decrypt the data first.
func UnpackPasswordReq(a []byte, key []byte) (*PasswordReq, int, error) {
	if len(a) < PASSREQLEN {
		return nil, 0, io.ErrShortBuffer
	}
	if key != nil {
		decrypt(key, a, PASSREQLEN)
	}
	f := new(PasswordReq)
	f.Num = a[0]
	f.Old = geta(a[1:], ANAMELEN)
	f.Old[ANAMELEN-1] = 0
	f.New = geta(a[1+ANAMELEN:], ANAMELEN)
	f.New[ANAMELEN-1] = 0
	f.ChangeSecret = a[1+2*ANAMELEN]
	f.Secret = geta(a[1+2*ANAMELEN+1:], SECRETLEN)
	f.Secret[SECRETLEN-1] = 0
	return f, PASSREQLEN, nil
}

// Pack returns the wire form of a ticket.
// The optional key is used to encrypt the result first.
func (f *Ticket) Pack(key []byte) []byte {
	a := make([]byte, TICKETLEN)
	a[0] = f.Num
	puta(a[1:], f.Chal, CHALLEN)
	puts(a[1+CHALLEN:], f.ClientID, ANAMELEN)
	puts(a[1+CHALLEN+ANAMELEN:], f.ServerID, ANAMELEN)
	puta(a[1+CHALLEN+2*ANAMELEN:], f.Key, DESKEYLEN)
	if key != nil {
		encrypt(key, a, len(a))
	}
	return a
}

// UnpackTicket returns a ticket given its wire form.
// The optional key is used to decrypt the wire form first.
func UnpackTicket(a []byte, key []byte) (*Ticket, int, error) {
	if len(a) < TICKETLEN {
		return nil, 0, io.ErrShortBuffer
	}
	if key != nil {
		decrypt(key, a, TICKETLEN)
	}
	f := new(Ticket)
	f.Num = a[0]
	f.Chal = geta(a[1:], CHALLEN)
	f.ClientID = gets(a[1+CHALLEN:], ANAMELEN)
	f.ServerID = gets(a[1+CHALLEN+ANAMELEN:], ANAMELEN)
	f.Key = geta(a[1+CHALLEN+2*ANAMELEN:], DESKEYLEN)
	return f, TICKETLEN, nil
}

// Pack returns the wire form of a ticket request.
func (f *TicketReq) Pack() []byte {
	a := make([]byte, TICKREQLEN)
	a[0] = f.RType
	puts(a[1:], f.AuthID, ANAMELEN)
	puts(a[1+ANAMELEN:], f.AuthDom, DOMLEN)
	puta(a[1+ANAMELEN+DOMLEN:], f.Chal, CHALLEN)
	puts(a[1+ANAMELEN+DOMLEN+CHALLEN:], f.HostID, ANAMELEN)
	puts(a[1+ANAMELEN+DOMLEN+CHALLEN+ANAMELEN:], f.UID, ANAMELEN)
	return a
}

// UnpackTicketReq returns a ticket request given its wire form.
func UnpackTicketReq(a []byte) (*TicketReq, int, error) {
	if len(a) < TICKREQLEN {
		return nil, 0, io.ErrShortBuffer
	}
	f := new(TicketReq)
	f.RType = a[0]
	f.AuthID = gets(a[1:], ANAMELEN)
	f.AuthDom = gets(a[1+ANAMELEN:], DOMLEN)
	f.Chal = geta(a[1+ANAMELEN+DOMLEN:], CHALLEN)
	f.HostID = gets(a[1+ANAMELEN+DOMLEN+CHALLEN:], ANAMELEN)
	f.UID = gets(a[1+ANAMELEN+DOMLEN+CHALLEN+ANAMELEN:], ANAMELEN)
	return f, TICKREQLEN, nil
}

// Netcrypt returns the required response for a given challenge and key
// for a software version of the Old SecureNet netkey device.
func Netcrypt(key []byte, Chal string) string {
	buf := make([]byte, 8)
	a := []byte(Chal)
	if len(a) > 7 {
		a = a[0:7]
	}
	copy(buf, a)
	encrypt(key, buf, len(buf))
	return fmt.Sprintf("%02x%02x%02x%02x", buf[0], buf[1], buf[2], buf[3])
}

// PassToKey calculates the Plan 9 DES key from a given password.
func PassToKey(p string) []byte {
	a := []byte(p)
	n := len(a)
	if n >= ANAMELEN {
		n = ANAMELEN - 1
	}
	buf := make([]byte, ANAMELEN)
	for i := range 8 {
		buf[i] = ' '
	}
	copy(buf, a[0:n])
	buf[n] = 0
	key := make([]byte, DESKEYLEN)
	for t := 0; ; {
		for i := range DESKEYLEN {
			key[i] = byte((int(buf[t+i]) >> i) + (int(buf[t+i+1]) << (8 - (i + 1))))
		}
		if n <= 8 {
			return key
		}
		n -= 8
		t += 8
		if n < 8 {
			t -= 8 - n
			n = 8
		}
		encrypt(key, buf[t:], 8)
	}
}

var parity []byte = []byte{
	0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e,
	0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f,
	0x20, 0x23, 0x25, 0x26, 0x29, 0x2a, 0x2c, 0x2f,
	0x31, 0x32, 0x34, 0x37, 0x38, 0x3b, 0x3d, 0x3e,
	0x40, 0x43, 0x45, 0x46, 0x49, 0x4a, 0x4c, 0x4f,
	0x51, 0x52, 0x54, 0x57, 0x58, 0x5b, 0x5d, 0x5e,
	0x61, 0x62, 0x64, 0x67, 0x68, 0x6b, 0x6d, 0x6e,
	0x70, 0x73, 0x75, 0x76, 0x79, 0x7a, 0x7c, 0x7f,
	0x80, 0x83, 0x85, 0x86, 0x89, 0x8a, 0x8c, 0x8f,
	0x91, 0x92, 0x94, 0x97, 0x98, 0x9b, 0x9d, 0x9e,
	0xa1, 0xa2, 0xa4, 0xa7, 0xa8, 0xab, 0xad, 0xae,
	0xb0, 0xb3, 0xb5, 0xb6, 0xb9, 0xba, 0xbc, 0xbf,
	0xc1, 0xc2, 0xc4, 0xc7, 0xc8, 0xcb, 0xcd, 0xce,
	0xd0, 0xd3, 0xd5, 0xd6, 0xd9, 0xda, 0xdc, 0xdf,
	0xe0, 0xe3, 0xe5, 0xe6, 0xe9, 0xea, 0xec, 0xef,
	0xf1, 0xf2, 0xf4, 0xf7, 0xf8, 0xfb, 0xfd, 0xfe,
}

func des56to64(k56 []byte) []byte {
	k64 := make([]byte, 8)
	hi := (int(k56[0]) << 24) | (int(k56[1]) << 16) | (int(k56[2]) << 8) | int(k56[3])
	lo := (int(k56[4]) << 24) | (int(k56[5]) << 16) | (int(k56[6]) << 8)

	k64[0] = parity[(hi>>25)&0x7f]
	k64[1] = parity[(hi>>18)&0x7f]
	k64[2] = parity[(hi>>11)&0x7f]
	k64[3] = parity[(hi>>4)&0x7f]
	k64[4] = parity[((hi<<3)|int((int64(lo)&0xFFFFFFFF)>>29))&0x7f] // watch the sign extension
	k64[5] = parity[(lo>>22)&0x7f]
	k64[6] = parity[(lo>>15)&0x7f]
	k64[7] = parity[(lo>>8)&0x7f]
	return k64
}

var (
	ErrSmallBlock = errors.New("data less than block length")
)

// encrypt encrypts n bytes of data in place with the given key,
// using Plan 9's algorithm.
func encrypt(key []byte, data []byte, n int) error {
	if n < 8 {
		return ErrSmallBlock
	}
	ds, err := des.NewCipher(des56to64(key))
	if err != nil {
		return err
	}
	n--
	r := n % 7
	n /= 7
	j := 0
	for _ = range n {
		ds.Encrypt(data[j:], data[j:])
		j += 7
	}
	if r != 0 {
		o := j - 7 + r
		ds.Encrypt(data[o:], data[o:])
	}
	return nil
}

// decrypt decrypts n bytes of data in place with the given key.
// using Plan 9's algorithm.
func decrypt(key []byte, data []byte, n int) error {
	if n < 8 {
		return ErrSmallBlock
	}
	ds, err := des.NewCipher(des56to64(key))
	if err != nil {
		return err
	}
	n--
	r := n % 7
	n /= 7
	j := n * 7
	if r != 0 {
		o := j - 7 + r
		ds.Decrypt(data[o:], data[o:])
	}
	for _ = range n {
		j -= 7
		ds.Decrypt(data[j:], data[j:])
	}
	return nil
}

// readn returns a buffer with exactly nb bytes, or returns an error.
func readn(fd io.Reader, nb int) ([]byte, error) {
	buf := make([]byte, nb)
	nr, err := io.ReadAtLeast(fd, buf, nb)
	if err != nil {
		return nil, err
	}
	if nr != nb {
		return nil, io.ErrUnexpectedEOF
	}
	return buf, nil
}

// exchange messages with auth server

const (
	pbmsg = "AS protocol botch"
)

// ASGetTicket gets a ticket from the authentication server on fd, returning
// the ticket, and a packed ticket encrypted by the server's key.
// The error could be more precise but these functions have only ephemeral interest.
func ASGetTicket(fd io.ReadWriter, tr *TicketReq, key []byte) (*Ticket, []byte, error) {
	a := tr.Pack()
	_, err := fd.Write(a)
	if err != nil {
		return nil, nil, fmt.Errorf("AS protocol botch: %w", err)
	}
	a, err = asReadResponse(fd, 2*TICKETLEN)
	if err != nil {
		return nil, nil, err
	}
	t, _, err := UnpackTicket(a, key)
	if err != nil {
		return nil, nil, fmt.Errorf("AS protocol botch: %w", err)
	}
	return t, a[TICKETLEN:], nil // can't unpack both since the second uses server key
}

func asReadResponse(fd io.Reader, n int) ([]byte, error) {
	b, err := readn(fd, 1)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pbmsg, err)
	}

	var buf []byte
	switch b[0] {
	case AuthOK:
		buf, err = readn(fd, n)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pbmsg, err)
		}

	case AuthOKvar:
		b, err = readn(fd, 5)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pbmsg, err)
		}
		s := string(b)
		n, err := strconv.ParseInt(s, 10, 32)
		if err != nil || n <= 0 || n > 4096 {
			return nil, fmt.Errorf("%s: invalid message length: %q", pbmsg, s)
		}
		buf, err = readn(fd, int(n))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pbmsg, err)
		}

	case AuthErr:
		b, err = readn(fd, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pbmsg, err)
		}
		i := 0
		for ; i < len(b) && b[i] != 0; i++ {
			// skip
		}
		return nil, fmt.Errorf("remote %s", string(b[0:i]))

	default:
		return nil, fmt.Errorf("%s resp %d", pbmsg, b[0])
	}
	return buf, nil
}
