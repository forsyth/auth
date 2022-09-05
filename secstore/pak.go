package secstore

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"
)

// note: this implementation uses many of the original names,
// to keep it aligned with the Plan 9/Plan 9 port/Inferno implementations,
//  but that leads to using hexX for an ascii version of X,
// which is actually base64, not hex.

// PAK holds a negotiated session key and the name presented by the other party after negotiation.
type PAK struct {
	Peer    string // what the other client/server calls itself
	Session []byte // negotiated session key
}

// PW is used only on the server, to represent a user and their key, during and after negotiation.
type PW struct {
	Key any      // a value provided by the user manager identifying a user
	Hi  *big.Int // H(passphrase)^-1 mod p	// a transformation of the user's (hashed) secret
}

// UserManager manages a set of users.
type UserManager interface {

	// Look returns a PW value representing a given user, or an error if the user doesn't exist (or has expired).
	Look(name string) (*PW, error)
}

// pakParams holds the fixed parameter values for the PAK protocol.
type pakParams struct {
	q *big.Int
	p *big.Int
	r *big.Int
	g *big.Int
}

// from seed EB7B6E35F7CD37B511D96C67D6688CC4DD440E1E

var pak = &pakParams{
	q: mustHexToBig("E0F0EF284E10796C5A2A511E94748BA03C795C13"),
	p: mustHexToBig("C41CFBE4D4846F67A3DF7DE9921A49D3B42DC33728427AB159CEC8CBB" +
		"DB12B5F0C244F1A734AEB9840804EA3C25036AD1B61AFF3ABBC247CD4B384224567A86" +
		"3A6F020E7EE9795554BCD08ABAD7321AF27E1E92E3DB1C6E7E94FAAE590AE9C48F96D9" +
		"3D178E809401ABE8A534A1EC44359733475A36A70C7B425125062B1142D"),
	r: mustHexToBig("DF310F4E54A5FEC5D86D3E14863921E834113E060F90052AD332B3241" +
		"CEF2497EFA0303D6344F7C819691A0F9C4A773815AF8EAECFB7EC1D98F039F17A32A7E" +
		"887D97251A927D093F44A55577F4D70444AEBD06B9B45695EC23962B175F266895C67D" +
		"21C4656848614D888A4"),
	g: mustHexToBig("2F1C308DC46B9A44B52DF7DACCE1208CCEF72F69C743ADD4D23271734" +
		"44ED6E65E074694246E07F9FD4AE26E0FDDD9F54F813C40CB9BCD4338EA6F242AB94CD" +
		"410E676C290368A16B1A3594877437E516C53A6EEE5493A038A017E955E218E7819734" +
		"E3E2A6E0BAE08B14258F8C03CC1B30E0DDADFCF7CEDF0727684D3D255F1"),
}

func mustHexToBig(s string) *big.Int {
	i := new(big.Int)
	_, ok := i.SetString(s, 16)
	if !ok {
		panic("bad initial hex value")
	}
	return i
}

// H = (sha(ver,C,sha(passphrase)))^r mod p,
// a hash function expensive to attack by brute force.
const Reps = 7

func longhash(ver string, C string, passwd []byte) *big.Int {
	aver := []byte(ver)
	aC := []byte(C)
	Cp := make([]byte, len(aver)+len(aC)+len(passwd))
	copy(Cp, aver)
	copy(Cp[len(aver):], aC)
	copy(Cp[len(aver)+len(aC):], passwd)
	buf := []byte{}
	for i := 0; i < Reps; i++ {
		key := []byte{byte('A' + i)}
		buf = append(buf, hmac_sha1(Cp, key)...)
	}
	erasekey(Cp)
	b := new(big.Int).SetBytes(buf)
	h := new(big.Int)
	h.Mod(b, pak.p)
	h.Exp(h, pak.r, pak.p)
	return h
}

func shaz(s string, state hash.Hash) {
	a := []byte(s)
	_, err := state.Write(a)
	if err != nil {
		panic(err)
	}
	erasekey(a)
}

func bigrand() (*big.Int, error) {
	var rbytes [240 / 8]byte
	n, err := rand.Reader.Read(rbytes[:])
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(rbytes[:n]), nil
}

// Hi = H^-1 mod p
func PAKHi(C string, pass []byte) (string, *big.Int, *big.Int) {
	H := longhash(VERSION, C, pass)
	Hi := new(big.Int)
	Hi = Hi.ModInverse(H, pak.p)
	return enc64(Hi.Bytes()), H, Hi
}

// another, faster, hash function for each party to
// confirm that the other has the right secrets.

func shorthash(mess string, C string, S string, m string, mu string, sigma string, Hi string) []byte {
	state := sha1.New()
	for i := 0; i < 2; i++ {
		shaz(mess, state)
		shaz(C, state)
		shaz(S, state)
		shaz(m, state)
		shaz(mu, state)
		shaz(sigma, state)
		shaz(Hi, state)
	}
	return state.Sum(nil)
}

// Client establishes a secure client-side connection on conn using the PAK Encrypted Key Exchange protocol,
// where C is the client's name and pass is the user's passphrase. Client returns a value containing
// the name of the peer (server) and a session secret to apply to the connection.
func Client(conn io.ReadWriter, version string, C string, pass []byte) (*PAK, error) {
	hexHi, H, _ := PAKHi(C, pass)

	// random 1<=x<=q-1; send C, m=g**x H
	x, err := bigrand()
	if err != nil {
		return nil, err
	}
	x.Mod(x, pak.q)
	if x.Cmp(big.NewInt(0)) == 0 {
		x = big.NewInt(1)
	}
	m := new(big.Int).Set(pak.g)
	m.Exp(m, x, pak.p)
	m.Mul(m, H)
	m.Mod(m, pak.p)
	hexm := enc64(m.Bytes())

	_, err = fmt.Fprintf(conn, "%sC=%s\nm=%s\n", version, C, hexm)
	if err != nil {
		return nil, err
	}

	// recv g**y, S, check hash1(g**xy)
	s, err := readString(conn)
	if err != nil {
		err = writeError(conn, "couldn't read g**y: "+err.Error())
		return nil, err
	}
	// should be: "mu=%s\nk=%s\nS=%s\n"
	flds := strings.Split(s, "\n")
	if len(flds) != 4 {
		err = writeError(conn, "verifier syntax error")
		return nil, err
	}
	hexmu := ex("mu=", flds[0])
	ks := ex("k=", flds[1])
	S := ex("S=", flds[2])
	if hexmu == "" || ks == "" || S == "" {
		err = writeError(conn, "verifier syntax error")
		return nil, err
	}
	mu, err := dec64(hexmu)
	if err != nil {
		return nil, err
	}
	sigma := new(big.Int).Exp(mu, x, pak.p)
	hexsigma := enc64(sigma.Bytes())
	digest := shorthash("server", C, S, hexm, hexmu, hexsigma, hexHi)
	kc := enc64(digest)
	if ks != kc {
		err = writeError(conn, "verifier didn't match")
		return nil, err
	}

	// send hash2(g**xy)
	digest = shorthash("client", C, S, hexm, hexmu, hexsigma, hexHi)
	kc = enc64(digest)
	_, err = fmt.Fprintf(conn, "k'=%s\n", kc)
	if err != nil {
		return nil, err
	}

	// set session key
	digest = shorthash("session", C, S, hexm, hexmu, hexsigma, hexHi)

	return &PAK{Peer: S, Session: digest}, nil
}

// Server establishes a secure server-side connection on conn using the PAK protocol,
// where S is the server's name and the user manager users can
// return the PAK-related key values for a given user (or an error if no such user).
// Server returns a value containing the name of the client and a session secret
// to apply to the connection, the PW value provided by the user manager, or
// an error. If the PW value is not nil and there's an error, a user manager can count
// it as a failure to authenticate.
func Server(conn io.ReadWriter, version string, S string, users UserManager) (*PAK, *PW, error) {
	var err error

	mess, err := readString(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading first mesg: %w", err)
	}

	// prefix has application version and algorithm
	if !strings.HasPrefix(mess, version) {
		err = writeError(conn, "protocol should start with ver alg")
		return nil, nil, err
	}
	mess = mess[len(version):]

	// parse rest of first message into C, m
	flds := strings.Split(mess, "\n")
	if len(flds) != 3 {
		err = writeError(conn, "PAK version syntax (fields)")
		return nil, nil, err
	}
	C := ex("C=", flds[0])
	hexm := ex("m=", flds[1])
	if C == "" || hexm == "" {
		err = writeError(conn, "PAK version syntax, C=, m=")
		return nil, nil, err
	}
	m, err := dec64(hexm)
	if err != nil {
		err = writeError(conn, "PAK version syntax, m format")
		return nil, nil, err
	}
	m.Mod(m, pak.p)

	// lookup client user
	pw, err := users.Look(C)
	if err != nil {
		err = writeError(conn, err.Error())
		return nil, pw, err
	}
	if m.Cmp(big.NewInt(0)) == 0 {
		// this can be disabled in original secstore by making special FICTITIOUS account that is used by default
		err = writeError(conn, "account exists")
		return nil, nil, err
	}
	hexHi := enc64(pw.Hi.Bytes())

	// random y, mu=g**y, sigma=g**xy
	y, err := bigrand()
	if err != nil {
		err = writeError(conn, "failed to generate random: "+err.Error())
		return nil, nil, err
	}
	y.Mod(y, pak.q)
	if y.Cmp(big.NewInt(0)) == 0 {
		y = big.NewInt(1)
	}
	mu := new(big.Int).Set(pak.g)
	mu.Exp(mu, y, pak.p)
	m.Mul(m, pw.Hi)
	m.Mod(m, pak.p)
	sigma := new(big.Int).Exp(m, y, pak.p)

	// send g**y, hash1(g**xy)
	hexmu := enc64(mu.Bytes())
	hexsigma := enc64(sigma.Bytes())
	digest := shorthash("server", C, S, hexm, hexmu, hexsigma, hexHi)
	ks := enc64(digest)
	_, err = fmt.Fprintf(conn, "mu=%s\nk=%s\nS=%s\n", hexmu, ks, S)
	if err != nil {
		return nil, nil, fmt.Errorf("connection write error: %w", err)
	}

	// recv hash2(g**xy)
	mess, err = readString(conn)
	if err != nil {
		err = writeError(conn, "couldn't read verifier: "+err.Error())
		return nil, nil, err
	}
	kc := ex("k'=", strings.TrimRight(mess, "\n"))
	if kc == "" {
		err = writeError(conn, "verifier syntax error, k'=")
		return nil, nil, err
	}
	digest = shorthash("client", C, S, hexm, hexmu, hexsigma, hexHi)
	ks = enc64(digest)
	if ks != kc {
		err = writeError(conn, "verifier didn't match")
		return nil, nil, err
	}

	// make session key
	digest = shorthash("session", C, S, hexm, hexmu, hexsigma, hexHi)

	return &PAK{Peer: C, Session: digest}, pw, nil
}

func ex(tag string, s string) string {
	if len(s) < len(tag) || s[0:len(tag)] != tag {
		return ""
	}
	return s[len(tag):]
}

func erasekey(a []byte) {
	for i := range a {
		a[i] = 0
	}
}

func hmac_sha1(buf []byte, key []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	return mac.Sum(nil)
}

func enc64(buf []byte) string {
	return base64.StdEncoding.EncodeToString(buf)
}

func dec64(s string) (*big.Int, error) {
	a, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	i := new(big.Int)
	i.SetBytes(a)
	return i, nil
}
