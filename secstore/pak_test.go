package secstore_test

import (
	"bytes"
	"fmt"
	"math/big"
	"net"
	"testing"

	"github.com/forsyth/auth/secstore"
)

type result struct {
	side string
	pak  *secstore.PAK
	pw   *secstore.PW // server only
	err  error
}

const userName = "testuser"

var pass = "truly sorry"
var wrongpass = "nothing doing!"

func TestPAK(t *testing.T) {
	run(t, userName, pass, true)
	run(t, "fictitious", pass, false)
	run(t, userName, wrongpass, false)
}

func run(t *testing.T, name string, pass string, passes bool) {
	f0, f1 := net.Pipe()
	wait := make(chan result, 2)
	go server(f0, t, wait)
	go client(f1, t, name, secstore.KeyHash(pass), wait)
	v1 := <-wait
	v2 := <-wait
	if !passes {
		switch {
		case v1.err != nil && v2.err != nil:
			t.Logf("correctly failed: %s %v, %s %v", v1.side, v1.err, v2.side, v2.err)
		case v1.err == nil && v2.err == nil:
			t.Errorf("expected failure, both succeeded: %s %v, %s %v", v1.side, v1.pak, v2.side, v2.pak)
		default:
			t.Errorf("failed, but one side succeeded: %s %v, %s %v", v1.side, v1.err, v2.side, v2.err)
		}
		return
	}
	switch {
	case v1.err != nil || v2.err != nil:
		t.Errorf("failed: %s %v, %s %v", v1.side, v1.err, v2.side, v2.err)
	case v1.pak != nil && v2.pak != nil:
		if !bytes.Equal(v1.pak.Session, v2.pak.Session) {
			t.Errorf("succeeded, but different session keys: %s %v %v, %s %v %v", v1.side, v1.pak, v1.pw, v2.side, v2.pak, v2.pw)
		} else {
			t.Logf("succeeded: %s %v %v, %s %v %v", v1.side, v1.pak, v1.pw, v2.side, v2.pak, v2.pw)
		}
	case v1.pak == nil || v2.pak == nil:
		t.Errorf("expected success, one failed silently: %s %v, %s, %v", v1.side, v1.pak, v2.side, v2.pak)
	default:
		t.Errorf("unexpected pass case: %s %v %v, %s %v %v", v1.side, v1.pak, v1.err, v2.side, v2.pak, v2.err)
	}
}

type user struct {
	name  string
	hi    *big.Int
	hexHi string
}

type users map[string]*user

func NewUsers() users {
	m := make(map[string]*user)
	hexHi, _, Hi := secstore.PAKHi("testuser", secstore.KeyHash(pass))
	m["testuser"] = &user{"testuser", Hi, hexHi}
	return users(m)
}

func (us users) Look(name string) (*secstore.PW, error) {
	u, ok := us[name]
	if !ok {
		return nil, fmt.Errorf("unknown user: %q", name)
	}
	return &secstore.PW{Key: u, Hi: u.hi}, nil
}

func server(conn net.Conn, t *testing.T, wait chan result) {
	defer conn.Close()
	userset := NewUsers()
	pak, pw, err := secstore.Server(conn, secstore.Version(), "devious", userset)
	wait <- result{"server", pak, pw, err}
}

func client(conn net.Conn, t *testing.T, name string, pass []byte, wait chan result) {
	defer conn.Close()
	pak, err := secstore.Client(conn, secstore.Version(), name, pass)
	wait <- result{"client", pak, nil, err}
}
