package authsrv_test

import (
//	"fmt"
	"reflect"
	"testing"

	"github.com/forsyth/auth/authsrv"
)

// quick test plan9.auth.P9auth pack and unpack

type ticketreq authsrv.TicketReq

func (tr *ticketreq) Pack(key []byte) []byte {
	return (*authsrv.TicketReq)(tr).Pack()
}

func (tr *ticketreq) Unpack(a []byte, key []byte) (int, error) {
	return (*authsrv.TicketReq)(tr).Unpack(a)
}

func blank(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

type Packer interface {
	Pack([]byte) []byte
	Unpack(a []byte, key []byte) (int, error)
}

type detail struct {
	len	int	// wire length in bytes
	new	func() Packer	// new value to unpack into
}

// details gives the wire length and makers for the various types.
var details map[string]detail = map[string]detail{
	"Ticket":        detail{ authsrv.TICKETLEN, func()Packer { return new(authsrv.Ticket) }},
	"ticketreq":     detail{ authsrv.TICKREQLEN, func()Packer { return new(ticketreq) }},
	"Authenticator": detail{ authsrv.AUTHENTLEN, func() Packer { return new(authsrv.Authenticator) }},
	"PasswordReq":   detail{ authsrv.PASSREQLEN, func() Packer { return new(authsrv.PasswordReq) }},
}

func typeName(p Packer) string {
	switch p.(type) {
	case *authsrv.Ticket:
		return "Ticket"
	case *ticketreq:
		return "ticketreq"
	case *authsrv.Authenticator:
		return "Authenticator"
	case *authsrv.PasswordReq:
		return "PasswordReq"
	default:
		panic("typeName")
	}
}

func TestAuthsrv(t *testing.T) {
	chal := blank(authsrv.CHALLEN)
	key := blank(authsrv.DESKEYLEN)
	pw := blank(authsrv.ANAMELEN)
	pw[authsrv.ANAMELEN-1] = 0
	secret := blank(authsrv.SECRETLEN)
	secret[authsrv.SECRETLEN-1] = 0
	var cases []Packer = []Packer {
		&ticketreq{RType: authsrv.AuthTreq, AuthID: "bootes", AuthDom: "plan9.com", Chal: chal, HostID: "example.com", UID: "gre"},
		&authsrv.Ticket{Num: 1, Chal: chal, ClientID: "gre", ServerID: "erg", Key: key},
		&authsrv.Authenticator{Num: 1, Chal: chal, ID: 12345},
		&authsrv.PasswordReq{Num: 1, Old: pw, New: pw, ChangeSecret: true, Secret: secret},
	}
	for _, c := range cases {
		tn := typeName(c)
		a := c.Pack(key)
		det := details[tn]
		if len(a) != det.len {
			t.Errorf("%s length: wanted %d; got %d", tn, det.len, len(a))
		}
		nv := det.new()
		nb, err := nv.Unpack(a, key)
		if err != nil {
			t.Errorf("%s: wanted %v; got error %v", tn, c, err)
		}
		if !reflect.DeepEqual(nv, c) {
			t.Errorf("%s: wanted %v; got %v", tn, c, nv)
		} else if nb != det.len {
			t.Errorf("%s unpacked length: wanted %d; got %d", tn, det.len, nb)
		}
		//fmt.Printf("%d %#v %v\n", nb, nv, err)
	}
}
