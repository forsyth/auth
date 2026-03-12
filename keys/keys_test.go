package keys_test

import (
	"fmt"
	"testing"

	"github.com/forsyth/auth/keys"
)

var quota []string = []string{
	"",
	"nothingtodo",
	"hello world",
	"'",
	"won't",
	"won't do it",
}

func TestQuote(t *testing.T) {
	for _, q := range quota {
		quoth := keys.Quote(q)
		toks := keys.Tokenize(quoth)
		if len(toks) != 1 {
			t.Errorf("have %q got %v; expected %q", quoth, toks, quoth)
		}
	}
}

var protos []string = []string {
	"proto=pass server=virgin.com user=00618806204 !password?",
	"proto=p9sk1 dom=terzarima.net user=forsyth !password?",
	"proto=p9sk1 dom=vitanuova.com user=forsyth !password?",
	"proto=p9sk1 dom=outside.plan9.bell-labs.com user=forsyth !password?",
	"proto=pass server=finestre service=ssh user=Administrator !password?",
	"proto=pass server=macdante service=ssh user=forsyth !password?",
	"proto=pass server=frangipani service=ssh user=forsyth !password?",
	"proto=pass server=www.fandc.com user=INV5772740 !password=frodo !memorable=12345",
}

var queries []string = []string {
	"dom=terzarima.net",
	"user=forsyth",
	"user=forsyth service=ssh",
	"user=INV5772740 !memorable=12345",
}

func TestKeys(t *testing.T) {
	ks := keys.NewKeystore()
	for _, proto := range protos {
		fmt.Printf("tokenize: %#v\n", keys.Tokenize(proto))
		key, err := keys.ParseKey(proto)
		if err != nil {
			t.Logf("parse key %s err %s", proto, err)
			continue
		}
		fmt.Printf("parse key %s:\nkey: %s\n", proto, key)
		ks.AddKey(key)
	}
	for _, query := range queries {
		fmt.Printf("query %s\n", query)
		attrs, err := keys.ParseAttrs(query)
		if err != nil {
			t.Logf("parse query %s: %s", query, err)
			continue
		}
		kl := ks.FindKeys(attrs)
		if kl == nil {
			t.Errorf("query %s; got nothing", query)
			continue
		}
		for _, k := range kl {
			fmt.Printf("\t%s\n", k)
		}
	}
}
