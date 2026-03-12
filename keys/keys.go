package keys

import (
	"iter"
	"slices"
)

// Keystore stores a set of public and private keys for a cryptosystem.
type Keystore struct {
	// Keys lists the keys.
	Keys []*Key
}

func NewKeystore() *Keystore {
	return &Keystore{Keys: []*Key{}}
}

func (ks *Keystore) FindKey(attrs Attrs) *Key {
	for _, k := range ks.Keys {
		if k.MatchAttrs(attrs) {
			return k
		}
	}
	return nil
}

func (ks *Keystore) FindKeys(attrs Attrs) []*Key {
	kl := []*Key{}
	for _, k := range ks.Keys {
		if k.MatchAttrs(attrs) {
			kl = append(kl, k)
		}
	}
	return kl
}

func (ks *Keystore) DelKey(attrs Attrs) int {
	kl := []*Key{}
	for _, k := range ks.Keys {
		if !k.MatchAttrs(attrs) {
			kl = append(kl, k)
		}
	}
	ndel := len(ks.Keys) - len(kl)
	ks.Keys = kl
	return ndel
}

func (ks *Keystore) AddKey(k *Key) {
	ks.Keys = append(ks.Keys, k)
}

func (ks *Keystore) All() iter.Seq[*Key] {
	return slices.Values(ks.Keys)
}
