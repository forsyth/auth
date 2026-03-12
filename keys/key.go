package keys

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Key holds the visible and secret attributes of a cryptographic key.
// In the textual form, secret attributes have a "!" prefix.
type Key struct {
	Proto   string // key protocol
	Visible Attrs  // public knowledge
	Secret  Attrs  // something to hide
}

var (
	ErrEmptyAttr = errors.New("empty attribute")
)

// NewKey makes a Key from a mixture of visible and secret attributes.
func NewKey(attrs Attrs) *Key {
	k := new(Key)
	k.Visible = []*Attr{}
	k.Secret = []*Attr{}
	var proto *Attr
	for _, a := range attrs {
		switch {
		case proto == nil && a.Name == "proto":
			proto = a
		case a.IsPublic():
			k.Visible = append(k.Visible, a)
		default:
			k.Secret = append(k.Secret, a)
		}
	}
	if proto != nil {
		k.Proto = proto.Name
		k.Visible = slices.Insert(k.Visible, 0, proto) // push proto to the front
	}
	return k
}

// ParseKey returns a key given its attr=value representation.
func ParseKey(s string) (*Key, error) {
	attrs, err := ParseAttrs(s)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	return NewKey(attrs), nil
}

// FindAttrVal returns the first instance of name=value in the key.
func (k *Key) FindAttrVal(name string) (string, bool) {
	if name[0] == '!' {
		return k.Secret.FindAttrVal(name)
	}
	return k.Visible.FindAttrVal(name)
}

// String returns the key in textual form but stripping the values from the secret attributes,
// leaving queries instead.
func (k *Key) String() string {
	if k == nil {
		return "nil"
	}
	var sb strings.Builder
	for _, va := range k.Visible {
		if sb.Len() != 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(va.String())
	}
	for _, sa := range k.Secret {
		if sb.Len() != 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(sa.Name)
		sb.WriteByte('?')
	}
	return sb.String()
}

// GoString returns the full text for a key including the values of secret attributes. NOT TO BE USED LIGHTLY.
func (k *Key) GoString() string {
	if k == nil {
		return "nil"
	}
	var sb strings.Builder
	for _, va := range k.Visible {
		if sb.Len() != 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(va.String())
	}
	for _, sa := range k.Secret {
		if sb.Len() != 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(sa.String())
	}
	return sb.String()
}

// MatchAttrs returns true iff the key matches at least the given set of attributes.
func (k *Key) MatchAttrs(attrs Attrs) bool {
	for _, a := range attrs {
		if !k.Visible.MatchAttr(a) && !k.Secret.MatchAttr(a) {
			return false
		}
	}
	return true
}

// Requires returns a string that lists the missing values for a set of attribute names, in the form of a key template.
func (k *Key) Requires(names []string) string {
	var sb strings.Builder
	for _, name := range names {
		if name == "" {
			continue
		}
		if name[0] == '!' {
			if k.Secret.FindAttr(name) != nil {
				continue
			}
		} else if k.Visible.FindAttr(name) != nil {
			continue
		}
		if sb.Len() != 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(name)
	}
	if sb.Len() != 0 {
		return sb.String()
	}
	return ""
}
