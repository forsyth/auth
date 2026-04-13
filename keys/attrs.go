// Package keys implements authentication keys in the style of Plan 9's Factotum.
// Keys are lists of attributes of the form of name=value and name?.
// A name starting with ! names a secret and its value must be handled with care.
package keys

import (
	"fmt"
	"slices"
	"strings"
)

// Kind tells the form of an attribute: name=value, name? and an internal one for match defaults, name:=value.
type Kind int

const (
	Valued  Kind = iota // Valued tags a name=value attribute.
	Query               // Query tags a query attribute, name?
	Default             // Default is used internally to represent a matching state, name:=value
)

// Attr represents an attribute of a key.
type Attr struct {
	Tag  Kind
	Name string
	Val  string
}

// NewValue makes a new attribute assigning val to name.
func NewValue(tag Kind, name, val string) *Attr {
	return &Attr{
		Tag:  Valued,
		Name: name,
		Val:  val,
	}
}

// NewQuery makes a new query attribute for the given name.
func NewQuery(name string) *Attr {
	return &Attr{
		Tag:  Query,
		Name: name,
	}
}

func (a *Attr) String() string {
	switch a.Tag {
	case Valued:
		return Quote(a.Name) + "=" + Quote(a.Val)
	case Query:
		return Quote(a.Name) + "?"
	case Default:
		return Quote(a.Name) + ":=" + Quote(a.Val)
	default:
		return a.Name + "??"
	}
}

// IsSecret is true iff the key name starts with "!" and thus is secret.
func (a *Attr) IsSecret() bool {
	return len(a.Name) != 0 && a.Name[0] == '!'
}

// IsPublic is true iff the key is not secret.
func (a *Attr) IsPublic() bool {
	return !a.IsSecret()
}

// Less sorts keys in alphabetical order, but secrets are kept at the back.
func (a *Attr) Less(b *Attr) bool {
	if a.IsSecret() && !b.IsSecret() {
		return false
	}
	if !a.IsSecret() && b.IsSecret() {
		return true
	}
	return a.Name < b.Name
}

// Attrs represents a sequence of attributes.
// Currently it is a slice not a map to keep the
// original textual order if possible, although it
// is not clear that matters.
type Attrs []*Attr

// ParseAttrs parses and returns the attribute/value pairs from string s.
func ParseAttrs(s string) (Attrs, error) {
	attrs := make(Attrs, 0)
	seen := make(map[string]bool)
	for _, f := range Tokenize(s) {
		l := len(f)
		if l == 0 {
			return nil, ErrEmptyAttr
		}
		if f[0] == '=' || f == "?" || f == "!?" {
			return nil, fmt.Errorf("missing name: %q", f)
		}
		if v, n, ok := strings.Cut(f, "="); ok {
			seen[n] = true
			attrs = append(attrs, &Attr{Tag: Valued, Name: n, Val: v})
		} else if l > 1 && f[l-1] == '?' {
			n = f[0 : l-1]
			attrs = append(attrs, &Attr{Tag: Query, Name: n})
		} else {
			return nil, fmt.Errorf("missing value or query: %q", f)
		}
	}

	// remove answered queries
	return slices.DeleteFunc(attrs, func(a *Attr) bool {
		return a.Tag == Query && seen[a.Name]
	}), nil
}

func (as Attrs) stringTo(sb *strings.Builder, hide bool) {
	for _, a := range as {
		if sb.Len() != 0 {
			sb.WriteByte(' ')
		}
		if hide && a.IsSecret() {
			sb.WriteString(a.Name)
			sb.WriteByte('?')
		} else {
			sb.WriteString(a.String())
		}
	}
}

// String returns the attributes in textual form,
// stripping the values from the secret ones,leaving queries instead.
func (as Attrs) String() string {
	var sb strings.Builder
	as.stringTo(&sb, true)
	return sb.String()
}

// SecretString returns the attributes in textual form, leaving the secret values visible.
// Obviously this must be used with care.
func (as Attrs) SecretString() string {
	var sb strings.Builder
	as.stringTo(&sb, false)
	return sb.String()
}

// FindAttr returns the first attribute with the given name,
// or nil if nothing matches.
func (as Attrs) FindAttr(name string) *Attr {
	for _, a := range as {
		if a.Tag == Valued && a.Name == name {
			return a
		}
	}
	return nil
}

// FindAttrVal returns the value of the first attribute with the given name.
func (as Attrs) FindAttrVal(name string) (string, bool) {
	a := as.FindAttr(name)
	if a == nil || a.Tag != Valued {
		return "", false
	}
	return a.Val, true
}

// AnyAttr returns true if name matches any name=value in the given set.
func (as Attrs) AnyAttr(name string) bool {
	for _, a := range as {
		if a.Tag == Valued && a.Name == name {
			return true
		}
	}
	return false
}

// DelAttr removes all attributes with the given name.
func (as Attrs) DelAttr(name string) Attrs {
	if !as.AnyAttr(name) {
		return as
	}
	return slices.DeleteFunc(as, func(a *Attr) bool {
		return a.Name == name
	})
}

func ignored(s string) bool {
	return s == "" || s == "role" || s == "disabled" || s[0] == ':'
}

// MatchAttr returns true iff the given attribute matches one in as.
func (as Attrs) MatchAttr(pat *Attr) bool {
	b := as.FindAttr(pat.Name)
	if b == nil {
		return false
	}
	return pat.Tag == Query || pat.Val == b.Val || ignored(pat.Name)
}
