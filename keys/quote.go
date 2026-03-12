package keys

import (
	"strings"
)

// To mimic the format of Plan 9's factotum a Go variant of tokenize,
// using different (and much simpler) quoting conventions compared to strconv/Quote etc.
// so those can't be used here.

const quotable = " \t\r\n'"

// Quote returns s with quotes added as needed in the style of Plan 9's rc(1) to protect spaces and quotes,
// and to delimit empty strings.
func Quote(s string) string {
	if len(s) == 0 {
		return "''"
	}
	if !strings.ContainsAny(s, quotable) {
		return s
	}
	var sb strings.Builder
	sb.WriteByte('\'')
	for i := range len(s) {
		c := s[i]
		if c == '\'' {
			sb.WriteByte('\'')
		}
		sb.WriteByte(c)
	}
	sb.WriteByte('\'')
	return sb.String()
}

// isSpace accepts a specific set of white space separators.
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// Tokenize splits a string into an array of strings, one per field, with possibly-quoted fields separated by unquoted white space.
// The quoting characters are removed.
func Tokenize(s string) []string {
	var word strings.Builder
	args := []string{}
	inquote := false
	n := len(s)
	for j := 0; j < n; {
		c := s[j]
		if isSpace(c) {
			j++
			continue
		}
		i := j
		for ; i < n && (!isSpace(s[i]) || inquote); i++ { // collect word
			if s[i] == '\'' {
				if i != j {
					word.WriteString(s[j:i])
				}
				j = i + 1
				if !inquote || j == n || s[j] != '\'' { // will accept missing trailing quote
					inquote = !inquote
				} else {
					i++
				}
			}
		}
		word.WriteString(s[j:i])
		args = append(args, word.String())
		word.Reset()
		j = i
	}
	if len(args) == 0 {
		args = append(args, "")
	}
	return args
}
