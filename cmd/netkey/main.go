package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/forsyth/auth/authsrv"
	"golang.org/x/term"
)

// test compatibility of encryption by implementing netkey
func main() {
	pw := readPassword("password")
	key := authsrv.PassToKey(string(pw))
	for {
		fmt.Fprintf(os.Stderr, "challenge: ")
		var w string
		nw, err := fmt.Scanln(&w)
		if err != nil || nw < 1 {
			return
		}
		n, err := strconv.ParseInt(w, 10, 32)
		chal := fmt.Sprint(n)
		resp := authsrv.Netcrypt(key, chal)
		fmt.Printf("response: %s\n", resp)
	}
}

func readPassword(prompt string) []byte {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	a, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fatal("error reading password: %s", err)
	}
	fmt.Fprintln(os.Stderr)
	return a
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "netkey: "+format+"\n", args...)
	os.Exit(1)
}
