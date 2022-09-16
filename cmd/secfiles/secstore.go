package main

//
// interact with the Plan 9 secstore
//
// This secstore client is similar to the Inferno one, not the Plan 9 original.
// The interface and behaviour resembles those of ar or tar.

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"

	"github.com/forsyth/auth/internal/sio"
	"github.com/forsyth/auth/secstore"
	"golang.org/x/term"
)

const MaxFileSize = secstore.MaxFileSize

var verbose = false

func usage() {
	fmt.Fprintf(os.Stderr, "usage: auth/secstore [-i] [-v] [-k keyy] [-p pin] [-s server[:port]] [-u user] [{drptx} file ...]\n")
	os.Exit(2)
}

func main() {
	secstore.Privacy()

	var network, addr string
	var pass string
	var pin string
	var userName string
	thisUser, err := user.Current()
	if err != nil {
		fatal("can't find current user name: %s", err)
	}
	srv := os.Getenv("SECSTORE")
	if srv == "" {
		srv = "$SECSTORE"
	}
	defUser := thisUser.Username
	iflag := false
	flag.BoolVar(&iflag, "i", false, "key and optional PIN from standard input")
	flag.StringVar(&pass, "k", "", "key")
	flag.StringVar(&pin, "p", "", "pin")
	flag.StringVar(&network, "n", "tcp", "network")
	flag.StringVar(&addr, "s", srv+":"+secstore.Port, "secstore service address (host[:port])")
	flag.StringVar(&userName, "u", defUser, "user name on secstore service")
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.Parse()
	if !strings.ContainsRune(addr, ':') {
		addr = addr + ":" + secstore.Port
	}
	args := flag.Args()
	na := flag.NArg()
	op := 't'
	if na > 0 {
		// ar, tar-like convention (tv, rv, etc)
		switch {
		case len(args[0]) > 1 && args[0][1] == 'v':
			verbose = true // like ar, tar
			op = rune(args[0][0])
		case len(args[0]) > 1 && args[0][0] == 'v':
			verbose = true
			op = rune(args[0][1])
		case len(args[0]) == 1:
			op = rune(args[0][0])
		default:
			usage()
		}
		switch op {
		case 'd', 'r', 'p', 'x': // file operations
			if na < 2 {
				usage()
			}
		case 't':
			// ok without args
		default:
			usage()
		}
		args = args[1:]
	}
	if iflag {
		pass, pin = filePassword(os.Stdin)
		if pass == "" {
			fatal("missing password on standard input")
		}
	} else {
		pass = os.Getenv("SECSTOREKEY")
	}
	key := []byte(pass)
	initpw := len(key) != 0
	var filekey []byte
	var conn *secstore.Secstore
	for try := 0; ; try++ {
		conn, err = secstore.Dial(network, addr)
		if err != nil {
			fatal("can't connect to %s: %s", addr, err)
		}
		if len(key) == 0 {
			key = readPassword("secstore password")
			if len(key) == 0 {
				fmt.Fprintf(os.Stderr, "cancelled\n")
				os.Exit(1)
			}
		}
		filekey, err = auth(conn, userName, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "secstore: %s\n", err)
			if iflag {
				os.Exit(1)
			}
		} else if !conn.NeedPIN {
			break
		} else {
			if pin == "" {
				if iflag {
					fatal("no pin on standard input")
				}
				pin = string(readPassword("STA PIN+SecureID"))
				if pin == "" {
					fmt.Fprintf(os.Stderr, "cancelled\n")
					os.Exit(1)
				}
			}
			err = conn.SendPIN(pin)
			if err == nil {
				break
			}
			fmt.Fprintf(os.Stderr, "secstore: pin rejected: %s\n", err)
			if iflag {
				fatal("connection failed")
			}
		}
		if try > 3 || iflag || initpw {
			os.Exit(1)
		}
		conn.Close()
		sio.EraseKey(key)
		key, pin = nil, ""
	}
	defer conn.Close()
	if verbose {
		fmt.Fprintf(os.Stderr, "server: %s\n", conn.Peer)
	}
	defer sio.EraseKey(filekey)
	if op == 't' {
		sio.EraseKey(filekey) // no longer need it
		entries, err := conn.Files()
		if err != nil {
			fatal("can't fetch file list: %s", err)
		}
		for _, ent := range entries {
			if na > 0 {
				for _, a := range args {
					if a == ent.Name {
						break
					}
				}
				if args == nil {
					continue
				}
			}
			if verbose {
				fmt.Printf("%-14s %10d %s %s\n", ent.Name, ent.Size, ent.ModTime, sio.Enc64(ent.Hash))
			} else {
				fmt.Printf("%s\n", ent.Name)
			}
		}
		return
	}
	badexit := false
	for _, fname := range args {
		switch op {
		case 'd':
			checkname(fname, true)
			if err := conn.Remove(fname); err != nil {
				fatal("can't remove %s: %s", fname, err)
			}
			verb('d', fname)
		case 'p':
			base := checkname(fname, true)
			file := getfile(conn, fname, filekey)
			scanner := bufio.NewScanner(bytes.NewReader(file))
			for lno := 1; scanner.Scan(); lno++ {
				if _, err := os.Stdout.Write([]byte(scanner.Text() + "\n")); err != nil {
					// not fatal, because the usual application is sending to factotum
					// and an error in one key shouldn't prevent others being loaded
					badexit = true
					fmt.Fprintf(os.Stderr, "secstore (%s:%d): write error: %s", fname, lno, err)
				}
			}
			checkErr(scanner, "secstore file "+base)
			sio.EraseKey(file)
			verb('p', fname)
		case 'x':
			checkname(fname, true)
			file := getfile(conn, fname, filekey)
			ofd, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE, 0o600)
			if err != nil {
				fatal("can't create %s: %s", fname, err)
			}
			defer ofd.Close()
			if _, err := ofd.Write(file); err != nil {
				fatal("error writing to %s: %r", fname)
			}
			sio.EraseKey(file)
			verb('x', fname)
		case 'r':
			base := checkname(fname, false)
			ifd, err := os.Open(fname)
			if err != nil {
				fatal("can't open %s: %s", fname, err)
			}
			defer ifd.Close()
			data, err := io.ReadAll(ifd)
			if err != nil {
				fatal("can't replace file %s: %s", fname, err)
			}
			putfile(conn, base, filekey, data)
		default:
			fatal("unknown operation: %c", op)
		}
	}
	if badexit {
		os.Exit(1)
	}
}

// auth authenticates a secstore instance
func auth(conn *secstore.Secstore, userName string, key []byte) ([]byte, error) {
	seckey := secstore.KeyHash(key)
	defer sio.EraseKey(seckey)
	err := conn.Auth(userName, seckey)
	if err != nil {
		return nil, err
	}
	return secstore.FileKey(key), nil
}

func badname(s string) {
	fatal("can't use %s as a secstore file name", s) // server checks as well, of course
}

func checkname(s string, noslash bool) string {
	tail := s
	if o := strings.IndexByte(s, '/'); o >= 0 {
		if noslash {
			badname(s)
		}
		tail = s[o+1:]
	}
	if s == "" || tail == "" || s == ".." {
		badname(s)
	}
	for _, c := range s {
		if c == '\n' || c <= ' ' {
			badname(s)
			return ""
		}
	}
	return tail
}

func verb(op rune, n string) {
	if verbose {
		fmt.Fprintf(os.Stderr, "%c %s\n", op, n)
	}
}

func getfile(conn *secstore.Secstore, fname string, key []byte) []byte {
	f, err := conn.GetFile(fname, 0)
	if err != nil {
		fatal("can't fetch %s: %s", fname, err)
	}
	if fname != "." {
		f, err = secstore.Decrypt(f, key)
		if err != nil {
			fatal("can't decrypt %s: %s", fname, err)
		}
	}
	return f
}

func putfile(conn *secstore.Secstore, fname string, key []byte, file []byte) {
	enc, err := secstore.Encrypt(file, key)
	if err != nil {
		fatal("can't encrypt %s: %s", fname, err)
	}
	err = conn.PutFile(fname, enc)
	if err != nil {
		fatal("can't put file %s: %s", fname, err)
	}
}

// filePassword returns a password and optional pin read as the next two lines from standard input.
func filePassword(fd io.Reader) (string, string) {
	scanner := bufio.NewScanner(os.Stdin)
	var vals [2]string
	for i := 0; i < 2; i++ {
		if !scanner.Scan() {
			break
		}
		vals[i] = scanner.Text()
	}
	checkErr(scanner, "standard input")
	return vals[0], vals[1]
}

func checkErr(scanner *bufio.Scanner, name string) {
	if err := scanner.Err(); err != nil {
		if !errors.Is(err, io.EOF) {
			fatal("error reading %s: %s", name, err)
		}
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "secstore: "+format+"\n", args...)
	os.Exit(1)
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
