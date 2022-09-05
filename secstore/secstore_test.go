package secstore_test

import (
	"net"
	"os"
	"testing"

	"github.com/forsyth/auth/internal/ssl"
	"github.com/forsyth/auth/secstore"
)

const secstoreServer = "plan9.terzarima.net:5356"

var clientName = os.Getenv("TESTUSER")

func clientKey() []byte {
	return secstore.KeyHash(os.Getenv("TESTKEY"))
}

func clientFileKey() []byte {
	return secstore.FileKey(os.Getenv("TESTKEY"))
}

func TestBasicSecstoreConnection(t *testing.T) {
	conn, err := net.Dial("tcp", secstoreServer)
	if err != nil {
		t.Errorf("can't dial %s: %s", secstoreServer, err)
		return
	}
	conn = ssl.Client(conn)
	defer conn.Close()
	pak, err := secstore.Client(conn, secstore.Version(), clientName, clientKey())
	if err != nil {
		t.Errorf("access as %s rejected: %s", clientName, err)
		return
	}
	t.Logf("pak succeeded as %s: %#v", clientName, pak)
}

func TestFileList(t *testing.T) {
	conn, sname, _, err := secstore.Connect("tcp", secstoreServer, clientName, clientKey())
	if err != nil {
		t.Errorf("can't connect to %s: %s", secstoreServer, err)
	}
	defer secstore.Bye(conn)
	t.Logf("connected to %s (%s) as %s", secstoreServer, sname, clientName)
	files, err := secstore.Files(conn)
	if err != nil {
		t.Errorf("failed to get file list: %s", err)
		return
	}
	for _, f := range files {
		t.Logf("%s %d %s %v", f.Name, f.Size, f.ModTime, f.Hash)
	}
}

func TestFileGet(t *testing.T) {
	conn, sname, _, err := secstore.Connect("tcp", secstoreServer, clientName, clientKey())
	if err != nil {
		t.Errorf("can't connect to %s: %s", secstoreServer, err)
	}
	defer secstore.Bye(conn)
	t.Logf("connected to %s (%s) as %s", secstoreServer, sname, clientName)
	rawdata, err := secstore.GetFile(conn, "factotum", 0)
	if err != nil {
		t.Errorf("failed to get file: users: %v", err)
		return
	}
	t.Logf("file users: %d bytes", len(rawdata))
	data, err := secstore.Decrypt(rawdata, clientFileKey())
	if err != nil {
		t.Errorf("failed to decrypt file: users: %v", err)
		return
	}
	t.Logf("decrypted: %d bytes", len(data))
	println(string(data))
	xdata, err := secstore.Encrypt(data, clientFileKey(), rawdata[0: 16])
	if err != nil {
		t.Errorf("failed to encrypt file: users: %v", err)
		return
	}
	ydata, _ := secstore.Decrypt(xdata, clientFileKey())
	if !eq(data, ydata) {
		t.Errorf("second decrypt different")
	}
	println(len(xdata))
	println(len(ydata))
	if !eq(rawdata, xdata) {
		t.Errorf("failed to re-encrypt properly")
		return
	}
}

func eq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			println("mismatch", i, a[i], b[i])
			return false
		}
	}
	return true
}
