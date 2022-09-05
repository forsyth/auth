package secstore_test

import (
	"fmt"
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

var testFiles = []string {
	"users",
	"factotum",
}

func TestFileGet(t *testing.T) {
	conn, sname, _, err := secstore.Connect("tcp", secstoreServer, clientName, clientKey())
	if err != nil {
		t.Errorf("can't connect to %s: %s", secstoreServer, err)
	}
	defer secstore.Bye(conn)
	t.Logf("connected to %s (%s) as %s", secstoreServer, sname, clientName)
	key := clientFileKey()
	for _, name := range testFiles {
		data, err := fetchFile(conn, name, key)
		if err != nil {
			t.Errorf("fetch %s: %s", name, err)
			continue
		}
		t.Logf("decrypted %s: %d bytes", name, len(data))
		data, err = testEncrypt(data, key)
		if err != nil {
			t.Errorf("encrypt %s: %s", name, err)
			continue
		}
		t.Logf("re-encrypted %s ok, %d bytes", name, len(data))
	}
}

func fetchFile(conn *ssl.Conn, name string, key []byte) ([]byte, error) {
	rawdata, err := secstore.GetFile(conn, name, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get file: %w", err)
	}
	data, err := secstore.Decrypt(rawdata, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file: %w", err)
	}
	return data, nil
}

func testEncrypt(data []byte, key []byte) ([]byte, error) {
	encdata, err := secstore.Encrypt(data, key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}
	cdata, err := secstore.Decrypt(encdata, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	if !eq(data, cdata) {
		return nil, fmt.Errorf("second decrypt different")
	}
	//println(len(xdata))
	//println(len(ydata))
	return encdata, nil
}

func eq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
