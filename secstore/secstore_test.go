package secstore_test

import (
	"fmt"
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

func TestSecstore(t *testing.T) {
	conn, sname, _, err := secstore.Connect("tcp", secstoreServer, clientName, clientKey())
	if err != nil {
		t.Fatalf("can't dial %s: %s", secstoreServer, err)
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
	key := clientFileKey()
	testFileGet(t, conn, files, key)
}

func testFileGet(t *testing.T, conn *ssl.Conn, files []secstore.DirEntry, key []byte) {
	for _, dirent := range files {
		name := dirent.Name
		if dirent.Size > 32*1024 {	// keep small but non-trivial for testing
			t.Logf("not fetching %s: %d bytes", name, dirent.Size)
			continue
		}
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
