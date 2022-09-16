package secstore_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/forsyth/auth/secstore"
)

func getenv(name string) string {
	s := os.Getenv(name)
	if s == "" {
		return "$" + name
	}
	return s
}

var secstoreServer = getenv("TESTSERVER")

var clientName = getenv("TESTUSER")

func clientKey() []byte {
	key := []byte(getenv("TESTKEY"))
	defer secstore.EraseKey(key)
	return secstore.KeyHash(key)
}

func clientFileKey() []byte {
	key := []byte(getenv("TESTKEY"))
	defer secstore.EraseKey(key)
	return secstore.FileKey(key)
}

func TestSecstore(t *testing.T) {
	sec, err := secstore.Dial("tcp", secstoreServer)
	if err != nil {
		t.Fatalf("can't dial %s: %s", secstoreServer, err)
	}
	defer sec.Close()
	err = sec.Auth(clientName, clientKey())
	if err != nil {
		t.Fatalf("can't authenticate as %s to %s: %s", clientName, secstoreServer, err)
	}
	t.Logf("connected to %s (%s) as %s", secstoreServer, sec.Peer, clientName)
	files, err := sec.Files()
	if err != nil {
		t.Errorf("failed to get file list: %s", err)
		return
	}
	for _, f := range files {
		t.Logf("%s %d %s %v", f.Name, f.Size, f.ModTime, f.Hash)
	}
	key := clientFileKey()
	testFileGet(t, sec, files, key)
	testFilePut(t, sec, key)
}

func testFileGet(t *testing.T, sec *secstore.Secstore, files []secstore.DirEntry, key []byte) {
	for _, dirent := range files {
		name := dirent.Name
		if dirent.Size > 32*1024 { // keep small but non-trivial for testing
			t.Logf("not fetching %s: %d bytes", name, dirent.Size)
			continue
		}
		data, err := fetchFile(sec, name, key)
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

func fetchFile(sec *secstore.Secstore, name string, key []byte) ([]byte, error) {
	rawdata, err := sec.GetFile(name, 0)
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
	return encdata, nil
}

func testFilePut(t *testing.T, sec *secstore.Secstore, key []byte) {
	file := []byte("mary had a little lamb\nits fleece was white as snow\nand everywhere that mary went\nthe lamb was sure to go\n")
	data, err := secstore.Encrypt(file, key)
	if err != nil {
		t.Errorf("failed to encrypt: %s", err)
		return
	}
	err = sec.PutFile("mary", data)
	if err != nil {
		t.Errorf("failed to put 'mary': %s", err)
		return
	}
	t.Logf("put file 'mary'")
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
