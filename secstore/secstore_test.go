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

func TestRemoteSecstore(t *testing.T) {
	conn, err := net.Dial("tcp", secstoreServer)
	if err != nil {
		t.Errorf("can't dial %s: %s", secstoreServer, err)
		return
	}
	conn = ssl.Client(conn)
	key := secstore.KeyHash(os.Getenv("TESTKEY"))
	pak, err := secstore.Client(conn, secstore.Version(), clientName, key)
	if err != nil {
		t.Errorf("access as %s rejected: %s", clientName, err)
		return
	}
	t.Logf("pak succeeded as %s: %#v", clientName, pak)
}
