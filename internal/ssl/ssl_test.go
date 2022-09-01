package ssl_test

import (
	"github.com/forsyth/auth/internal/ssl"
	"net"
	"sync"
	"testing"
)

func TestSSL(t *testing.T) {
	f0, f1 := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(2)
	go server(f0, t, nil, &wg)
	go client(f1, t, nil, &wg)
	wg.Wait()
	secret := make([]byte, 20)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	f0, f1 = net.Pipe()
	wg.Add(2)
	go server(f0, t, secret, &wg)
	go client(f1, t, secret, &wg)
	wg.Wait()
}

func server(a net.Conn, t *testing.T, secret []byte, wg *sync.WaitGroup) {
	f := ssl.Client(a)
	defer f.Close()
	if secret != nil {
		f.StartCipher(secret, secret)
	}
	for i := 0; i < 5; i++ {
		nw, err := f.Write([]byte("hey there!\n"))
		if err != nil {
			t.Errorf("write error: %d %s", nw, err)
		} else {
			t.Logf("wrote %d\n", nw)
		}
	}
	wg.Done()
}

func client(a net.Conn, t *testing.T, secret []byte, wg *sync.WaitGroup) {
	f := ssl.Client(a)
	defer f.Close()
	if secret != nil {
		f.StartCipher(secret, secret)
	}
	for i := 0; i < 5; i++ {
		buf := make([]byte, ssl.MaxMsg)
		nr, err := f.Read(buf)
		if err != nil {
			t.Errorf("read error: %d %s", nr, err)
		} else {
			t.Logf("read %d %q\n", nr, string(buf[0:nr]))
		}
	}
	wg.Done()
}
