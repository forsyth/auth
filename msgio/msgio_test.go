package msgio_test

import (	
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/forsyth/auth/msgio"
)

var errTest = errors.New("Test Error Message ¡!")

var sizes = []int{ 5, 275, 1925, 2049, 4096, 9999}

func data(n int) []byte {
	a := make([]byte, n)
	for i := range n {
		a[i] = byte(i)
	}
	return a
}

func checkData(data []byte) bool {
	for i, b := range data {
		if b != byte(i) {
			return false
		}
	}
	return true
}

func reader(t *testing.T, r *os.File, done chan<- int) {
	defer r.Close()
	msg := msgio.New(r)
	for _, size := range sizes {
		buf := make([]byte, size)
		if size > msgio.MaxMsgLen {
			continue
		}
		n, err := msg.Read(buf)
		if err != nil {
			// give up, since out of sync
			t.Fatalf("want block of %d bytes; got error %s", size, err)
		}
		if n != size {
			t.Fatalf("read block: want block of %d bytes; got %d", size, n)
		}
		if !checkData(buf) {
			t.Errorf("read block: want %v; got %v", data(len(buf)), buf)
		}
	}
	s0, err := msg.ReadString()
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}
	if s0 != "hello" {
		t.Errorf("read string: want \"hello\"; got %q", s0)
	}
	s1, err := msg.ReadString()
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}
	if s1 != "new world" {
		t.Errorf("read string: want \"new world\"; got %q", s1)
	}
	s3, err := msg.ReadString()
	if err == nil {
		t.Errorf("read string: want error %s; got %q", errTest, s3)
	}
	if err.Error() != "remote: "+errTest.Error() {
		t.Errorf("read string: want error %s; got error %s", errTest, err)
	}
	close(done)
}

func TestMsgIO(t *testing.T) {
	// os.Pipe gives the old style one-directional pipe, sadly.
	r, w, _ := os.Pipe()
	done := make(chan int)
	go reader(t, r, done)
	msg := msgio.New(w)
	for _, size := range sizes {
		buf := data(size)
		n, err := msg.Write(buf)
		if err != nil {
			if size > msgio.MaxMsgLen {
				continue
			}
			// give up, since out of sync
			t.Fatalf("wrote %d bytes; got error %s", size, err)
		}
		if size > msgio.MaxMsgLen {
			t.Errorf("wrote %d bytes, want message too long error; got %d", size, n)
		}
		if n != size {
			t.Fatalf("write block: wrote block of %d bytes; got %d", size, n)
		}
	}
	msg.WriteString("hello")
	msg.Write([]byte("new world"))
	msg.WriteError(errTest)
	w.Close()
	<-done
}
