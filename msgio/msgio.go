// Package msgio provides record-oriented messaging on arbitrary transport,
// compatible with Inferno's msgio.m. It also allows sending and receiving error messages.
// There are two formats: one with byte counts before messages, usable
// on streams without delimiters; and one that distinguishes normal
// and error messages more simply, assuming the stream is delimited.

package msgio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

const (
	// MaxMsg is the largest message size in bytes.
	// It was an old choice and might be too small for long keys now.
	MaxMsgLen = 4096

	// MaxErr is the largest error message size in bytes.
	// Longer messages are truncated.
	MaxErrLen = 999

	// HdrLen is the length of the byte-count header: "dddd\n" for normal messages,
	//" !ddd\n "for error messages, where d is a decimal digit.
	HdrLen = 5
)

var (
	ErrBadFormat = errors.New("message header format error")
	ErrTooLong = errors.New("message too long")
)

// MsgIO provides message-oriented IO on a stream that might not
// be delimited, for instance before pushing TLS. Initially it provides
// its own byte counts. After calling [Delimited], a simpler message format is used,
// suitable when the stream provides its own message boundaries.
type MsgIO struct {
	FD	io.ReadWriter
	ob	*bytes.Buffer
	hdr	[HdrLen]byte
	ib	[MaxMsgLen]byte
	delim	bool	// true if stream keeps message boundaries
	hdrlen	int	// current header length (5 w/o delim, 1 with)
}

// New returns a new message-oriented connection above the
// stream fd, which is assumed not to provide its own delimiters.
func New(fd io.ReadWriter) *MsgIO {
	return &MsgIO{
		FD: fd,
		ob: bytes.NewBuffer(make([]byte, 0, MaxMsgLen+HdrLen)),
		delim: false,
		hdrlen: HdrLen,
	}
}

// Delimited marks the stream as keeping message boundaries.
func (m *MsgIO) Delimited() {
	m.delim = true
	m.hdrlen = 1
}

func (m *MsgIO) writeHdr(l int) {
	m.ob.Reset()
	if m.delim {
		m.ob.WriteByte(0)
	} else {
		m.ob.WriteString(fmt.Sprintf("%04d\n", l))
	}
}

func (m *MsgIO) writeErr(l int) {
	m.ob.Reset()
	if m.delim {
		m.ob.WriteByte(0xFF)
	} else {
		m.ob.WriteString(fmt.Sprintf("!%03d\n", l))
	}
}

// Write implements the standard Write interface,
// formatting the data as required by the current
// delimited status.
func (m *MsgIO) Write(data []byte) (int, error) {
	l := len(data)
	if l > MaxMsgLen {
		return 0, ErrTooLong
	}
	m.writeHdr(l)
	m.ob.Write(data)
	nw := m.ob.Len()
	n, err := m.ob.WriteTo(m.FD)
	if err != nil {
		return 0, err
	}
	if n < int64(nw) {
		return 0, io.ErrShortWrite
	}
	return int(n) - m.hdrlen, nil
}

// WriteString writes the contents of the string s to the underlying output stream.
// A reader will see the string delimited as a single message.
func (m *MsgIO) WriteString(s string) (int, error) {
	return m.Write([]byte(s))
}

// WriteError writes an error message to the underlying output stream.
// A Read or ReadString on the other end will return with that error.
func (m *MsgIO) WriteError(err error) (int, error) {
	a := []byte(err.Error())
	l := len(a)
	if l > MaxErrLen {
		l = MaxErrLen
	}
	m.writeErr(l)
	m.ob.Write(a[0: l])
	n, err := m.ob.WriteTo(m.FD)
	return int(n), err
}

// readErr reads and returns an error message, as the error return.
// If the read fails, that error is returned instead, preceded by the
// text "remote: ", to distinguish it from local errors.
func (m *MsgIO) readErr(n int) (int, error) {
	n, err := io.ReadFull(m.FD, m.ib[0: n])
	if err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("remote: %s", string(m.ib[0: n]))
}

// getMsg reads into data and returns the byte count,
// unless it is an error message, which is returned as the error value.
func (m *MsgIO) readMsg(data []byte) (int, error) {
	if m.delim {
		n, err := m.FD.Read(m.hdr[0: 1])
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		if m.hdr[0] == 0xFF {
			return m.readErr(MaxErrLen)
		}
		if m.hdr[0] != 0 {
			return 0, ErrBadFormat
		}
		return m.FD.Read(data)
	}
	n, err := io.ReadFull(m.FD, m.hdr[0: HdrLen])
	if err != nil {
		return 0, err
	}
	if n < HdrLen || m.hdr[HdrLen-1] != '\n' {
		return 0, ErrBadFormat
	}
	isErr := false
	i := 0
	if m.hdr[0] == '!' {
		isErr = true
		i = 1
	}
	// ParseInt is overkill
	n = 0
	for ; i < 4; i++ {
		c := m.hdr[i]
		if !(c >= '0' && c <= '9') {
			return 0, ErrBadFormat
		}
		n = n*10 + (int(c)-'0')
	}
	if n > MaxMsgLen {
		return 0, ErrTooLong
	}
	if isErr {
		return m.readErr(n)
	}
	return io.ReadFull(m.FD, data[0: n])
}

// Read implements the Reader interface, returning
// the number of bytes read into the given data buffer,
// and any error.
func (m *MsgIO) Read(data []byte) (int, error) {
	return m.readMsg(data)
}

// ReadString reads and returns data to be interpreted as a UTF-8 string.
func (m *MsgIO) ReadString() (string, error) {
	n, err := m.readMsg(m.ib[0:])
	if err != nil {
		return "", err
	}
	return string(m.ib[0: n]), nil
}
