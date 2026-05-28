// Package msgio provides record-oriented messaging on arbitrary transport,
// that might not delimit messages, for instance TCP/IP before pushing TLS,
// or reading structured data from a file.
// It also allows sending and receiving error messages.
// There are two formats: one with byte counts before messages, usable
// on streams without delimiters; and one that distinguishes normal
// and error messages more simply, when told the stream is delimited.
// This implementation is compatible with Inferno's msgio.m.

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
	ErrReadOnly = errors.New("read-only stream")
)

// ReadWriter stores pointers to both a [Reader] and a [Writer],
// satisfying [io.ReadWriter].
type ReadWriter struct {
	*Reader
	*Writer
}

// NewReadWriter allocates a new structure that despatches to [r] and [w].
func NewReadWriter(r *Reader, w *Writer) *ReadWriter {
	return &ReadWriter{r, w}
}

// Delimited marks both Reader and Writer streams as delimited.
func (io *ReadWriter) Delimited() {
	io.Reader.Delimited()
	io.Writer.Delimited()
}

type delims struct {
	delim	bool	// true if stream keeps message boundaries
	hdrlen	int	// current header length (5 w/o delim, 1 with)
}

// Writer writes successive messages to an underlying stream,
// that might or might not delimit message boundaries.
// Initially it writes a byte count to delimit a message and to distinguish
// a data message from an error message.
// Once [Delimited] has been called, and the underlying stream
// provides its own message boundaries, a simpler format is used that
// distinguishes data messages from error messages.
type Writer struct {
	wr	io.Writer
	delims
	ob	*bytes.Buffer
}

// NewWriter returns a new [Writer], output to a message-oriented connection on
// [rd], which is assumed not to provide its own delimiters.
func NewWriter(fd io.Writer) *Writer {
	return &Writer {
		wr: fd,
		delims: delims{false, HdrLen},
		ob: bytes.NewBuffer(make([]byte, 0, MaxMsgLen+HdrLen)),
	}
}

// Delimited marks the stream as keeping message boundaries.
func (wr *Writer) Delimited() {
	wr.delim = true
	wr.hdrlen = 1
}

func (wr *Writer) writeHdr(l int) {
	wr.ob.Reset()
	if wr.delim {
		wr.ob.WriteByte(0)
	} else {
		wr.ob.WriteString(fmt.Sprintf("%04d\n", l))
	}
}

func (wr *Writer) writeErr(l int) {
	wr.ob.Reset()
	if wr.delim {
		wr.ob.WriteByte(0xFF)
	} else {
		wr.ob.WriteString(fmt.Sprintf("!%03d\n", l))
	}
}

// Write implements the standard Write interface,
// formatting the data as required by the current
// delimited status.
func (wr *Writer) Write(data []byte) (int, error) {
	l := len(data)
	if l > MaxMsgLen {
		return 0, ErrTooLong
	}
	wr.writeHdr(l)
	wr.ob.Write(data)
	nw := wr.ob.Len()
	n, err := wr.ob.WriteTo(wr.wr)
	if err != nil {
		return 0, err
	}
	if n < int64(nw) {
		return 0, io.ErrShortWrite
	}
	return int(n) - wr.hdrlen, nil
}

// WriteString writes the contents of the string s to the underlying output stream.
// A reader will see the string delimited as a single message.
func (wr *Writer) WriteString(s string) (int, error) {
	return wr.Write([]byte(s))
}

// WriteError writes an error message to the underlying output stream.
// A Read or ReadString on the other end will return with that error.
func (wr *Writer) WriteError(err error) (int, error) {
	a := []byte(err.Error())
	l := len(a)
	if l > MaxErrLen {
		l = MaxErrLen
	}
	wr.writeErr(l)
	wr.ob.Write(a[0: l])
	n, err := wr.ob.WriteTo(wr.wr)
	return int(n), err
}

// Reader returns successive messages from an underlying stream,
// that might or might not delimit message boundaries.
// Initially it reads a byte count to delimit a message and to distinguish
// a data message from an error message.
// Once [Delimited] has been called, and the underlying stream
// provides its own message boundaries, a simpler format is used that
// distinguishes data messages from error messages.
type Reader struct {
	rd	io.Reader
	delims
	hdr	[HdrLen]byte
	ib	[MaxMsgLen]byte
}

// NewReader returns a new [Reader], input from a message-oriented connection above the
// stream [fd], which is assumed not to provide its own delimiters.
func NewReader(fd io.Reader) *Reader {
	return &Reader{
		rd: fd,
		delims: delims{false, HdrLen},
	}
}

// Delimited marks the stream as keeping message boundaries.
func (rd *Reader) Delimited() {
	rd.delim = true
	rd.hdrlen = 1
}

// readErr reads and returns an error message, as the error return.
// If the read fails, that error is returned instead, preceded by the
// text "remote: ", to distinguish it from local errors.
func (rd *Reader) readErr(n int) (int, error) {
	n, err := io.ReadFull(rd.rd, rd.ib[0: n])
	if err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("remote: %s", string(rd.ib[0: n]))
}

// getMsg reads into data and returns the byte count,
// unless it is an error message, which is returned as the error value.
func (rd *Reader) readMsg(data []byte) (int, error) {
	if rd.delim {
		n, err := rd.rd.Read(rd.hdr[0: 1])
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		if rd.hdr[0] == 0xFF {
			return rd.readErr(MaxErrLen)
		}
		if rd.hdr[0] != 0 {
			return 0, ErrBadFormat
		}
		return rd.rd.Read(data)
	}
	n, err := io.ReadFull(rd.rd, rd.hdr[0: HdrLen])
	if err != nil {
		return 0, err
	}
	if n < HdrLen || rd.hdr[HdrLen-1] != '\n' {
		return 0, ErrBadFormat
	}
	isErr := false
	i := 0
	if rd.hdr[0] == '!' {
		isErr = true
		i = 1
	}
	// ParseInt is overkill
	n = 0
	for ; i < 4; i++ {
		c := rd.hdr[i]
		if !(c >= '0' && c <= '9') {
			return 0, ErrBadFormat
		}
		n = n*10 + (int(c)-'0')
	}
	if n > MaxMsgLen {
		return 0, ErrTooLong
	}
	if isErr {
		return rd.readErr(n)
	}
	return io.ReadFull(rd.rd, data[0: n])
}

// Read implements the Reader interface, returning
// the number of bytes read into the given data buffer,
// and any error.
func (rd *Reader) Read(data []byte) (int, error) {
	return rd.readMsg(data)
}

// ReadString reads and returns data to be interpreted as a UTF-8 string.
func (rd *Reader) ReadString() (string, error) {
	n, err := rd.readMsg(rd.ib[0:])
	if err != nil {
		return "", err
	}
	return string(rd.ib[0: n]), nil
}
