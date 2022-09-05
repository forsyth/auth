package secstore

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"

	"github.com/forsyth/auth/internal/cbc"
)

const Checkpat = "XXXXXXXXXXXXXXXX" //  it's what Plan 9's aescbc uses
const Checklen = len(Checkpat)

var (
	ErrFileTooSmall = errors.New("encrypted file size too small")
	ErrDecrypt      = errors.New("file did not decrypt correctly") // should only be wrong key
)

// FileKey converts a secret s into a secstore file key, hiding the text of the key.
func FileKey(s string) []byte {
	key := []byte(s)
	sha := sha1.New()
	sha.Write([]byte("aescbc file"))
	sha.Write(key)
	skey := sha.Sum(nil)
	erasekey(key)
	erasekey(skey[aes.BlockSize:])
	return skey[0:aes.BlockSize:aes.BlockSize]
}

// Decrypt decrypts the bytes read from a file, using the given key, returning the decoded bytes or an error.
func Decrypt(file []byte, key []byte) ([]byte, error) {
	length := len(file)
	if length == 0 {
		return file, nil
	}
	if length < aes.BlockSize+Checklen && false {
		return nil, ErrFileTooSmall
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to set up AES: %w", err)
	}
	cb := cbc.NewCBCDecrypter(block, file[0:aes.BlockSize])
	cb.CryptBlocks(file[aes.BlockSize:], file[aes.BlockSize:])
	if string(file[length-Checklen:]) != Checkpat {
		return nil, ErrDecrypt
	}
	return file[aes.BlockSize : length-Checklen], nil
}

// Encrypt encrypts the bytes to be written to a file, using the given key, returning the encoded bytes or an error.
func Encrypt(file []byte, key []byte) ([]byte, error) {
	const ivSize = aes.BlockSize
	dat := make([]byte, ivSize+len(file)+Checklen)
	iv := dat[0:ivSize]
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("read of random: %w", err)
	}
	copy(dat[ivSize:], file)
	copy(dat[ivSize+len(file):], Checkpat)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to set up AES: %w", err)
	}
	cb := cbc.NewCBCEncrypter(block, iv)
	cb.CryptBlocks(dat[ivSize:], dat[ivSize:])
	return dat, nil
}
