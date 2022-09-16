package secstore

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"

	"github.com/forsyth/auth/internal/cbc"
	"github.com/forsyth/auth/internal/sio"
)

const checkPat = "XXXXXXXXXXXXXXXX" //  it's what Plan 9's aescbc uses
const checkLen = len(checkPat)

var (
	ErrFileTooSmall = errors.New("encrypted file size too small")
	ErrDecrypt      = errors.New("file did not decrypt correctly") // should only be wrong key
)

// EraseKey zeroes the bytes of a key, removing it from casual memory viewing.
func EraseKey(key []byte) {
	sio.EraseKey(key)
}

// FileKey converts a secret s into a secstore file key, hiding the text of the key.
func FileKey(key []byte) []byte {
	sha := sha1.New()
	sha.Write([]byte("aescbc file"))
	sha.Write(key)
	skey := sha.Sum(nil)
	sio.EraseKey(skey[aes.BlockSize:])
	return skey[0:aes.BlockSize:aes.BlockSize]
}

// EncryptionKeys converts a session key to a pair of encryption keys, one for each direction.
func EncryptionKeys(sigma []byte, direction int) [2][]byte {
	var secretin, secretout []byte
	if direction != 0 {
		secretout = sio.HMAC(sha1.New, sigma, []byte("one"))
		secretin = sio.HMAC(sha1.New, sigma, []byte("two"))
	} else {
		secretout = sio.HMAC(sha1.New, sigma, []byte("two"))
		secretin = sio.HMAC(sha1.New, sigma, []byte("one"))
	}
	return [2][]byte{secretin, secretout}
}

// KeyHash return the SHA1 hash of a password.
func KeyHash(key []byte) []byte {
	state := sha1.New()
	state.Write(key)
	return state.Sum(nil)
}

// Decrypt decrypts the bytes read from a file, using the given key (the result of FileKey), returning the decoded bytes or an error.
func Decrypt(file []byte, key []byte) ([]byte, error) {
	length := len(file)
	if length == 0 {
		return file, nil
	}
	if length < aes.BlockSize+checkLen && false {
		return nil, ErrFileTooSmall
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to set up AES: %w", err)
	}
	cb := cbc.NewCBCDecrypter(block, file[0:aes.BlockSize])
	cb.CryptBlocks(file[aes.BlockSize:], file[aes.BlockSize:])
	if string(file[length-checkLen:]) != checkPat {
		return nil, ErrDecrypt
	}
	return file[aes.BlockSize : length-checkLen], nil
}

// Encrypt encrypts the bytes to be written to a file, using the given key (the result of FileKey), returning the encoded bytes or an error.
func Encrypt(file []byte, key []byte) ([]byte, error) {
	const ivSize = aes.BlockSize
	dat := make([]byte, ivSize+len(file)+checkLen)
	iv := dat[0:ivSize]
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("read of random: %w", err)
	}
	copy(dat[ivSize:], file)
	copy(dat[ivSize+len(file):], checkPat)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to set up AES: %w", err)
	}
	cb := cbc.NewCBCEncrypter(block, iv)
	cb.CryptBlocks(dat[ivSize:], dat[ivSize:])
	return dat, nil
}
