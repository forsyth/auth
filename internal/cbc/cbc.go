// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Cipher block chaining (CBC) mode.

// This is a version of crypto/cipher/cbc.go hacked to support Plan 9's version of CBC for AES,
// which handled final blocks not a multiple of the block size, not using the padding scheme of PKCS#7.
// Don't use this outside secstore and the aescbc command. It would be better to

package cbc

import "crypto/cipher"

type Block = cipher.Block
type BlockMode = cipher.BlockMode

type cbc struct {
	b         Block
	blockSize int
	iv        []byte
	tmp       []byte
}

func newCBC(b Block, iv []byte) *cbc {
	return &cbc{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        dup(iv),
		tmp:       make([]byte, b.BlockSize()),
	}
}

type cbcEncrypter cbc

// NewCBCEncrypter returns a BlockMode which encrypts in cipher block chaining
// mode, using the given Block. The length of iv must be the same as the
// Block's block size.
func NewCBCEncrypter(b Block, iv []byte) BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cipher.NewCBCEncrypter: IV length must equal block size")
	}
	return (*cbcEncrypter)(newCBC(b, iv))
}

func (x *cbcEncrypter) BlockSize() int { return x.blockSize }

func (x *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	//	if subtle.InexactOverlap(dst[:len(src)], src) {
	//		panic("crypto/cipher: invalid buffer overlap")
	//	}

	iv := x.iv

	for len(src) >= x.blockSize {
		// Write the xor to dst, then encrypt in place.
		xorBytes(dst[:x.blockSize], src[:x.blockSize], iv)
		x.b.Encrypt(dst[:x.blockSize], dst[:x.blockSize])

		// Move to the next block with this block as the next iv.
		iv = dst[:x.blockSize]
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}

	if len(src) > 0 {
		// technique used by old aescbc to handle non-blocksize chunk, following descbc of the time
		n := len(src)
		copy(x.iv, iv)
		x.b.Encrypt(x.tmp, x.iv)
		xorBytes(dst[:n], dst[:n], x.tmp)
		iv = x.tmp
	}

	// Save the iv for the next CryptBlocks call.
	copy(x.iv, iv)
}

type cbcDecrypter cbc

// NewCBCDecrypter returns a BlockMode which decrypts in cipher block chaining
// mode, using the given Block. The length of iv must be the same as the
// Block's block size and must match the iv used to encrypt the data.
func NewCBCDecrypter(b Block, iv []byte) BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cipher.NewCBCDecrypter: IV length must equal block size")
	}
	return (*cbcDecrypter)(newCBC(b, iv))
}

func (x *cbcDecrypter) BlockSize() int { return x.blockSize }

func (x *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	//	if subtle.InexactOverlap(dst[:len(src)], src) {
	//		panic("crypto/cipher: invalid buffer overlap")
	//	}
	if len(src) == 0 {
		return
	}

	iv := x.iv

	for len(src) >= x.blockSize {

		copy(x.tmp, dst[:x.blockSize])

		// Decrypt in place then xor
		x.b.Decrypt(dst[:x.blockSize], src[:x.blockSize])
		xorBytes(dst[:x.blockSize], dst[:x.blockSize], x.iv)

		// Move to the next block with this block as the next iv.
		copy(iv, x.tmp)
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}

	if len(src) > 0 {
		// technique used by old aescbc to handle non-blocksize chunk, following descbc of the time
		n := len(src)
		copy(x.iv, iv)
		x.b.Encrypt(x.tmp, x.iv)
		xorBytes(dst[:n], dst[:n], x.tmp)
		iv = x.tmp
	}

	// Save the iv for the next CryptBlocks call.
	copy(x.iv, iv)
}

func dup(p []byte) []byte {
	q := make([]byte, len(p))
	copy(q, p)
	return q
}
