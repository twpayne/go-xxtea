// Package xxtea implements the XXTEA block cipher.
//
// See https://en.wikipedia.org/wiki/XXTEA.
package xxtea

import (
	"encoding/binary"
	"errors"
)

const delta = 0x9e3779b9

// A Key is an XXTEA key.
type Key [4]uint32

// A RoundsFunc is a function that returns the number of rounds for a given
// number of input bytes.
type RoundsFunc func(int) int

// A Cipher is an XXTEA block cipher.
type Cipher struct {
	byteOrder  binary.ByteOrder
	key        Key
	roundsFunc RoundsFunc
}

// A CipherOption sets an option on a Cipher.
type CipherOption func(*Cipher)

// WithByteOrder sets the byte order.
func WithByteOrder(byteOrder binary.ByteOrder) CipherOption {
	return func(c *Cipher) {
		c.byteOrder = byteOrder
	}
}

// WithKey sets the key.
func WithKey(key Key) CipherOption {
	return func(c *Cipher) {
		c.key = key
	}
}

// WithRounds sets the number of rounds.
func WithRounds(rounds int) CipherOption {
	return func(c *Cipher) {
		c.roundsFunc = func(int) int {
			return rounds
		}
	}
}

// WithRoundsFunc sets the number of rounds as a function of the number of
// uint32s.
func WithRoundsFunc(roundsFunc RoundsFunc) CipherOption {
	return func(c *Cipher) {
		c.roundsFunc = roundsFunc
	}
}

func NewCipher(options ...CipherOption) *Cipher {
	c := &Cipher{
		byteOrder:  binary.LittleEndian,
		roundsFunc: DefaultRoundsFunc,
	}
	for _, option := range options {
		option(c)
	}
	return c
}

// Decrypt returns the decrypted bytes of ciphertext.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if err := checkLength(ciphertext); err != nil {
		return nil, err
	}
	uint32s, err := BytesToUint32s(ciphertext, c.byteOrder)
	if err != nil {
		return nil, err
	}
	if err := c.DecryptInPlace(uint32s); err != nil {
		return nil, err
	}
	return Uint32sToBytes(uint32s, c.byteOrder), nil
}

// DecryptInPlace decrypts v in place.
func (c *Cipher) DecryptInPlace(v []uint32) error {
	if len(v) < 2 {
		return errors.ErrUnsupported
	}
	rounds := c.roundsFunc(len(v))
	n := len(v)
	sum := uint32(rounds * delta)
	y := v[0]
	var z uint32
	for i := 0; i < rounds; i++ {
		e := int((sum >> 2) & 3)
		for p := n - 1; p > 0; p-- {
			z = v[p-1]
			v[p] -= c.mx(sum, y, z, p, e)
			y = v[p]
		}
		z = v[n-1]
		v[0] -= c.mx(sum, y, z, 0, e)
		y = v[0]
		sum -= delta
	}
	return nil
}

// Encrypt returns the encrypted bytes of plaintext.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if err := checkLength(plaintext); err != nil {
		return nil, err
	}
	uint32s, err := BytesToUint32s(plaintext, c.byteOrder)
	if err != nil {
		return nil, err
	}
	if err := c.EncryptInPlace(uint32s); err != nil {
		return nil, err
	}
	return Uint32sToBytes(uint32s, c.byteOrder), nil
}

// EncryptInPlace encrypts v in place.
func (c *Cipher) EncryptInPlace(v []uint32) error {
	if len(v) < 2 {
		return errors.ErrUnsupported
	}
	n := len(v)
	rounds := c.roundsFunc(n)
	sum := uint32(0)
	var y uint32
	z := v[n-1]
	for i := 0; i < rounds; i++ {
		sum += delta
		e := int((sum >> 2) & 3)
		for p := 0; p < n-1; p++ {
			y = v[p+1]
			v[p] += c.mx(sum, y, z, p, e)
			z = v[p]
		}
		y = v[0]
		v[n-1] += c.mx(sum, y, z, n-1, e)
		z = v[n-1]
	}
	return nil
}

func (c *Cipher) mx(sum, y, z uint32, p, e int) uint32 {
	return ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (c.key[p&3^e] ^ z))
}

// DefaultRoundsFunc returns the default number of rounds for encrypting n
// bytes.
func DefaultRoundsFunc(n int) int {
	if n == 0 {
		return 6
	}
	return 6 + 52/n
}

// BytesToUint32s returns a []uint32 containing bytes. It returns an error if
// the length of bytes is not a multiple of four.
func BytesToUint32s(bytes []byte, byteOrder binary.ByteOrder) ([]uint32, error) {
	switch {
	case bytes == nil:
		return nil, nil
	case len(bytes) == 0:
		return []uint32{}, nil
	case len(bytes)%4 != 0:
		return nil, errors.ErrUnsupported
	}
	uint32s := make([]uint32, len(bytes)/4)
	for i := range uint32s {
		uint32s[i] = byteOrder.Uint32(bytes[4*i : 4*i+4])
	}
	return uint32s, nil
}

// Uint32sToBytes returns the bytes in a []uint32.
func Uint32sToBytes(uint32s []uint32, byteOrder binary.ByteOrder) []byte {
	switch {
	case uint32s == nil:
		return nil
	case len(uint32s) == 0:
		return []byte{}
	}
	bytes := make([]byte, 4*len(uint32s))
	for i, value := range uint32s {
		byteOrder.PutUint32(bytes[4*i:4*i+4], value)
	}
	return bytes
}

func checkLength(data []byte) error {
	if len(data) < 8 || len(data)%4 != 0 {
		return errors.ErrUnsupported
	}
	return nil
}
