package xxtea_test

import (
	"encoding/binary"
	"errors"
	"flag"
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/twpayne/go-xxtea"
)

var (
	seed1  = flag.Uint64("seed1", 1, "seed1")
	seed2  = flag.Uint64("seed2", 2, "seed2")
	ntests = flag.Int("ntests", 1024, "number of random tests to run")
)

func TestEncryptDecrypt(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewPCG(*seed1, *seed2)) //nolint:gosec
	for i := range *ntests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			c := xxtea.NewCipher(
				xxtea.WithByteOrder(randomByteOrder(r)),
				xxtea.WithKey(randomKey(r)),
				xxtea.WithRounds(r.IntN(16)),
			)
			plaintext := randomBytes(r, 8+4*r.IntN(16))
			ciphertext, err := c.Encrypt(plaintext)
			assert.NoError(t, err)
			decryptedPlaintext, err := c.Decrypt(ciphertext)
			assert.NoError(t, err)
			assert.Equal(t, plaintext, decryptedPlaintext)
		})
	}
}

func TestEncryptDecryptInPlace(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewPCG(*seed1, *seed2)) //nolint:gosec
	for i := range *ntests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			c := xxtea.NewCipher(
				xxtea.WithByteOrder(randomByteOrder(r)),
				xxtea.WithKey(randomKey(r)),
				xxtea.WithRounds(r.IntN(16)),
			)
			plaintext := randomUint32s(r, 2+r.IntN(16))
			ciphertext := slices.Clone(plaintext)
			assert.NoError(t, c.EncryptInPlace(ciphertext))
			decryptedCiphertext := slices.Clone(ciphertext)
			assert.NoError(t, c.DecryptInPlace(decryptedCiphertext))
			assert.Equal(t, plaintext, decryptedCiphertext)
		})
	}
}

func TestUnsupported(t *testing.T) {
	var c xxtea.Cipher

	for _, data := range [][]byte{
		nil,
		{},
		{0},
		{0, 1, 2, 3, 4, 5, 6},
	} {
		_, decryptErr := c.Decrypt(data)
		assert.Equal(t, errors.ErrUnsupported, decryptErr)
		_, encryptErr := c.Encrypt(data)
		assert.Equal(t, errors.ErrUnsupported, encryptErr)
	}

	assert.Equal(t, errors.ErrUnsupported, c.DecryptInPlace(nil))
	assert.Equal(t, errors.ErrUnsupported, c.DecryptInPlace([]uint32{}))
	assert.Equal(t, errors.ErrUnsupported, c.DecryptInPlace([]uint32{0}))

	assert.Equal(t, errors.ErrUnsupported, c.EncryptInPlace(nil))
	assert.Equal(t, errors.ErrUnsupported, c.EncryptInPlace([]uint32{}))
	assert.Equal(t, errors.ErrUnsupported, c.EncryptInPlace([]uint32{0}))
}

func TestBytesToUint32s(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewPCG(*seed1, *seed2)) //nolint:gosec
	for i := range *ntests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			uint32s := randomUint32s(r, r.IntN(16))
			byteOrder := randomByteOrder(r)
			actualUint32s, err := xxtea.BytesToUint32s(xxtea.Uint32sToBytes(uint32s, byteOrder), byteOrder)
			assert.NoError(t, err)
			assert.Equal(t, uint32s, actualUint32s)
		})
	}
}

func TestBytesToUint32sEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		actual, err := xxtea.BytesToUint32s(nil, binary.LittleEndian)
		assert.NoError(t, err)
		assert.Zero(t, actual)
	})

	t.Run("empty", func(t *testing.T) {
		actual, err := xxtea.BytesToUint32s([]byte{}, binary.LittleEndian)
		assert.NoError(t, err)
		assert.Equal(t, []uint32{}, actual)
	})

	t.Run("unsupported", func(t *testing.T) {
		actual, err := xxtea.BytesToUint32s([]byte{0}, binary.LittleEndian)
		assert.Equal(t, errors.ErrUnsupported, err)
		assert.Zero(t, actual)
	})
}

func TestUint32sToBytesEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		assert.Zero(t, xxtea.Uint32sToBytes(nil, binary.LittleEndian))
	})

	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, []byte{}, xxtea.Uint32sToBytes([]uint32{}, binary.LittleEndian))
	})
}

func TestDefaultRounds(t *testing.T) {
	t.Parallel()
	for n, expected := range map[int]int{
		0:  6,
		4:  19,
		8:  12,
		12: 10,
		16: 9,
		20: 8,
		24: 8,
		28: 7,
		52: 7,
		56: 6,
	} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			assert.Equal(t, expected, xxtea.DefaultRoundsFunc(n))
		})
	}
}

func randomByteOrder(r *rand.Rand) binary.ByteOrder {
	if r.IntN(2) == 0 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

func randomBytes(r *rand.Rand, n int) []byte {
	bytes := make([]byte, n)
	for i := range bytes {
		bytes[i] = byte(r.UintN(256))
	}
	return bytes
}

func randomKey(r *rand.Rand) xxtea.Key {
	return xxtea.Key{r.Uint32(), r.Uint32(), r.Uint32(), r.Uint32()}
}

func randomUint32s(r *rand.Rand, n int) []uint32 {
	uint32s := make([]uint32, n)
	for i := range uint32s {
		uint32s[i] = r.Uint32()
	}
	return uint32s
}
