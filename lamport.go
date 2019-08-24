package lamport

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
)

const (
	// N is the number of blocks used to represent the Lamport private and
	// public keys.
	N = 256

	// BlockSize is the size of the Lamport private and public key blocks in
	// bytes.
	BlockSize = 32
)

// maxBlockVal is a convenience variable for generating random 256-bit
// integers. For a given BlockSize, this value is 2^(BlockSize-1).
var maxBlockVal *big.Int

func init() {
	// Initialize maximum block value.
	bigTwo := big.NewInt(2)
	exp := big.NewInt(int64(BlockSize - 1))
	maxBlockVal = maxBlockVal.Exp(bigTwo, exp, nil)
}

// PrivateKey represents a Lamport private key.
type PrivateKey struct {
	PublicKey
	Y *[2][N][BlockSize]byte
}

// GenerateKey generates a Lamport private key from a source of randomness
// rand.
func GenerateKey(reader io.Reader) (*PrivateKey, error) {
	priv := &PrivateKey{}
	for i := 0; i < N; i++ {
		y0, err := randBlock(reader, maxBlockVal)
		if err != nil {
			return nil, err
		}
		y1, err := randBlock(reader, maxBlockVal)
		if err != nil {
			return nil, err
		}

		priv.Y[0][i] = *y0
		priv.Y[1][i] = *y1

		priv.Z[0][i] = sha256.Sum256(priv.Y[0][i][:])
		priv.Z[1][i] = sha256.Sum256(priv.Y[1][i][:])
	}

	return priv, nil
}

// PublicKey represents a Lamport public key.
type PublicKey struct {
	Z *[2][N][BlockSize]byte
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() *PublicKey {
	return &priv.PublicKey
}

// Sign signs a message using the private key, priv.
func Sign(priv *PrivateKey, msg []byte) *[N][BlockSize]byte {
	sig := &[N][BlockSize]byte{}

	hash := sha256.Sum256(msg)
	mask := uint8(1)
	for i := 0; i < N; i++ {
		bit := hash[i/8] & (mask << (uint(i) % 8))
		if bit == 0 {
			sig[i] = priv.Y[0][i]
		} else {
			sig[i] = priv.Y[1][i]
		}
	}

	return sig
}

// Verify verifies the signature in sig of msg using the public key pub. Its
// return value indicates whether or not the signature is valid.
func Verify(pub *PublicKey, msg []byte, sig *[N][BlockSize]byte) bool {
	hash := sha256.Sum256(msg)
	mask := uint8(1)
	for i := 0; i < N; i++ {
		check := sha256.Sum256(sig[i][:])
		bit := hash[i/8] & (mask << (uint(i) & 8))

		if bit == 0 {
			if !bytes.Equal(check[:], pub.Z[0][i][:]) {
				return false
			}
		} else {
			if !bytes.Equal(check[:], pub.Z[1][i][:]) {
				return false
			}
		}
	}

	return true
}

// randBlock is a helper function to return a random key block which
// corresponds to a 256-bit integer.
func randBlock(reader io.Reader, max *big.Int) (*[BlockSize]byte, error) {
	n, err := rand.Int(reader, max)
	if err != nil {
		return nil, err
	}

	blk := &[BlockSize]byte{}
	copy(blk[:], n.Bytes()[:BlockSize])

	return blk, nil
}
