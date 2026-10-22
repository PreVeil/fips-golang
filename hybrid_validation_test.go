package fips

import (
	"crypto/elliptic"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHybridDeriveDecryptionKeyInvalidInputs(t *testing.T) {
	for _, fips := range []bool{false, true} {
		t.Run(fmt.Sprintf("fips=%v", fips), func(t *testing.T) {
			privX, pubX, err := GenerateEcKey(Curve25519, EncryptionUsage)
			require.NoError(t, err)
			privP, pubP, err := GenerateEcKey(NistP256, EncryptionUsage)
			require.NoError(t, err)
			ciphertext, err := HybridSeal(pubX, pubP, []byte("pointer"), fips)
			require.NoError(t, err)
			check := func(name string, x, p, ct []byte, message string) {
				t.Helper()
				t.Run(name, func(t *testing.T) {
					out, err := HybridDeriveDecryptionKey(x, p, ct, fips)
					require.Error(t, err)
					require.Nil(t, out)
					require.Contains(t, err.Error(), "HybridDeriveDecryptionKey")
					require.Contains(t, err.Error(), message)
				})
			}
			check("nil ciphertext", privX, privP, nil, "ciphertext too short")
			for _, n := range []int{0, 1, 31, 33, 64} {
				check(fmt.Sprintf("X25519 length %d", n), make([]byte, n), privP, ciphertext, "X25519 private key length")
				check(fmt.Sprintf("P256 length %d", n), privX, make([]byte, n), ciphertext, "P-256 private key length")
			}
			check("zero scalar", privX, make([]byte, 32), ciphertext, "scalar")
			check("scalar N", privX, elliptic.P256().Params().N.Bytes(), ciphertext, "scalar")
			maxScalar := make([]byte, 32)
			for i := range maxScalar {
				maxScalar[i] = 255
			}
			check("scalar above N", privX, maxScalar, ciphertext, "scalar")

			badPoint := append([]byte(nil), ciphertext...)
			badPoint[32] = 4 // Not a compressed point.
			check("bad point prefix", privX, privP, badPoint, "ephemeral P-256")
			for i := 33; i < 65; i++ {
				badPoint[i] = 255
			}
			badPoint[32] = 2
			check("point outside field", privX, privP, badPoint, "ephemeral P-256")

			// OpenSSL must reject low-order X25519 points during ECDH.
			for _, low := range []byte{0, 1} {
				badX := append([]byte(nil), ciphertext...)
				for i := 0; i < 32; i++ {
					badX[i] = 0
				}
				badX[0] = low
				check(fmt.Sprintf("low order X25519 %d", low), privX, privP, badX, "status")
			}

			// Derivation alone cannot authenticate the payload; unsealing must.
			tampered := append([]byte(nil), ciphertext...)
			tampered[len(tampered)-1] ^= 1
			key, err := HybridDeriveDecryptionKey(privX, privP, tampered, fips)
			require.NoError(t, err)
			require.Len(t, key, 32)
			out, err := HybridUnseal(privX, privP, tampered, fips)
			require.Error(t, err)
			require.Nil(t, out)
		})
	}
}
