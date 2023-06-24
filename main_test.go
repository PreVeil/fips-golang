package fips

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAesEncrypt(t *testing.T) {
	data, err := randBytes(15)
	require.NoError(t, err)

	// random iv
	key, err := randBytes(aesKeyLength)
	require.NoError(t, err)
	ciphertext, tag, iv, err := AesEncrypt(key, data, make([]byte, 0))
	require.NoError(t, err)

	actual, err := AesDecrypt(key, ciphertext, tag, iv)
	require.NoError(t, err)
	require.Equal(t, data, actual)

	// given input iv
	fixedIv, err := randBytes(ivLength)
	cipher, tag, iv, err := AesEncrypt(key, data, fixedIv)
	require.NoError(t, err)
	require.Equal(t, fixedIv, iv)

	decipher, err := AesDecrypt(key, cipher, tag, iv)
	require.NoError(t, err)
	require.Equal(t, data, decipher)

	// bad input iv
	invalidSizeFixedIv, err := randBytes(20)
	_, _, _, err = AesEncrypt(key, data, invalidSizeFixedIv)
	require.Error(t, err)

	// fixed iv
	// fixed ciphertext
	sameIV := []byte{180, 182, 193, 141, 134, 31, 133, 173, 88, 253, 131, 143}
	fixedCipher, tag, iv, err := AesEncrypt(key, data, sameIV)
	require.NoError(t, err)
	require.Equal(t, sameIV, iv)
	buf := make([]byte, 0, 1024)
	smallBuf := make([]byte, 0)
	for i := 0; i < 10; i++ {
		sameFixedCipher, tag, iv, err := AesEncrypt(key, data, sameIV)
		require.NoError(t, err)
		require.Equal(t, sameIV, iv)
		require.Equal(t, fixedCipher, sameFixedCipher)

		decipher, err = AesDecrypt(key, sameFixedCipher, tag, iv)
		require.NoError(t, err)
		require.Equal(t, data, decipher)

		err = AesDecryptWithBuffer(key, sameFixedCipher, tag, iv, &buf)
		require.NoError(t, err)
		require.Equal(t, data, buf)
		err = AesDecryptWithBuffer(key, sameFixedCipher, tag, iv, &smallBuf)
		require.Error(t, err)
	}
}

func TestCtypes(t *testing.T) {
	arr, err := randBytes(1000)
	require.NoError(t, err)
	ua := newUnsignedArr(arr)
	defer ua.Free()
	bytes := ua.Bytes()
	require.Equal(t, bytes, arr)
}

func TestInitAesEncrypt(t *testing.T) {
	key, err := randBytes(aesKeyLength)
	require.NoError(t, err)

	invalidIV, err := randBytes(10000)
	require.NoError(t, err)
	_, _, err = initAesEncrypt(key, invalidIV)
	require.Error(t, err)

	arr, err := randBytes(ivLength)
	require.NoError(t, err)
	_, iv, err := initAesEncrypt(key, arr)
	require.NoError(t, err)
	require.Equal(t, iv, arr)

	_, randIv, err := initAesEncrypt(key, make([]byte, 0))
	require.NoError(t, err)
	require.Equal(t, len(randIv), ivLength)
}

func TestEcKeys(t *testing.T) {
	kType := NistP256
	usage := EncryptionUsage
	key, pub, err := GenerateEcKey(kType, usage)

	actual, err := EcKeyToPublic(key, kType, usage)
	require.NoError(t, err)
	require.Equal(t, pub, actual)
}

func TestHybridEncrypt(t *testing.T) {
	raw25519Key, raw25519PubKey, err := GenerateEcKey(Curve25519, EncryptionUsage)
	require.NoError(t, err)
	require.NotNil(t, raw25519Key)
	raw256Key, raw256PubKey, err := GenerateEcKey(NistP256, EncryptionUsage)
	require.NoError(t, err)
	require.NotNil(t, raw256Key)

	data, err := randBytes(20)
	require.NoError(t, err)

	// sha256 key derivation function
	cipher, err := HybridSeal(raw25519PubKey, raw256PubKey, data, false)
	require.NoError(t, err)
	actual, err := HybridUnseal(raw25519Key, raw256Key, cipher, false)
	require.NoError(t, err)
	require.Equal(t, data, actual)

	// fips key derivation function
	fipsCipher, err := HybridSeal(raw25519PubKey, raw256PubKey, data, true)
	require.NoError(t, err)
	fipsActual, err := HybridUnseal(raw25519Key, raw256Key, fipsCipher, true)
	require.NoError(t, err)
	require.Equal(t, data, fipsActual)
}

func TestHybridSign(t *testing.T) {
	raw25519Key, raw25519PubKey, err := GenerateEcKey(Curve25519, SignatureUsage)
	require.NoError(t, err)

	raw256Key, raw256PubKey, err := GenerateEcKey(NistP256, SignatureUsage)
	require.NoError(t, err)

	data, err := randBytes(20)
	require.NoError(t, err)

	signature, err := HybridSign(raw25519Key, raw256Key, data)
	require.NoError(t, err)

	actual, err := HybridVerify(raw25519PubKey, raw256PubKey, signature, data)
	require.NoError(t, err)
	require.True(t, actual)
}

func TestHybridBoxEncrypt(t *testing.T) {
	raw25519Key, raw25519PubKey, err := GenerateEcKey(Curve25519, SignatureUsage)
	require.NoError(t, err)
	require.NotNil(t, raw25519Key)
	raw256Key, raw256PubKey, err := GenerateEcKey(NistP256, SignatureUsage)
	require.NoError(t, err)
	require.NotNil(t, raw256Key)

	data, err := randBytes(20)
	require.NoError(t, err)

	// sha256 key derivation function
	cipher, err := HybridBoxEncrypt(raw25519Key, raw25519PubKey, raw256Key, raw256PubKey, data, false)
	require.NoError(t, err)

	actual, err := HybridBoxDecrypt(raw25519Key, raw25519PubKey, raw256Key, raw256PubKey, cipher, false)
	require.NoError(t, err)
	require.Equal(t, data, actual)

	// fips key derivation function
	fipsCipher, err := HybridBoxEncrypt(raw25519Key, raw25519PubKey, raw256Key, raw256PubKey, data, true)
	require.NoError(t, err)

	fipsActual, err := HybridBoxDecrypt(raw25519Key, raw25519PubKey, raw256Key, raw256PubKey, fipsCipher, true)
	require.NoError(t, err)
	require.Equal(t, data, fipsActual)
}
