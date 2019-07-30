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
}

func TestCtypes(t *testing.T) {
	arr, err := randBytes(1000)
	require.NoError(t, err)
	ua := newUnsignedArr(arr)
	defer ua.Free()
	bytes := ua.Bytes()
	require.Equal(t, bytes, arr)
}

func TestGetIV(t *testing.T) {
	invalidIV, err := randBytes(10000)
	require.NoError(t, err)
	_, err = getIV(invalidIV)
	require.Error(t, err)

	arr, err := randBytes(ivLength)
	require.NoError(t, err)
	iv, err := getIV(arr)
	require.NoError(t, err)
	require.Equal(t, iv, arr)

	randIv, err := getIV(make([]byte, 0))
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

	cipher, err := HybridSeal(raw25519PubKey, raw256PubKey, data)
	require.NoError(t, err)
	actual, err := HybridUnseal(raw25519Key, raw256Key, cipher)
	require.NoError(t, err)
	require.Equal(t, data, actual)
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

	cipher, err := HybridBoxEncrypt(raw25519Key, raw25519PubKey, raw256Key, raw256PubKey, data)
	require.NoError(t, err)

	actual, err := HybridBoxDecrypt(raw25519Key, raw25519PubKey, raw256Key, raw256PubKey, cipher)
	require.NoError(t, err)
	require.Equal(t, data, actual)
}
