package fips

// #include <stdio.h>
// #include <stdlib.h>
//#include "fips-crypto/fips-crypto.h"
//#cgo LDFLAGS: -lfips-crypto
import "C"

import (
	"crypto/rand"
	"fmt"
	"unsafe"
)

const (
	aesKeyLength = C.AES_KEY_LENGTH
	aesBlockSize = 16
	ivLength     = C.AES_IV_LENGTH
	aesTagLength = C.AES_TAG_LEN

	ecPrivateKeyLength     = C.EC_PRIVATE_KEY_LENGTH
	curve25519PubKeyLength = C.CURVE25519_PUB_KEY_LENGTH
	nistP256PubKeyLength   = C.P256_PUB_KEY_LENGTH

	rawEDSASignatureLength = 64
	ed25519SignatureLength = 64
	hybridSignatureLength  = rawEDSASignatureLength + ed25519SignatureLength
)

// Must call Free()
func newUnsignedArr(arr []byte) UnsignedArr {
	return UnsignedArr{
		p:    C.CBytes(arr),
		size: len(arr),
	}
}

type UnsignedArr struct {
	p    unsafe.Pointer
	size int
}

func (ua UnsignedArr) Free() {
	C.free(ua.p)
}

func (ua UnsignedArr) Uchar() *C.uchar {
	return (*C.uchar)(ua.p)
}

func (ua UnsignedArr) Bytes() []byte {
	return C.GoBytes(ua.p, C.int(ua.size))
}

func randBytes(numBytes int) ([]byte, error) {
	buf := make([]byte, numBytes)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func getIV(inputIv []byte) ([]byte, error) {
	if len(inputIv) == 0 {
		iv, err := randBytes(ivLength)
		if err != nil {
			return nil, err
		}
		return iv, nil
	}

	if len(inputIv) != ivLength {
		return nil, fmt.Errorf("invalid iv length")
	}

	iv := make([]byte, ivLength)
	copy(iv, inputIv)
	return iv, nil
}

// Takes in AES_KEY_LENGTH size key,
// returns (ciphertet, tag, iv)
func AesEncrypt(key []byte, plaintext []byte, inputIv []byte) ([]byte, []byte, []byte, error) {
	keyPtr := newUnsignedArr(key)
	defer keyPtr.Free()
	plaintextPtr := newUnsignedArr(plaintext)
	defer plaintextPtr.Free()

	// if 0 byte iv is given, generate a random iv
	iv, err := getIV(inputIv)
	if err != nil {
		return nil, nil, nil, err
	}

	ivPtr := newUnsignedArr(iv)
	defer ivPtr.Free()

	var outLen C.int
	outBufPtr := newUnsignedArr(make([]byte, len(plaintext)+aesBlockSize))
	defer outBufPtr.Free()

	ref := C.aes_encrypt_init(keyPtr.Uchar(), ivPtr.Uchar())
	if status := C.aes_encrypt_update(
		ref,
		outBufPtr.Uchar(),
		&outLen,
		plaintextPtr.Uchar(),
		C.int(len(plaintext)),
	); status != 1 {
		return nil, nil, nil, fmt.Errorf("AesEncrypt: C.aes_encrypt_update() status %v, error: %v", status, C.GoString(C.fips_crypto_last_error()))
	}

	var padLen C.int
	padBufPtr := newUnsignedArr(make([]byte, aesBlockSize))
	defer padBufPtr.Free()

	tagPtr := newUnsignedArr(make([]byte, aesTagLength))
	defer tagPtr.Free()

	if status := C.aes_encrypt_finalize(
		ref,
		padBufPtr.Uchar(),
		&padLen,
		tagPtr.Uchar(),
	); status != 1 {
		return nil, nil, nil, fmt.Errorf("AesEncrypt: C.aes_encrypt_finalize() status %v, error: %v", status, C.GoString(C.fips_crypto_last_error()))
	}

	// now need to append outBuf[:outLen] + padBuf[:padLen]
	ciphertext := append(outBufPtr.Bytes()[:outLen], padBufPtr.Bytes()[:padLen]...)
	return ciphertext, tagPtr.Bytes(), iv, nil
}

func AesDecrypt(key []byte, ciphertext []byte, tag []byte, iv []byte) ([]byte, error) {
	keyPtr := newUnsignedArr(key)
	defer keyPtr.Free()

	cipherTextPtr := newUnsignedArr(ciphertext)
	defer cipherTextPtr.Free()

	ivPtr := newUnsignedArr(iv)
	defer ivPtr.Free()

	var outLen C.int
	outPtr := newUnsignedArr(make([]byte, len(ciphertext)+aesBlockSize))
	defer outPtr.Free()

	ref := C.aes_decrypt_init(keyPtr.Uchar(), ivPtr.Uchar())
	if status := C.aes_decrypt_update(
		ref,
		outPtr.Uchar(),
		&outLen,
		cipherTextPtr.Uchar(),
		C.int(len(ciphertext)),
	); status != 1 {
		return nil, fmt.Errorf("AesDecrypt: C.aes_decrypt_update() status %v, error: %v", status, C.GoString(C.fips_crypto_last_error()))
	}

	tagPtr := newUnsignedArr(tag)
	defer tagPtr.Free()
	if status := C.aes_decrypt_finalize(
		ref,
		tagPtr.Uchar(),
	); status != 1 {
		return nil, fmt.Errorf("AesDecrypt: C.aes_decrypt_finalize() status %v, error: %v", status, C.GoString(C.fips_crypto_last_error()))
	}
	return outPtr.Bytes()[:outLen], nil
}

type keyType int32

func (kt keyType) CType() C.EC_KEY_TYPE {
	switch kt {
	case Curve25519:
		return C.CURVE_25519
	case NistP256:
		return C.NIST_P256
	default:
		return 0
	}
}

func (kt keyType) keyLen() int {
	switch kt {
	case Curve25519:
		return curve25519PubKeyLength
	case NistP256:
		return nistP256PubKeyLength
	default:
		return 0
	}
}

const (
	Curve25519 keyType = 0
	NistP256   keyType = 1
)

func (ku keyUsage) CType() C.EC_KEY_USAGE {
	switch ku {
	case SignatureUsage:
		return C.SIGNATURE_USAGE
	case EncryptionUsage:
		return C.ENCRYPTION_USAGE
	default:
		return 0
	}

}

type keyUsage int32

const (
	SignatureUsage  keyUsage = 0
	EncryptionUsage keyUsage = 1
)

// key, public
func GenerateEcKey(ktype keyType, usage keyUsage) ([]byte, []byte, error) {
	keyPtr := newUnsignedArr(make([]byte, ecPrivateKeyLength))
	defer keyPtr.Free()

	ctype := ktype.CType()
	cusage := usage.CType()

	ref := C.generate_ec_key(ctype, cusage)
	defer C.ec_key_free(ref)

	if status := C.ec_key_to_binary(
		ref,
		ctype,
		keyPtr.Uchar(),
		C.size_t(ecPrivateKeyLength),
		C.bool(true),
	); status != 1 {
		return nil, nil, fmt.Errorf("GenerateEcKey: C.ec_key_to_binary() status %v, error: %v", status, C.GoString(C.fips_crypto_last_error()))
	}

	pubLen := ktype.keyLen()
	pubPtr := newUnsignedArr(make([]byte, pubLen))
	defer pubPtr.Free()
	if status := C.ec_key_to_binary(
		ref,
		ctype,
		pubPtr.Uchar(),
		C.size_t(pubLen),
		C.bool(false),
	); status != 1 {
		return nil, nil, fmt.Errorf("GenerateEcKey: C.ec_key_to_binary() status %v, error: %v", status, C.GoString(C.fips_crypto_last_error()))
	}
	return keyPtr.Bytes(), pubPtr.Bytes(), nil
}

// takes in ec key, returns `public key []byte`
func EcKeyToPublic(key []byte, ktype keyType, usage keyUsage) ([]byte, error) {
	keyPtr := newUnsignedArr(key)
	defer keyPtr.Free()

	ref := C.ec_key_from_binary(
		keyPtr.Uchar(),
		C.size_t(len(key)), // TODO? ecPrivateKeyLength,
		ktype.CType(),
		usage.CType(),
		C.bool(true),
	)
	defer C.ec_key_free(ref)

	pubLen := ktype.keyLen()
	pubPtr := newUnsignedArr(make([]byte, pubLen))
	defer pubPtr.Free()

	if status := C.ec_key_to_binary(
		ref,
		ktype.CType(),
		pubPtr.Uchar(),
		C.size_t(pubLen),
		C.bool(false),
	); status != 1 {
		return nil, fmt.Errorf("EcKeyToPublic: C.ec_key_to_binary() status %v, error: %v", status, C.GoString(C.fips_crypto_last_error()))
	}
	return pubPtr.Bytes(), nil
}

// takes in 2 keys, double seals and returns ciphertext
func HybridSeal(curve25519Pub []byte, nistp256Pub []byte, plaintext []byte) ([]byte, error) {
	curve25519PubPtr := newUnsignedArr(curve25519Pub)
	defer curve25519PubPtr.Free()

	curve25519KeyRef := C.ec_key_from_binary(
		curve25519PubPtr.Uchar(),
		C.size_t(len(curve25519Pub)),
		C.CURVE_25519,
		C.ENCRYPTION_USAGE,
		C.bool(false),
	)
	defer C.ec_key_free(curve25519KeyRef)

	nistp256PubPtr := newUnsignedArr(nistp256Pub)
	defer nistp256PubPtr.Free()

	nistp256KeyRef := C.ec_key_from_binary(
		nistp256PubPtr.Uchar(),
		C.size_t(len(nistp256Pub)), // NISTP256_PUB_KEY_LENGTH,
		C.NIST_P256,
		C.ENCRYPTION_USAGE,
		C.bool(false),
	)
	defer C.ec_key_free(nistp256KeyRef)

	plaintextPtr := newUnsignedArr(plaintext)
	defer plaintextPtr.Free()

	var outLen C.int
	var cipherBuf *C.uchar
	if status := C.hybrid_encrypt(
		curve25519KeyRef,
		nistp256KeyRef,
		plaintextPtr.Uchar(),
		C.size_t(len(plaintext)),
		&cipherBuf,
		&outLen,
	); status != 1 {
		return nil, fmt.Errorf("HybridSeal: C.hybrid_encrypt() status %v, error: %v", status, C.GoString(C.fips_crypto_last_error()))
	}
	return C.GoBytes(unsafe.Pointer(cipherBuf), outLen), nil
}

func HybridUnseal(curve25519Key []byte, nistp256Key []byte, ciphertext []byte) ([]byte, error) {
	curve25519KeyPtr := newUnsignedArr(curve25519Key)
	defer curve25519KeyPtr.Free()
	curve25519KeyRef := C.ec_key_from_binary(
		curve25519KeyPtr.Uchar(),
		C.size_t(len(curve25519Key)),
		C.CURVE_25519,
		C.ENCRYPTION_USAGE,
		C.bool(true),
	)
	defer C.ec_key_free(curve25519KeyRef)

	nistp256KeyPtr := newUnsignedArr(nistp256Key)
	defer nistp256KeyPtr.Free()
	nistp256KeyRef := C.ec_key_from_binary(
		nistp256KeyPtr.Uchar(),
		C.size_t(len(nistp256Key)),
		C.NIST_P256,
		C.ENCRYPTION_USAGE,
		C.bool(true),
	)
	defer C.ec_key_free(nistp256KeyRef)

	ciphertextPtr := newUnsignedArr(ciphertext)
	defer ciphertextPtr.Free()

	var outLen C.int
	var outBuf *C.uchar
	status := C.hybrid_decrypt(
		curve25519KeyRef,
		nistp256KeyRef,
		ciphertextPtr.Uchar(),
		C.size_t(len(ciphertext)),
		&outBuf,
		&outLen,
	)
	if status != 1 {
		return nil, fmt.Errorf("HybridUnseal: C.hybrid_decrypt() status %v, error: %v", status, C.GoString(C.fips_crypto_last_error()))
	}
	return C.GoBytes(unsafe.Pointer(outBuf), outLen), nil
}

func HybridSign(curve25519_key, nistp256_key, message []byte) ([]byte, error) {
	curve25519KeyPtr := newUnsignedArr(curve25519_key)
	defer curve25519KeyPtr.Free()
	curve25519_key_ref := C.ec_key_from_binary(
		curve25519KeyPtr.Uchar(), ecPrivateKeyLength,
		C.CURVE_25519, C.SIGNATURE_USAGE,
		C.bool(true),
	)

	nistp256KeyPtr := newUnsignedArr(nistp256_key)
	defer nistp256KeyPtr.Free()
	nistp256_key_ref := C.ec_key_from_binary(
		nistp256KeyPtr.Uchar(), ecPrivateKeyLength,
		C.NIST_P256, C.SIGNATURE_USAGE,
		C.bool(true),
	)

	signaturePtr := newUnsignedArr(make([]byte, hybridSignatureLength))
	defer signaturePtr.Free()

	messagePtr := newUnsignedArr(message)
	defer messagePtr.Free()

	status := C.ec_sign(
		curve25519_key_ref,
		nistp256_key_ref,
		messagePtr.Uchar(),
		C.size_t(len(message)),
		signaturePtr.Uchar(),
	)
	if status != 1 {
		return nil, fmt.Errorf("HybridSign: C.ec_sign() status %v, error: %v", status, C.GoString(C.fips_crypto_last_error()))
	}
	return signaturePtr.Bytes(), nil
}

func HybridVerify(curve25519_pub, nistp256_pub, signature, message []byte) (bool, error) {
	curve25519_pubPtr := newUnsignedArr(curve25519_pub)
	defer curve25519_pubPtr.Free()

	curve25519_key_ref := C.ec_key_from_binary(
		curve25519_pubPtr.Uchar(),
		C.CURVE25519_PUB_KEY_LENGTH, C.CURVE_25519,
		C.SIGNATURE_USAGE, C.bool(false),
	)
	defer C.ec_key_free(curve25519_key_ref)
	nistp256_pubPtr := newUnsignedArr(nistp256_pub)
	defer nistp256_pubPtr.Free()
	nistp256_key_ref := C.ec_key_from_binary(
		nistp256_pubPtr.Uchar(), nistP256PubKeyLength,
		C.NIST_P256, C.SIGNATURE_USAGE,
		C.bool(false),
	)
	defer C.ec_key_free(nistp256_key_ref)

	signaturePtr := newUnsignedArr(signature)
	defer signaturePtr.Free()
	messagePtr := newUnsignedArr(message)
	defer messagePtr.Free()
	status := C.ec_verify(
		curve25519_key_ref,
		nistp256_key_ref,
		messagePtr.Uchar(), C.size_t(len(message)),
		signaturePtr.Uchar(),
	)
	if status != 1 {
		return false, fmt.Errorf("HybridVerify: C.ec_verify() status %v, error: %v", status, C.GoString(C.fips_crypto_last_error()))
	}
	return status == 1, nil
}

func HybridBoxEncrypt(curve25519Private, curve25519Public, nistP256Private, nistP256Public, plaintext []byte) ([]byte, error) {
	// get all references..
	curve25519PrivatePtr := newUnsignedArr(curve25519Private)
	defer curve25519PrivatePtr.Free()
	curve25519PrivateRef := C.ec_key_from_binary(
		curve25519PrivatePtr.Uchar(),
		C.size_t(ecPrivateKeyLength),
		Curve25519.CType(),
		EncryptionUsage.CType(),
		C.bool(true),
	)
	defer C.ec_key_free(curve25519PrivateRef)

	curve25519PublicPtr := newUnsignedArr(curve25519Public)
	defer curve25519PublicPtr.Free()
	curve25519PublicRef := C.ec_key_from_binary(
		curve25519PublicPtr.Uchar(),
		C.size_t(curve25519PubKeyLength),
		Curve25519.CType(),
		EncryptionUsage.CType(),
		C.bool(false),
	)
	defer C.ec_key_free(curve25519PublicRef)

	nistP256PrivatePtr := newUnsignedArr(nistP256Private)
	defer nistP256PrivatePtr.Free()
	nistP256PrivateRef := C.ec_key_from_binary(
		nistP256PrivatePtr.Uchar(),
		C.size_t(ecPrivateKeyLength),
		NistP256.CType(),
		EncryptionUsage.CType(),
		C.bool(true),
	)
	defer C.ec_key_free(nistP256PrivateRef)

	nistP256PublicPtr := newUnsignedArr(nistP256Public)
	defer nistP256PublicPtr.Free()
	nistP256PublicRef := C.ec_key_from_binary(
		nistP256PublicPtr.Uchar(),
		C.size_t(nistP256PubKeyLength),
		NistP256.CType(),
		EncryptionUsage.CType(),
		C.bool(false),
	)
	defer C.ec_key_free(nistP256PublicRef)

	plaintextPtr := newUnsignedArr(plaintext)
	defer plaintextPtr.Free()
	var outlen C.int
	var outbuf *C.uchar
	status := C.box_encrypt(
		curve25519PrivateRef,
		nistP256PrivateRef,
		curve25519PublicRef,
		nistP256PublicRef,
		plaintextPtr.Uchar(),
		C.int(len(plaintext)),
		&outbuf,
		&outlen,
	)
	if status != 1 {
		return nil, fmt.Errorf("HybridBoxEncrypt: C.box_encrypt() status %v, error: %v", status, C.GoString(C.fips_crypto_last_error()))
	}
	return C.GoBytes(unsafe.Pointer(outbuf), outlen), nil
}

func HybridBoxDecrypt(curve25519Private, curve25519Public, nistP256Private, nistP256Public, ciphertext []byte) ([]byte, error) {
	// get all references..
	curve25519PrivatePtr := newUnsignedArr(curve25519Private)
	defer curve25519PrivatePtr.Free()
	curve25519PrivateRef := C.ec_key_from_binary(
		curve25519PrivatePtr.Uchar(),
		C.size_t(ecPrivateKeyLength),
		Curve25519.CType(),
		EncryptionUsage.CType(),
		C.bool(true),
	)
	defer C.ec_key_free(curve25519PrivateRef)

	curve25519PublicPtr := newUnsignedArr(curve25519Public)
	defer curve25519PublicPtr.Free()
	curve25519PublicRef := C.ec_key_from_binary(
		curve25519PublicPtr.Uchar(),
		C.size_t(curve25519PubKeyLength),
		Curve25519.CType(),
		EncryptionUsage.CType(),
		C.bool(false),
	)
	defer C.ec_key_free(curve25519PublicRef)

	nistP256PrivatePtr := newUnsignedArr(nistP256Private)
	defer nistP256PrivatePtr.Free()
	nistP256PrivateRef := C.ec_key_from_binary(
		nistP256PrivatePtr.Uchar(),
		C.size_t(ecPrivateKeyLength),
		NistP256.CType(),
		EncryptionUsage.CType(),
		C.bool(true),
	)
	defer C.ec_key_free(nistP256PrivateRef)

	nistP256PublicPtr := newUnsignedArr(nistP256Public)
	defer nistP256PublicPtr.Free()
	nistP256PublicRef := C.ec_key_from_binary(
		nistP256PublicPtr.Uchar(),
		C.size_t(nistP256PubKeyLength),
		NistP256.CType(),
		EncryptionUsage.CType(),
		C.bool(false),
	)
	defer C.ec_key_free(nistP256PublicRef)

	// now do the decrypt
	ciphertextPtr := newUnsignedArr(ciphertext)
	defer ciphertextPtr.Free()
	var outlen C.int
	var outbuf *C.uchar
	status := C.box_decrypt(
		curve25519PublicRef,
		nistP256PublicRef,
		curve25519PrivateRef,
		nistP256PrivateRef,
		ciphertextPtr.Uchar(),
		C.size_t(len(ciphertext)),
		&outbuf,
		&outlen,
	)
	if status != 1 {
		return nil, fmt.Errorf("HybridBoxDecrypt: C.box_decrypt() status %v, error: %v", status, C.GoString(C.fips_crypto_last_error()))
	}
	return C.GoBytes(unsafe.Pointer(outbuf), outlen), nil
}
