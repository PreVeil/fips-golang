#ifndef fips_crypto_h
#define fips_crypto_h

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif
    
#include <stddef.h>
    
typedef void* AES_REF;
typedef unsigned char BYTE;

//! Length in bytes of symmetric keys
/*! Also available as an export constant: AesKeyLength. */
#define AES_KEY_LENGTH  32
//! Length in bytes of symmetric key initialization vectors
/*! Also available as an export constant: AesIvLength. */
#define AES_IV_LENGTH 12
//! Length in bytes of authentication tag used by AES-GCM
/*! Also available as an export constant: AesTagLen. */
#define AES_TAG_LEN 16
//! Length in bytes of an elliptic curve private key (Curve25519 or P256)
/*! Also available as an export constant: EcPrivateKeyLength. */
#define EC_PRIVATE_KEY_LENGTH 32
//! Length in bytes of a Curve25519 public key
/*! Also available as an export constant: Curve25519PubKeyLength. */
#define CURVE25519_PUB_KEY_LENGTH 32
//! Length in bytes of a P256 public key
/*! Also available as an export constant: P256PubKeyLength. */
#define P256_PUB_KEY_LENGTH 33

//! Use to free any memory allocated by this library
void fips_crypto_free(void* ptr);
//! Get description of last error
extern const char* fips_crypto_last_error(void);

//! Initialize a symmetric encryption operation
/*!
 * \param key An AES key of length KEY_LENGTH
 * \param iv An initialization vector of length IV_LENGTH. Note that IV will not be included with
             the ciphertext output. Storing it is the responsibility of the caller.
 * \return An encryption context, or NULL. Will leak if further aes_* functions are not called.
 */
extern AES_REF aes_encrypt_init(const BYTE key[AES_KEY_LENGTH], const BYTE iv[AES_IV_LENGTH]);

//! Encrypt a data buffer
/*!
 * After aes_encrypt_init(), this should be invoked one or more times with chunks of plaintext.
 * \param ciphertext Output buffer allocated by the caller. Must have at least
          at least len bytes, rounded up to the nearest multiple of 16. Will be cleaned
          up on error.
 * \param outlen Number of bytes written.
 * \param aes Encryption context
 * \param plaintext An input buffer of any length
 * \param len Length of the plaintext buffer
 * \return 1 if success, or 0 if error
 */
extern int aes_encrypt_update(AES_REF aes, BYTE ciphertext[], int* outlen, const BYTE plaintext[], int len);
    
//! Finish the encryption operation
/*!
 * \param aes The encryption context, which is cleaned up by the operation.
 * \param ciphertext Output buffer to receive any partial block left over. Must have
          room for one block (16 bytes) of data.
   \param outlen Number of bytes written.
   \param tag An 16-byte output buffer for authentication tag, used to verify that the
              ciphertext has not been tampered with. The caller is responsible for
              storing this.
 * \return 1 if success, or 0 if error
 */
extern int aes_encrypt_finalize(AES_REF aes, BYTE ciphertext[], int* outlen, BYTE tag[AES_TAG_LEN]);

//! Initialize a symmetric decryption operation
/*!
 * \param key The key used for encryption
 * \param iv The initialization vector used for encryption
 * \return An encryption context, or NULL. Will leak if further aes_* functions are not called.
 */
extern AES_REF aes_decrypt_init(const BYTE key[AES_KEY_LENGTH], const BYTE iv[AES_IV_LENGTH]);
    
//! Decrypt a data buffer
/*!
 * After aes_decrypt_init(), this should be invoked one or more times until all ciphertext
 * has been passed in.
 * \param aes Encryption context
 * \param plaintext Output buffer allocated by the caller. Must have enough room for
 *        len + 16 bytes of plaintext.
 * \param outlen Number of bytes used.
 * \param ciphertext An input buffer of any length
 * \param len Length of the ciphertext buffer
 * \return 1 if success, or 0 if error
 */
extern int aes_decrypt_update(AES_REF aes, BYTE plaintext[], int* outlen, const BYTE ciphertext[], int len);
    
//! Finish the decryption operation
/*!
 * \param aes The encryption context, which is cleaned up by the operation.
 * \param tag The 16-byte authentication tag generated during encryption
 * \return 1 if success, -1 if verification fails, or 0 for other errors.
 */
extern int aes_decrypt_finalize(AES_REF aes, BYTE tag[AES_TAG_LEN]);

//! Types of elliptic curves supported
/*!
 * Note that changing the curve will also change the algorithm (ECDSA vs ED25519 for signing, and
 * ECDHE vs X25519 for encryption).
 */
typedef enum {
    CURVE_25519 = 0,
    NIST_P256 = 1
} EC_KEY_TYPE;
    
//! How the key will be used. Signing keys may not be valid for encryption, vice versa.
typedef enum {
    SIGNATURE_USAGE, ENCRYPTION_USAGE
} EC_KEY_USAGE;
typedef void* EC_KEY_REF;

//! Generate a new key-pair
/*!
 * \param type Which curve to use
 * \param usage How the key will be used
 * \return An opaque reference to a key
 */
extern EC_KEY_REF generate_ec_key(EC_KEY_TYPE type, EC_KEY_USAGE usage);
    
//! Serialize a key to binary format
/*!
 * \param key The key being serialized
 * \param key_bytes On output, the key bytes in compressed format. For P256 public keys this
 *        requires 33 bytes. P256 private keys and all Curve25519 keys use 32 bytes.
 * \param key_length Length of key_bytes
 * \param include_private Store the private key, or only the public key component?
 * \return 1 if success, or 0 if error
 */
extern int ec_key_to_binary(EC_KEY_REF key, EC_KEY_TYPE key_type, BYTE key_bytes[], size_t key_length, bool include_private);

//! Deserialize a key from a binary format
/*!
 * \param key_bytes Key bytes in compressed format.
 * \param key_length Length of key_bytes
 * \param key_type Which curve was used to create the key
 * \param key_usage The intended usage of the key
 * \param is_private Do the bytes represent a private key or a public key? If the
 *        private key is provided, the public key will be reconstructed.
 * \return Opaque reference to a keypair
 */
EC_KEY_REF ec_key_from_binary(BYTE key_bytes[], size_t key_length, EC_KEY_TYPE key_type, EC_KEY_USAGE key_usage, bool is_private);

//! Dispose resources used by key
extern void ec_key_free(EC_KEY_REF key);
    
//! Sign a message with Curve25519 + P256
/*!
 * \param curve25519_key A key with type CURVE_25519 and usage USAGE_SIGN
 * \param nistp256_key A key with type NIST_P256 and usage USAGE_SIGN
 * \param message An input buffer of any length, containing the message data
 * \param msg_len The length of the message buffer
 * \param signature A buffer containing the signature, output by the caller
 * \return 1 if success, or 0 if error
 */
extern int ec_sign(EC_KEY_REF curve25519_key, EC_KEY_REF nistp256_key, BYTE* message, size_t msg_len, BYTE* signature);

//! Verify a message signature
/*!
 * \param curve25519_key The CURVE_25519 key used to perform the signature
 * \param nistp256_key The NIST_P256 key used to perform the signature
 * \param message The message that was signed
 * \param msg_len Length of message
 * \param signature Signature to be verified
 * \return 1 if success, -1 if verification fails, or 0 for other errors.
 */
extern int ec_verify(EC_KEY_REF curve25519_key, EC_KEY_REF nistp256_key, BYTE* message, size_t msg_len, BYTE signature[128]);

//! Encrypt a message using the sender's private key and the recipient's public key
/*!
 * \param curve25519_private_key key Private key of the sender with type CURVE_25519 and usage USAGE_ENCRYPT
 * \param nistp256_private_key key Private key of the sender with type NIST_P256 and usage USAGE_ENCRYPT
 * \param curve25519_public_key key Public key of the recipient with type CURVE_25519 and usage USAGE_ENCRYPT
 * \param nistp256_public_key key Public key of the recipient with type NIST_P256 and usage USAGE_ENCRYPT
 * \param message The message to be encrypted. Can be any length.
 * \param msg_len Length of message
 * \param output The ciphertext and associated metadata. Allocated by the function.
 * \param output_len Length of output
 * \return 1 if success, or 0 if error
 */
int box_encrypt(EC_KEY_REF curve25519_private_key, EC_KEY_REF nistp256_private_key,
                EC_KEY_REF curve25519_public_key,  EC_KEY_REF nistp256_public_key,
                BYTE* message, int msg_len, BYTE** output, int* output_len);

//! Decrypt a message using the sender's public key and the recipient's private key
/*!
 * \param curve25519_public_key key Public key of the sender with type CURVE_25519 and usage USAGE_ENCRYPT
 * \param nistp256_public_key key Public key of the sender with type NIST_P256 and usage USAGE_ENCRYPT
 * \param curve25519_private_key key Private key of the recipient with type CURVE_25519 and usage USAGE_ENCRYPT
 * \param nistp256_private_key key Private key of the recipient with type NIST_P256 and usage USAGE_ENCRYPT
 * \param input The message to be decrypted.
 * \param input_len Length of input
 * \param plaintext The output of the decryption operation. Allocated by the function.
 * \param plaintext_len Length of output
 * \return 1 if success, -1 if verification fails, or 0 for other errors.
 */
int box_decrypt(EC_KEY_REF curve25519_public_key,  EC_KEY_REF nistp256_public_key,
                EC_KEY_REF curve25519_private_key, EC_KEY_REF nistp256_private_key,
                BYTE* input, size_t input_len, BYTE** plaintext, int* plaintext_len);

//! Encrypt a message using the recipient's public key
/*!
 * \param curve25519_key Public key of the recipient with type CURVE_25519 and usage USAGE_ENCRYPT
 * \param nistp256_key Public key of the recipient with type NIST_P256 and usage USAGE_ENCRYPT
 * \param message The message to be encrypted. Can be any length.
 * \param msg_len Length of message
 * \param output The ciphertext and associated metadata. Allocated by the function.
 * \param output_len Length of output
 * \return 1 if success, or 0 if error
 */
extern int hybrid_encrypt(EC_KEY_REF curve25519_key, EC_KEY_REF nistp256_key, BYTE* message, size_t msg_len, BYTE** output, int* output_len);
                          
//! Decrypt a message usiong the recipient's private key
/*!
 * \param curve25519_key Private CURVE_25519 key of the recpient
 * \param nistp256_key Private NIST_P256 key of the recipient
 * \param input The full ciphertext (with associated metadata)
 * \param input_len Length of input
 * \param plaintext The result of decrypting input. Allocated by the function.
 * \param plaintext_len On output, length of plaintext.
 * \return 1 if success, -1 if verification fails, or 0 for other errors.
 */
extern int hybrid_decrypt(EC_KEY_REF curve25519_key, EC_KEY_REF nistp256_key, BYTE* input, size_t input_len, BYTE** plaintext, int* plaintext_len);

#ifdef __cplusplus
}
#endif

#endif // !defined(fips_crypto_h)
