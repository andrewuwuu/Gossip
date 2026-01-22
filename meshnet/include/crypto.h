/*
 * crypto.h
 *
 * Cryptographic primitives for the Gossip Protocol v0.1.
 * Provides AEAD encryption using XChaCha20-Poly1305 and secure random number generation.
 *
 * All functions in this module are designed to:
 * - Be constant-time where security-relevant
 * - Never expose partial plaintext on authentication failure
 * - Use libsodium for all cryptographic operations
 */

#ifndef GOSSIP_CRYPTO_H
#define GOSSIP_CRYPTO_H

#include <cstdint>
#include <cstddef>
#include <vector>

namespace gossip {
namespace crypto {

/*
 * Cryptographic constants matching Gossip Protocol v0.1 specification.
 */
constexpr size_t KEY_SIZE = 32;       /* 256-bit symmetric key */
constexpr size_t NONCE_SIZE = 24;     /* XChaCha20 extended nonce */
constexpr size_t TAG_SIZE = 16;       /* Poly1305 authentication tag */

/*
 * Initializes the cryptographic subsystem.
 * Must be called once before any other crypto functions.
 *
 * @return true on success, false if initialization failed
 */
bool init();

/*
 * Fills a buffer with cryptographically secure random bytes.
 *
 * @param buf    Pointer to buffer to fill
 * @param len    Number of random bytes to generate
 */
void random_bytes(uint8_t* buf, size_t len);

/*
 * Encrypts plaintext using XChaCha20-Poly1305 AEAD.
 *
 * @param key           32-byte encryption key
 * @param nonce         24-byte nonce (must be unique per message)
 * @param plaintext     Data to encrypt
 * @param plaintext_len Length of plaintext
 * @param aad           Additional authenticated data (not encrypted, but authenticated)
 * @param aad_len       Length of AAD
 * @param ciphertext    Output buffer (must be at least plaintext_len + TAG_SIZE bytes)
 *
 * @return true on success, false on failure
 *
 * The output format is: [ciphertext (plaintext_len bytes)] [tag (16 bytes)]
 */
bool aead_encrypt(
    const uint8_t* key,
    const uint8_t* nonce,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* aad,
    size_t aad_len,
    uint8_t* ciphertext
);

/*
 * Decrypts ciphertext using XChaCha20-Poly1305 AEAD.
 *
 * @param key            32-byte decryption key
 * @param nonce          24-byte nonce used during encryption
 * @param ciphertext     Encrypted data with appended tag
 * @param ciphertext_len Length of ciphertext (including 16-byte tag)
 * @param aad            Additional authenticated data
 * @param aad_len        Length of AAD
 * @param plaintext      Output buffer (must be at least ciphertext_len - TAG_SIZE bytes)
 *
 * @return true on successful decryption and authentication, false if authentication fails
 *
 * SECURITY: On authentication failure, the plaintext buffer is NOT modified.
 */
bool aead_decrypt(
    const uint8_t* key,
    const uint8_t* nonce,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* aad,
    size_t aad_len,
    uint8_t* plaintext
);

/*
 * Securely compares two byte arrays in constant time.
 *
 * @param a   First buffer
 * @param b   Second buffer
 * @param len Length to compare
 *
 * @return true if equal, false otherwise
 */
bool secure_compare(const uint8_t* a, const uint8_t* b, size_t len);

/*
 * Securely zeros a memory region.
 *
 * @param buf Pointer to memory to zero
 * @param len Number of bytes to zero
 */
void secure_zero(void* buf, size_t len);

}  /* namespace crypto */
}  /* namespace gossip */

#endif  /* GOSSIP_CRYPTO_H */
