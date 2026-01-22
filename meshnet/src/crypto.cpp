/*
 * crypto.cpp
 *
 * Implementation of cryptographic primitives using libsodium.
 * Provides XChaCha20-Poly1305 AEAD encryption and secure random generation.
 */

#include "crypto.h"
#include <sodium.h>
#include <cstring>

namespace gossip {
namespace crypto {

bool init() {
    /*
     * sodium_init() returns 0 on success, -1 on failure, and 1 if already initialized.
     * We treat both 0 and 1 as success.
     */
    return sodium_init() >= 0;
}

void random_bytes(uint8_t* buf, size_t len) {
    randombytes_buf(buf, len);
}

bool aead_encrypt(
    const uint8_t* key,
    const uint8_t* nonce,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* aad,
    size_t aad_len,
    uint8_t* ciphertext
) {
    if (key == nullptr || nonce == nullptr || ciphertext == nullptr) {
        return false;
    }
    
    if (plaintext_len > 0 && plaintext == nullptr) {
        return false;
    }

    unsigned long long ciphertext_len;
    
    int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext,
        &ciphertext_len,
        plaintext,
        plaintext_len,
        aad,
        aad_len,
        nullptr,  /* nsec - not used */
        nonce,
        key
    );

    return result == 0;
}

bool aead_decrypt(
    const uint8_t* key,
    const uint8_t* nonce,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* aad,
    size_t aad_len,
    uint8_t* plaintext
) {
    if (key == nullptr || nonce == nullptr || plaintext == nullptr) {
        return false;
    }
    
    if (ciphertext_len < TAG_SIZE) {
        return false;
    }

    if (ciphertext_len > TAG_SIZE && ciphertext == nullptr) {
        return false;
    }

    unsigned long long plaintext_len;
    
    /*
     * crypto_aead_xchacha20poly1305_ietf_decrypt returns 0 on success,
     * -1 if authentication fails. On failure, plaintext is not modified.
     */
    int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext,
        &plaintext_len,
        nullptr,  /* nsec - not used */
        ciphertext,
        ciphertext_len,
        aad,
        aad_len,
        nonce,
        key
    );

    return result == 0;
}

bool secure_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    return sodium_memcmp(a, b, len) == 0;
}

void secure_zero(void* buf, size_t len) {
    sodium_memzero(buf, len);
}

void generate_keypair(uint8_t* public_key, uint8_t* private_key) {
    /*
     * crypto_kx_keypair generates a keypair for key exchange.
     * The private key is the seed, public key is derived.
     */
    crypto_kx_keypair(public_key, private_key);
}

void derive_public_key(uint8_t* public_key, const uint8_t* private_key) {
    /*
     * Derive the public key from the private key seed.
     * crypto_scalarmult_base computes public = private * basepoint.
     */
    crypto_scalarmult_base(public_key, private_key);
}

bool derive_shared_secret(
    uint8_t* shared_secret,
    const uint8_t* my_private,
    const uint8_t* their_public
) {
    /*
     * Perform X25519 scalar multiplication to derive shared secret.
     * Both parties derive the same secret:
     *   A: secret = my_priv * their_pub = a * B
     *   B: secret = my_priv * their_pub = b * A
     *   Since A = a*G and B = b*G, both derive a*b*G.
     *
     * crypto_scalarmult returns 0 on success, -1 if their_public is
     * a low-order point (security check).
     */
    int result = crypto_scalarmult(shared_secret, my_private, their_public);
    
    if (result != 0) {
        secure_zero(shared_secret, SHARED_SECRET_SIZE);
        return false;
    }
    
    /*
     * Hash the raw shared secret for additional safety.
     * This prevents issues with low-entropy DH outputs.
     */
    uint8_t hashed[crypto_generichash_BYTES];
    crypto_generichash(hashed, sizeof(hashed), shared_secret, SHARED_SECRET_SIZE, nullptr, 0);
    memcpy(shared_secret, hashed, SHARED_SECRET_SIZE);
    secure_zero(hashed, sizeof(hashed));
    
    return true;
}

}  /* namespace crypto */
}  /* namespace gossip */
