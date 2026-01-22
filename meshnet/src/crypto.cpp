/*
 * crypto.cpp
 *
 * Implementation of cryptographic primitives using libsodium.
 * Provides XChaCha20-Poly1305 AEAD encryption and secure random generation.
 */

#include "crypto.h"
#include <sodium.h>

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

}  /* namespace crypto */
}  /* namespace gossip */
