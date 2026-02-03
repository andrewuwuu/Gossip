/*
 * crypto.cpp
 *
 * Implementation of cryptographic primitives using libsodium.
 * Provides XChaCha20-Poly1305 AEAD, X25519 key exchange, Ed25519 signatures,
 * SHA-256 hashing, and HKDF-SHA256 key derivation.
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

/*
 * =============================================================================
 * Ed25519 Implementation
 * =============================================================================
 */

void ed25519_generate_keypair(uint8_t* public_key, uint8_t* secret_key) {
    /*
     * crypto_sign_keypair generates an Ed25519 keypair.
     * The secret key is 64 bytes (seed + public key cached).
     */
    crypto_sign_keypair(public_key, secret_key);
}

void ed25519_keypair_from_seed(uint8_t* public_key, uint8_t* secret_key, const uint8_t* seed) {
    /*
     * crypto_sign_seed_keypair derives an Ed25519 keypair from a 32-byte seed.
     * This is deterministic - same seed always produces the same keypair.
     */
    crypto_sign_seed_keypair(public_key, secret_key, seed);
}

bool ed25519_sign(
    const uint8_t* secret_key,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature
) {
    if (secret_key == nullptr || signature == nullptr) {
        return false;
    }
    
    if (message_len > 0 && message == nullptr) {
        return false;
    }
    
    /*
     * crypto_sign_detached produces a 64-byte signature without
     * prepending it to the message.
     */
    unsigned long long sig_len;
    int result = crypto_sign_detached(
        signature,
        &sig_len,
        message,
        message_len,
        secret_key
    );
    
    return result == 0;
}

bool ed25519_verify(
    const uint8_t* public_key,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature
) {
    if (public_key == nullptr || signature == nullptr) {
        return false;
    }
    
    if (message_len > 0 && message == nullptr) {
        return false;
    }
    
    /*
     * crypto_sign_verify_detached returns 0 if valid, -1 if invalid.
     */
    int result = crypto_sign_verify_detached(
        signature,
        message,
        message_len,
        public_key
    );
    
    return result == 0;
}

/*
 * =============================================================================
 * SHA-256 Implementation
 * =============================================================================
 */

void sha256(const uint8_t* data, size_t len, uint8_t* hash) {
    crypto_hash_sha256(hash, data, len);
}

void sha256_multi(
    const std::vector<std::pair<const uint8_t*, size_t>>& parts,
    uint8_t* hash
) {
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    
    for (const auto& part : parts) {
        if (part.first != nullptr && part.second > 0) {
            crypto_hash_sha256_update(&state, part.first, part.second);
        }
    }
    
    crypto_hash_sha256_final(&state, hash);
}

/*
 * =============================================================================
 * HKDF-SHA256 Implementation
 * =============================================================================
 */

void hkdf_extract(
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* ikm,
    size_t ikm_len,
    uint8_t* prk
) {
    /*
     * HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
     * If salt is not provided, use a string of HASH_SIZE zeros.
     */
    uint8_t default_salt[HASH_SIZE] = {0};
    const uint8_t* actual_salt = (salt != nullptr && salt_len > 0) ? salt : default_salt;
    size_t actual_salt_len = (salt != nullptr && salt_len > 0) ? salt_len : HASH_SIZE;
    
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, actual_salt, actual_salt_len);
    crypto_auth_hmacsha256_update(&state, ikm, ikm_len);
    crypto_auth_hmacsha256_final(&state, prk);
}

void hkdf_expand(
    const uint8_t* prk,
    const uint8_t* info,
    size_t info_len,
    uint8_t* okm,
    size_t okm_len
) {
    /*
     * HKDF-Expand: OKM = T(1) || T(2) || ... || T(N)
     * where T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
     * and T(0) = empty string.
     */
    uint8_t t[HASH_SIZE];
    size_t t_len = 0;
    uint8_t counter = 1;
    size_t offset = 0;
    
    while (offset < okm_len) {
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, prk, HASH_SIZE);
        
        /* T(i-1) - empty for first iteration */
        if (t_len > 0) {
            crypto_auth_hmacsha256_update(&state, t, t_len);
        }
        
        /* info */
        if (info != nullptr && info_len > 0) {
            crypto_auth_hmacsha256_update(&state, info, info_len);
        }
        
        /* counter byte */
        crypto_auth_hmacsha256_update(&state, &counter, 1);
        
        crypto_auth_hmacsha256_final(&state, t);
        t_len = HASH_SIZE;
        
        /* Copy output */
        size_t copy_len = (okm_len - offset < HASH_SIZE) ? (okm_len - offset) : HASH_SIZE;
        memcpy(okm + offset, t, copy_len);
        
        offset += copy_len;
        counter++;
    }
    
    secure_zero(t, sizeof(t));
}

void hkdf_expand_label(
    const uint8_t* prk,
    const char* label,
    uint8_t* okm
) {
    size_t label_len = strlen(label);
    hkdf_expand(prk, reinterpret_cast<const uint8_t*>(label), label_len, okm, KEY_SIZE);
}

}  /* namespace crypto */
}  /* namespace gossip */
