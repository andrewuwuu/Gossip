/*
 * test_crypto.cpp
 *
 * Unit tests for the cryptographic primitives in crypto.h/cpp.
 */

#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <cstring>
#include "../include/crypto.h"

using namespace gossip;

class CryptoTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        ASSERT_TRUE(crypto::init()) << "Failed to initialize crypto subsystem";
    }
};

TEST_F(CryptoTest, SecureRandomBytes) {
    uint8_t buf1[32];
    uint8_t buf2[32];

    crypto::secure_zero(buf1, sizeof(buf1));
    crypto::secure_zero(buf2, sizeof(buf2));

    crypto::random_bytes(buf1, sizeof(buf1));
    crypto::random_bytes(buf2, sizeof(buf2));

    EXPECT_NE(std::memcmp(buf1, buf2, sizeof(buf1)), 0);
    
    bool all_zeros = true;
    for (int i = 0; i < 32; i++) {
        if (buf1[i] != 0) all_zeros = false;
    }
    EXPECT_FALSE(all_zeros);
}

TEST_F(CryptoTest, SHA256) {
    std::string input = "hello world";
    uint8_t hash[crypto::HASH_SIZE];
    
    crypto::sha256(reinterpret_cast<const uint8_t*>(input.data()), input.size(), hash);
    
    // Known SHA-256 of "hello world"
    // b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    uint8_t expected[32] = {
        0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08,
        0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
        0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee,
        0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9
    };
    
    EXPECT_EQ(std::memcmp(hash, expected, 32), 0);
}

TEST_F(CryptoTest, Ed25519SignVerify) {
    uint8_t pk[crypto::PUBLIC_KEY_SIZE];
    uint8_t sk[crypto::PRIVATE_KEY_SIZE]; 
    // Note: In crypto.h, PRIVATE_KEY_SIZE is 64 for Ed25519 (seed+pub) 
    // or 32 for X25519. Wait, let's verify header. 
    // Actually crypto.h defines PRIVATE_KEY_SIZE as 32 (X25519). 
    // Ed25519 needs 64 bytes for secret key (seed + pub) in libsodium's high level API, 
    // or sometimes just 32 for seed.
    // Looking at crypto.h, we have `ed25519_sign` taking `secret_key`.
    // Let's assume the implementation handles it. 
    // Actually, update: `crypto::ed25519_generate_keypair` likely outputs 32B public, 64B secret.
    // The constant might be misleading if used for both.
    
    uint8_t ed_sk[64]; // Use explicit size for safety if header is ambiguous
    
    crypto::ed25519_generate_keypair(pk, ed_sk);
    
    std::string msg = "Signed Message";
    uint8_t sig[crypto::ED25519_SIGNATURE_SIZE];
    
    crypto::ed25519_sign(
        ed_sk,
        reinterpret_cast<const uint8_t*>(msg.data()), 
        msg.size(),
        sig
    );
    
    EXPECT_TRUE(crypto::ed25519_verify(
        pk,
        reinterpret_cast<const uint8_t*>(msg.data()), 
        msg.size(),
        sig
    ));
    
    sig[0] ^= 0xFF;
    EXPECT_FALSE(crypto::ed25519_verify(
        pk,
        reinterpret_cast<const uint8_t*>(msg.data()), 
        msg.size(),
        sig
    ));
}

TEST_F(CryptoTest, HKDF_Derivation) {
    uint8_t ikm[32]; // Input Key Material (e.g. shared secret)
    uint8_t salt[32];
    uint8_t info[10];
    
    crypto::secure_zero(ikm, 32);
    crypto::secure_zero(salt, 32);
    crypto::secure_zero(info, 10);
    
    uint8_t prk[crypto::HASH_SIZE];
    uint8_t out_key[32];
    
    // Extract
    crypto::hkdf_extract(salt, 32, ikm, 32, prk);
    
    // Expand
    crypto::hkdf_expand(prk, (const uint8_t*)"info", 4, out_key, 32);
    
    // Check it's deterministic
    uint8_t out_key2[32];
    crypto::hkdf_expand(prk, (const uint8_t*)"info", 4, out_key2, 32);
    EXPECT_EQ(std::memcmp(out_key, out_key2, 32), 0);
    
    // Check different info gives different key
    crypto::hkdf_expand(prk, (const uint8_t*)"other", 5, out_key2, 32);
    EXPECT_NE(std::memcmp(out_key, out_key2, 32), 0);
}

TEST_F(CryptoTest, EncryptDecryptRoundTrip) {
    uint8_t key[32];
    uint8_t nonce[crypto::NONCE_SIZE];
    crypto::random_bytes(key, sizeof(key));
    crypto::random_bytes(nonce, sizeof(nonce));

    std::string message = "Hello, Gossip Protocol!";
    std::string aad_str = "header_data";
    
    std::vector<uint8_t> plaintext(message.begin(), message.end());
    std::vector<uint8_t> aad(aad_str.begin(), aad_str.end());
    std::vector<uint8_t> ciphertext(plaintext.size() + crypto::TAG_SIZE);
    std::vector<uint8_t> decrypted(plaintext.size());

    // Encrypt
    ASSERT_TRUE(crypto::aead_encrypt(
        key, nonce,
        plaintext.data(), plaintext.size(),
        aad.data(), aad.size(),
        ciphertext.data()
    ));

    // Decrypt
    ASSERT_TRUE(crypto::aead_decrypt(
        key, nonce,
        ciphertext.data(), ciphertext.size(),
        aad.data(), aad.size(),
        decrypted.data()
    ));

    // Verify
    EXPECT_EQ(plaintext, decrypted);
}
