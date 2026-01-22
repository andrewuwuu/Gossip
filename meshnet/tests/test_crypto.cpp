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

    // Probability of collision is negligible
    EXPECT_NE(std::memcmp(buf1, buf2, sizeof(buf1)), 0);
    
    // Check it's not all zeros
    bool all_zeros = true;
    for (int i = 0; i < 32; i++) {
        if (buf1[i] != 0) all_zeros = false;
    }
    EXPECT_FALSE(all_zeros);
}

TEST_F(CryptoTest, EncryptDecryptRoundTrip) {
    uint8_t key[crypto::KEY_SIZE];
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

TEST_F(CryptoTest, DecryptFailsWithWrongKey) {
    uint8_t key[crypto::KEY_SIZE];
    uint8_t wrong_key[crypto::KEY_SIZE];
    uint8_t nonce[crypto::NONCE_SIZE];
    crypto::random_bytes(key, sizeof(key));
    crypto::random_bytes(wrong_key, sizeof(wrong_key)); // Different random key
    crypto::random_bytes(nonce, sizeof(nonce));

    std::vector<uint8_t> plaintext(10, 'A');
    std::vector<uint8_t> aad(5, 'B');
    std::vector<uint8_t> ciphertext(plaintext.size() + crypto::TAG_SIZE);
    std::vector<uint8_t> decrypted(plaintext.size());

    ASSERT_TRUE(crypto::aead_encrypt(
        key, nonce,
        plaintext.data(), plaintext.size(),
        aad.data(), aad.size(),
        ciphertext.data()
    ));

    // Try decrypt with wrong key
    EXPECT_FALSE(crypto::aead_decrypt(
        wrong_key, nonce,
        ciphertext.data(), ciphertext.size(),
        aad.data(), aad.size(),
        decrypted.data()
    ));
}

TEST_F(CryptoTest, DecryptFailsWithTamperedAAD) {
    uint8_t key[crypto::KEY_SIZE];
    uint8_t nonce[crypto::NONCE_SIZE];
    crypto::random_bytes(key, sizeof(key));
    crypto::random_bytes(nonce, sizeof(nonce));

    std::vector<uint8_t> plaintext(10, 'A');
    std::vector<uint8_t> aad(5, 'B');
    std::vector<uint8_t> tampered_aad = aad;
    tampered_aad[0] = 'C'; // Change one byte

    std::vector<uint8_t> ciphertext(plaintext.size() + crypto::TAG_SIZE);
    std::vector<uint8_t> decrypted(plaintext.size());

    ASSERT_TRUE(crypto::aead_encrypt(
        key, nonce,
        plaintext.data(), plaintext.size(),
        aad.data(), aad.size(),
        ciphertext.data()
    ));

    // Try decrypt with tampered AAD
    EXPECT_FALSE(crypto::aead_decrypt(
        key, nonce,
        ciphertext.data(), ciphertext.size(),
        tampered_aad.data(), tampered_aad.size(),
        decrypted.data()
    ));
}

TEST_F(CryptoTest, DecryptFailsWithTamperedCiphertext) {
    uint8_t key[crypto::KEY_SIZE];
    uint8_t nonce[crypto::NONCE_SIZE];
    crypto::random_bytes(key, sizeof(key));
    crypto::random_bytes(nonce, sizeof(nonce));

    std::vector<uint8_t> plaintext(10, 'A');
    std::vector<uint8_t> aad(5, 'B');
    std::vector<uint8_t> ciphertext(plaintext.size() + crypto::TAG_SIZE);
    std::vector<uint8_t> decrypted(plaintext.size());

    ASSERT_TRUE(crypto::aead_encrypt(
        key, nonce,
        plaintext.data(), plaintext.size(),
        aad.data(), aad.size(),
        ciphertext.data()
    ));

    // Tamper with ciphertext
    ciphertext[0] ^= 0xFF;

    EXPECT_FALSE(crypto::aead_decrypt(
        key, nonce,
        ciphertext.data(), ciphertext.size(),
        aad.data(), aad.size(),
        decrypted.data()
    ));
}
