/*
 * test_session.cpp
 *
 * Unit tests for Session management (v1.0).
 */

#include <gtest/gtest.h>
#include "../include/session.h"
#include "../include/crypto.h"
#include "../include/frame.h"
#include "../include/protocol.h"

using namespace gossip;

class SessionTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        crypto::init();
    }
    
    Session* session_init;
    Session* session_resp;
    uint8_t k_init[32];
    uint8_t k_resp[32];

    void SetUp() override {
        crypto::random_bytes(k_init, 32);
        crypto::random_bytes(k_resp, 32);
        
        // Simulates two sides of a connection (initiator=true, responder=false)
        // Note: Responder's send key is Initiator's recv key, and vice versa.
        session_init = new Session(k_init, k_resp, true);
        session_resp = new Session(k_resp, k_init, false);
    }

    void TearDown() override {
        delete session_init;
        delete session_resp;
    }
};

TEST_F(SessionTest, ImplicitNonceEncryption) {
    // Initiator encrypts a frame
    // Uses send_key (K_init) and internal sequence (0)
    std::vector<uint8_t> plaintext = {0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<uint8_t> ciphertext;
    
    // Mock Frame Header (8 bytes)
    uint8_t header[8] = {0x47, 0x52, 0x10, 0x00, 0x00, 0x04, 0x00, 0x00}; 
    // Magic(2), Type(1), Flags(1), Len(2), Rsrv(2)
    // Wait, v1.0 header format in protocol.h? 
    // Or does FrameV1::encrypt take raw plaintext?
    
    // Verify Frame::encrypt interface
    protocol::MessageType type = protocol::MessageType::MSG;
    uint64_t seq_out;
    
    bool ok = FrameV1::encrypt(*session_init, type, plaintext.data(), plaintext.size(), ciphertext, seq_out);
    ASSERT_TRUE(ok);
    
    // Ciphertext size = Header + Plaintext + Tag
    EXPECT_EQ(ciphertext.size(), 8 + plaintext.size() + 16);
    
    // Responder decrypts (Uses recv_key = K_init)
    std::vector<uint8_t> decrypted;
    protocol::MessageType dec_type;
    uint64_t seq;
    
    ok = FrameV1::decrypt(*session_resp, ciphertext.data(), ciphertext.size(), decrypted, dec_type, seq);
    ASSERT_TRUE(ok);
    
    EXPECT_EQ(decrypted, plaintext);
    EXPECT_EQ(dec_type, type);
    EXPECT_EQ(seq, 0); // First message
}

TEST_F(SessionTest, DirectionalKeys) {
    // Initiator sends (encrypted with K_init)
    std::vector<uint8_t> data = {1, 2, 3};
    std::vector<uint8_t> encrypted_init;
    uint64_t seq;
    FrameV1::encrypt(*session_init, protocol::MessageType::MSG, data.data(), data.size(), encrypted_init, seq);
    
    // Responder sends (encrypted with K_resp)
    std::vector<uint8_t> encrypted_resp;
    FrameV1::encrypt(*session_resp, protocol::MessageType::MSG, data.data(), data.size(), encrypted_resp, seq);
    
    // They should differ even with same nonce/seq because keys differ
    EXPECT_NE(encrypted_init, encrypted_resp);
    
    // Valid cross-decrypt
    std::vector<uint8_t> out;
    protocol::MessageType type;
    // seq reuse

    
    // Resp decrypts Init's message (using recv_key = K_init) -> Success
    EXPECT_TRUE(FrameV1::decrypt(*session_resp, encrypted_init.data(), encrypted_init.size(), out, type, seq));
    
    // Init decrypts Resp's message (using recv_key = K_resp) -> Success
    EXPECT_TRUE(FrameV1::decrypt(*session_init, encrypted_resp.data(), encrypted_resp.size(), out, type, seq));
}

TEST_F(SessionTest, StrictOrdering) {
    
    std::vector<uint8_t> data = {0xAA};
    std::vector<uint8_t> c1, c2, c3;
    uint64_t temp_seq;
    
    FrameV1::encrypt(*session_init, protocol::MessageType::MSG, data.data(), data.size(), c1, temp_seq); // Seq 0
    FrameV1::encrypt(*session_init, protocol::MessageType::MSG, data.data(), data.size(), c2, temp_seq); // Seq 1
    FrameV1::encrypt(*session_init, protocol::MessageType::MSG, data.data(), data.size(), c3, temp_seq); // Seq 2
    
    std::vector<uint8_t> out;
    protocol::MessageType type;
    uint64_t seq;
    
    // Receive 0 -> OK
    EXPECT_TRUE(FrameV1::decrypt(*session_resp, c1.data(), c1.size(), out, type, seq));
    
    // Receive 2 -> FAIL (Gap, expected 1)
    EXPECT_FALSE(FrameV1::decrypt(*session_resp, c3.data(), c3.size(), out, type, seq));
    
    // Receive 1 -> OK
    EXPECT_TRUE(FrameV1::decrypt(*session_resp, c2.data(), c2.size(), out, type, seq));
    
    // Receive 1 again -> FAIL (Replay)
    EXPECT_FALSE(FrameV1::decrypt(*session_resp, c2.data(), c2.size(), out, type, seq));
    
    // Receive 2 -> FAIL (Wait, strict mode implies if we missed it, we assume broken connection? 
    // Or do we buffer? FrameV1::decrypt checks:
    // if (seq != seq_recv_expected_) return false;
    // So yes, strictly next. Since we failed to decrypt 2 earlier (it wasn't processed),
    // Recv seq remains at 2 (after 1).
    // So 2 should pass now.
    EXPECT_TRUE(FrameV1::decrypt(*session_resp, c3.data(), c3.size(), out, type, seq));
}
