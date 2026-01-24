#include <gtest/gtest.h>
#include "handshake.h"
#include "identity.h"
#include "logging.h"

using namespace gossip;

class HandshakeTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Suppress logging during tests
        // gossip::logging::set_level(gossip::logging::Level::OFF);
    }

    Identity id_init;
    Identity id_resp;
    
    void SetUpIdentities() {
        id_init.generate();
        id_resp.generate();
    }
};

TEST_F(HandshakeTest, FullHandshakeFlow) {
    SetUpIdentities();
    
    Handshake client(id_init);
    Handshake server(id_resp);
    
    // 1. Client creates HELLO
    auto client_hello = client.create_hello(true);
    ASSERT_EQ(client_hello.size(), 33); // 1 role + 32 pubkey
    ASSERT_EQ(client.state(), HandshakeState::HELLO_SENT);
    
    // 2. Server processes HELLO
    bool ok = server.process_hello(client_hello.data(), client_hello.size());
    ASSERT_TRUE(ok);
    ASSERT_EQ(server.state(), HandshakeState::HELLO_RECEIVED);
    ASSERT_EQ(server.role(), protocol::HandshakeRole::RESPONDER);
    
    // 3. Server creates HELLO
    auto server_hello = server.create_hello(false);
    ASSERT_EQ(server_hello.size(), 33);
    
    // 4. Client processes Server HELLO
    ok = client.process_hello(server_hello.data(), server_hello.size());
    ASSERT_TRUE(ok);
    ASSERT_EQ(client.state(), HandshakeState::HELLO_RECEIVED);
    
    // 5. Derive Keys
    ASSERT_TRUE(client.derive_keys());
    ASSERT_TRUE(server.derive_keys());
    
    ASSERT_EQ(client.state(), HandshakeState::KEYS_DERIVED);
    ASSERT_EQ(server.state(), HandshakeState::KEYS_DERIVED);
    
    // 6. Exchange AUTH
    // Client sends AUTH
    auto client_auth_payload = client.create_auth();
    ASSERT_FALSE(client_auth_payload.empty());
    
    // Server verifies AUTH
    uint8_t peer_id_out[32];
    ok = server.process_auth(client_auth_payload.data(), client_auth_payload.size(), peer_id_out);
    ASSERT_TRUE(ok);
    ASSERT_EQ(server.state(), HandshakeState::COMPLETE);
    
    // Verify pinned identity
    ASSERT_EQ(std::memcmp(peer_id_out, id_init.public_key(), 32), 0);
    
    // Server sends AUTH
    auto server_auth_payload = server.create_auth();
    ASSERT_FALSE(server_auth_payload.empty());
    
    // Client verifies AUTH
    ok = client.process_auth(server_auth_payload.data(), server_auth_payload.size(), peer_id_out);
    ASSERT_TRUE(ok);
    ASSERT_EQ(client.state(), HandshakeState::COMPLETE);
    
    // Verify pinned identity
    ASSERT_EQ(std::memcmp(peer_id_out, id_resp.public_key(), 32), 0);
}

TEST_F(HandshakeTest, FailOnBadSignature) {
    SetUpIdentities();
    Handshake client(id_init);
    Handshake server(id_resp);
    
    // Exchange HELLOs
    auto h1 = client.create_hello(true);
    server.process_hello(h1.data(), h1.size());
    auto h2 = server.create_hello(false);
    client.process_hello(h2.data(), h2.size());
    
    client.derive_keys();
    server.derive_keys();
    
    // Tamper with AUTH
    auto auth = client.create_auth();
    auth[5] ^= 0xFF; // Corrupt signature or key
    
    uint8_t buf[32];
    bool ok = server.process_auth(auth.data(), auth.size(), buf);
    ASSERT_FALSE(ok);
    ASSERT_EQ(server.state(), HandshakeState::FAILED);
}
