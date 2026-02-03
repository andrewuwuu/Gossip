#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <unordered_set>
#include <vector>

#include <sys/socket.h>
#include <unistd.h>

#include "connection.h"
#include "crypto.h"
#include "frame.h"
#include "packet.h"

using namespace gossip;

class RegressionTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        crypto::init();
    }
};

TEST_F(RegressionTest, PacketSequenceIsThreadSafe) {
    constexpr size_t kThreads = 8;
    constexpr size_t kPerThread = 1000;
    constexpr size_t kTotal = kThreads * kPerThread;

    std::vector<uint32_t> sequences(kTotal);
    std::atomic<size_t> index{0};
    std::vector<std::thread> threads;

    for (size_t t = 0; t < kThreads; ++t) {
        threads.emplace_back([&]() {
            for (size_t i = 0; i < kPerThread; ++i) {
                Packet packet(PacketType::PING, 1);
                size_t pos = index.fetch_add(1);
                sequences[pos] = packet.sequence();
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    std::unordered_set<uint32_t> unique(sequences.begin(), sequences.end());
    EXPECT_EQ(unique.size(), sequences.size());
}

TEST_F(RegressionTest, MessagePayloadRejectsLongUsername) {
    MessagePayload payload;
    payload.dest_id = 1;
    payload.username = std::string(256, 'a');
    payload.message = "hello";

    auto data = payload.serialize();
    EXPECT_TRUE(data.empty());
}

TEST_F(RegressionTest, EncryptedPayloadPreservesFlagsAndHeader) {
    uint8_t k_init[32];
    uint8_t k_resp[32];
    crypto::random_bytes(k_init, sizeof(k_init));
    crypto::random_bytes(k_resp, sizeof(k_resp));

    int fds[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

    auto send_session = std::make_shared<Session>(k_init, k_resp, true);
    Connection conn(fds[0], "local", 0);
    conn.set_session(send_session);

    Packet packet(PacketType::MSG, 0xBEEF, FLAG_BROADCAST);
    std::vector<uint8_t> payload = {0x10, 0x20, 0x30, 0x40};
    ASSERT_TRUE(packet.set_payload(payload));

    ASSERT_TRUE(conn.send(packet));

    std::vector<uint8_t> frame(2048);
    ssize_t n = ::recv(fds[1], frame.data(), frame.size(), 0);
    ASSERT_GT(n, 0);
    frame.resize(static_cast<size_t>(n));

    Session recv_session(k_resp, k_init, false);
    std::vector<uint8_t> decrypted;
    protocol::MessageType type;
    uint64_t seq = 0;

    ASSERT_TRUE(FrameV1::decrypt(recv_session, frame.data(), frame.size(), decrypted, type, seq));
    ASSERT_EQ(type, protocol::MessageType::MSG);
    ASSERT_GE(decrypted.size(), 6u);

    uint8_t orig_type = decrypted[0];
    uint8_t orig_flags = decrypted[1];
    uint16_t orig_source_id = (static_cast<uint16_t>(decrypted[2]) << 8) |
                              static_cast<uint16_t>(decrypted[3]);
    uint16_t orig_payload_len = (static_cast<uint16_t>(decrypted[4]) << 8) |
                                static_cast<uint16_t>(decrypted[5]);

    EXPECT_EQ(orig_type, static_cast<uint8_t>(PacketType::MSG));
    EXPECT_EQ(orig_flags & FLAG_BROADCAST, FLAG_BROADCAST);
    EXPECT_EQ(orig_source_id, 0xBEEF);
    EXPECT_EQ(orig_payload_len, payload.size());

    std::vector<uint8_t> recovered(
        decrypted.begin() + 6,
        decrypted.begin() + 6 + orig_payload_len
    );
    EXPECT_EQ(recovered, payload);

    ::close(fds[1]);
}
