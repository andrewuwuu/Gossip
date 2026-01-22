/*
 * test_session.cpp
 *
 * Unit tests for Session management and Replay Protection.
 */

#include <gtest/gtest.h>
#include "../include/session.h"
#include "../include/crypto.h"

using namespace gossip;

class SessionTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        crypto::init();
    }
    
    Session* session;
    uint8_t key[crypto::KEY_SIZE];

    void SetUp() override {
        crypto::random_bytes(key, sizeof(key));
        session = new Session(key);
    }

    void TearDown() override {
        delete session;
    }
};

TEST_F(SessionTest, SequenceIncrements) {
    uint64_t s1, s2, s3;
    
    ASSERT_TRUE(session->next_send_seq(s1));
    ASSERT_TRUE(session->next_send_seq(s2));
    ASSERT_TRUE(session->next_send_seq(s3));
    
    EXPECT_EQ(s1, 0);
    EXPECT_EQ(s2, 1);
    EXPECT_EQ(s3, 2);
}

TEST_F(SessionTest, ReplayWindowBasics) {
    // First message should be accepted
    EXPECT_TRUE(session->check_replay(100));
    session->update_replay_window(100);
    
    // Newer message accepted
    EXPECT_TRUE(session->check_replay(101));
    session->update_replay_window(101);
    
    // Duplicate rejected
    EXPECT_FALSE(session->check_replay(100));
    EXPECT_FALSE(session->check_replay(101));
}

TEST_F(SessionTest, ReplayWindowOutOfOrder) {
    // Receive 100
    session->update_replay_window(100);
    
    // Receive 102 (gap)
    EXPECT_TRUE(session->check_replay(102));
    session->update_replay_window(102);
    
    // Receive 101 (filled gap)
    EXPECT_TRUE(session->check_replay(101));
    session->update_replay_window(101);
    
    // All should now be duplicates
    EXPECT_FALSE(session->check_replay(100));
    EXPECT_FALSE(session->check_replay(101));
    EXPECT_FALSE(session->check_replay(102));
}

TEST_F(SessionTest, ReplayWindowTooOld) {
    size_t window_size = 64;
    uint64_t start = 1000;
    
    // Set high water mark
    session->update_replay_window(start);
    
    // Message just inside window (start - 63)
    uint64_t boundary = start - (window_size - 1); 
    EXPECT_TRUE(session->check_replay(boundary));
    
    // Message just outside window (start - 64)
    uint64_t too_old = start - window_size;
    EXPECT_FALSE(session->check_replay(too_old));
}

TEST_F(SessionTest, ReplayWindowSliding) {
    // Fill window: 100 to 163
    session->update_replay_window(163);
    
    // 100 is now at the edge (163 - 63 = 100)
    EXPECT_TRUE(session->check_replay(100));
    
    // Push window forward by 1
    session->update_replay_window(164);
    
    // 100 is now too old (164 - 64 = 100, wait, logic check: 
    // If recv_highest is 164. Accept if seq > 164 - 64 = 100.
    // So 100 is effectively old?
    // Let's check implementation:
    // if (seq + REPLAY_WINDOW_SIZE <= recv_highest_) return false;
    // 100 + 64 = 164 <= 164 -> TRUE -> returns false (too old)
    EXPECT_FALSE(session->check_replay(100));
    
    // 101 should still be valid (101 + 64 = 165 > 164)
    EXPECT_TRUE(session->check_replay(101));
}
