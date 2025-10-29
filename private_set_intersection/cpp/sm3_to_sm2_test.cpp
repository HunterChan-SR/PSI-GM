#include <gtest/gtest.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <vector>
#include <string>
#include <memory>

// Helper: RAII wrappers
struct ECGroupPtr { EC_GROUP* g; ECGroupPtr(EC_GROUP* p=nullptr):g(p){} ~ECGroupPtr(){ if(g) EC_GROUP_free(g);} };
struct ECPointPtr { EC_POINT* p; ECPointPtr(EC_POINT* q=nullptr):p(q){} ~ECPointPtr(){ if(p) EC_POINT_free(p);} };

// Convert EC_POINT to octet vector (uncompressed)
static std::vector<uint8_t> PointToOctets(const EC_GROUP* group, const EC_POINT* pt) {
    size_t len = EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (len == 0) return {};
    std::vector<uint8_t> out(len);
    size_t r = EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), NULL);
    if (r == 0) return {};
    return out;
}
static bool HashToCurveP256(const EC_GROUP* group, const uint8_t* dst, size_t dst_len,
                          const uint8_t* msg, size_t msg_len, std::vector<uint8_t>& out_octets) {
    // Create EC_POINT
    EC_POINT* pt = EC_POINT_new(group);
    if (!pt) return false;
    ECPointPtr pt_guard(pt);

    // Call the exported EC wrapper function (exists in the implementation file)
    int ok = EC_hash_to_curve_p256_xmd_sha256_sswu(group, pt, dst, dst_len, msg, msg_len);
     if (!ok) {
        return false;
    }

    // Validate not at infinity and on curve
    if (EC_POINT_is_at_infinity(group, pt)) return false;
    if (EC_POINT_is_on_curve(group, pt, NULL) != 1) return false;

    out_octets = PointToOctets(group, pt);
    return !out_octets.empty();
}


TEST(ECHashTOCurveP256, DeterministicAndOnCurve) {
    ECGroupPtr group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    ASSERT_NE(group.g, nullptr);

    const std::string dst = "TEST_DST_SHA256_SSWU";
    const std::string msg = "sample message for hash-to-curve";

    std::vector<uint8_t> out1, out2;
    ASSERT_TRUE(HashToCurveP256(group.g, (const uint8_t*)dst.data(), dst.size(),
                               (const uint8_t*)msg.data(), msg.size(), out1));
    ASSERT_TRUE(HashToCurveP256(group.g, (const uint8_t*)dst.data(), dst.size(),
                               (const uint8_t*)msg.data(), msg.size(), out2));

    // Deterministic: outputs identical
    EXPECT_EQ(out1.size(), out2.size());
    EXPECT_EQ(out1, out2);

    // Ensure point is on curve (redundant because HashToCurveP256 checks it) by reconstructing point
    ECPointPtr pt(EC_POINT_new(group.g));
    ASSERT_NE(pt.p, nullptr);
    ASSERT_EQ(EC_POINT_oct2point(group.g, pt.p, out1.data(), out1.size(), NULL), 1);
    EXPECT_EQ(EC_POINT_is_at_infinity(group.g, pt.p), 0);
    EXPECT_EQ(EC_POINT_is_on_curve(group.g, pt.p, NULL), 1);
}

TEST(ECHashToCurveP256, DifferentMessagesProduceDifferentPoints) {
    ECGroupPtr group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    ASSERT_NE(group.g, nullptr);

    const std::string dst = "TEST_DST_SHA256_SSWU";
    const std::string msg1 = "message one";
    const std::string msg2 = "message two";

    std::vector<uint8_t> out1, out2;
    ASSERT_TRUE(HashToCurveP256(group.g, (const uint8_t*)dst.data(), dst.size(),
                               (const uint8_t*)msg1.data(), msg1.size(), out1));
    ASSERT_TRUE(HashToCurveP256(group.g, (const uint8_t*)dst.data(), dst.size(),
                               (const uint8_t*)msg2.data(), msg2.size(), out2));

    // Very small probability of collision; assert inequality for sanity
    EXPECT_NE(out1, out2);
}

TEST(ECHashToCurveP256, EmptyMessageAccepted) {
    ECGroupPtr group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    ASSERT_NE(group.g, nullptr);

    const std::string dst = "DST_EMPTY_MSG";
    const std::string msg = "";

    std::vector<uint8_t> out;
    EXPECT_TRUE(HashToCurveP256(group.g, (const uint8_t*)dst.data(), dst.size(),
                               (const uint8_t*)msg.data(), msg.size(), out));
    EXPECT_FALSE(out.empty());
}

TEST(ECHashToCurveP256, WrongGroupRejected) {
    // Use SM2 group which should be rejected by the p256-specific entrypoint
    ECGroupPtr wrong_group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    ASSERT_NE(wrong_group.g, nullptr);

    const std::string dst = "DST";
    const std::string msg = "msg";

    // Prepare an EC_POINT to call the low-level EC_hash_to_curve_p256_xmd_sha256_sswu
    EC_POINT* pt = EC_POINT_new(wrong_group.g);
    ASSERT_NE(pt, nullptr);
    ECPointPtr pt_guard(pt);

    // Expect failure (function checks group curve name)
    int ret = EC_hash_to_curve_p256_xmd_sha256_sswu(wrong_group.g, pt, (const uint8_t*)dst.data(), dst.size(),
                                                   (const uint8_t*)msg.data(), msg.size());
    EXPECT_EQ(ret, 0);
    // Optionally check that an error was pushed
    unsigned long err = ERR_peek_last_error();
    EXPECT_NE(err, 0UL);
    // Clear error queue for test hygiene
    ERR_clear_error();
}


// Wrapper to call EC_hash_to_curve_sm2p256v1_xmd_sm3_sswu and return success + point octets.
static bool HashToCurveSM2(const EC_GROUP* group, const uint8_t* dst, size_t dst_len,
                          const uint8_t* msg, size_t msg_len, std::vector<uint8_t>& out_octets) {
    // Create EC_POINT
    EC_POINT* pt = EC_POINT_new(group);
    if (!pt) return false;
    ECPointPtr pt_guard(pt);

    // Call the exported EC wrapper function (exists in the implementation file)
    int ok = EC_hash_to_curve_sm2p256v1_xmd_sm3_sswu(group, pt, dst, dst_len, msg, msg_len);
     if (!ok) {
        return false;
    }

    // Validate not at infinity and on curve
    if (EC_POINT_is_at_infinity(group, pt)) return false;
    if (EC_POINT_is_on_curve(group, pt, NULL) != 1) return false;

    out_octets = PointToOctets(group, pt);
    return !out_octets.empty();
}


//------------------------------------------------

TEST(ECHashToCurveSM2, DeterministicAndOnCurve) {
    ECGroupPtr group(EC_GROUP_new_by_curve_name(NID_sm2));
    ASSERT_NE(group.g, nullptr)<<"不支持sm2p256v1曲线";

    const std::string dst = "TEST_DST_SM3_SSWU";
    const std::string msg = "sample message for hash-to-curve";

    std::vector<uint8_t> out1, out2;
    ASSERT_TRUE(HashToCurveSM2(group.g, (const uint8_t*)dst.data(), dst.size(),
                               (const uint8_t*)msg.data(), msg.size(), out1));
    ASSERT_TRUE(HashToCurveSM2(group.g, (const uint8_t*)dst.data(), dst.size(),
                               (const uint8_t*)msg.data(), msg.size(), out2));

    // Deterministic: outputs identical
    EXPECT_EQ(out1.size(), out2.size());
    EXPECT_EQ(out1, out2);

    // Ensure point is on curve (redundant because HashToCurveSM2 checks it) by reconstructing point
    ECPointPtr pt(EC_POINT_new(group.g));
    ASSERT_NE(pt.p, nullptr);
    ASSERT_EQ(EC_POINT_oct2point(group.g, pt.p, out1.data(), out1.size(), NULL), 1);
    EXPECT_EQ(EC_POINT_is_at_infinity(group.g, pt.p), 0);
    EXPECT_EQ(EC_POINT_is_on_curve(group.g, pt.p, NULL), 1);
}

TEST(ECHashToCurveSM2, DifferentMessagesProduceDifferentPoints) {
    ECGroupPtr group(EC_GROUP_new_by_curve_name(NID_sm2));
    ASSERT_NE(group.g, nullptr);

    const std::string dst = "TEST_DST_SM3_SSWU";
    const std::string msg1 = "message one";
    const std::string msg2 = "message two";

    std::vector<uint8_t> out1, out2;
    ASSERT_TRUE(HashToCurveSM2(group.g, (const uint8_t*)dst.data(), dst.size(),
                               (const uint8_t*)msg1.data(), msg1.size(), out1));
    ASSERT_TRUE(HashToCurveSM2(group.g, (const uint8_t*)dst.data(), dst.size(),
                               (const uint8_t*)msg2.data(), msg2.size(), out2));

    // Very small probability of collision; assert inequality for sanity
    EXPECT_NE(out1, out2);
}

TEST(ECHashToCurveSM2, EmptyMessageAccepted) {
    ECGroupPtr group(EC_GROUP_new_by_curve_name(NID_sm2));
    ASSERT_NE(group.g, nullptr);

    const std::string dst = "DST_EMPTY_MSG";
    const std::string msg = "";

    std::vector<uint8_t> out;
    EXPECT_TRUE(HashToCurveSM2(group.g, (const uint8_t*)dst.data(), dst.size(),
                               (const uint8_t*)msg.data(), msg.size(), out));
    EXPECT_FALSE(out.empty());
}

TEST(ECHashToCurveSM2, WrongGroupRejected) {
    // Use P-256 group which should be rejected by the sm2-specific entrypoint
    ECGroupPtr wrong_group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    ASSERT_NE(wrong_group.g, nullptr);

    const std::string dst = "DST";
    const std::string msg = "msg";

    // Prepare an EC_POINT to call the low-level EC_hash_to_curve_sm2p256v1_xmd_sm3_sswu
    EC_POINT* pt = EC_POINT_new(wrong_group.g);
    ASSERT_NE(pt, nullptr);
    ECPointPtr pt_guard(pt);

    // Expect failure (function checks group curve name)
    int ret = EC_hash_to_curve_sm2p256v1_xmd_sm3_sswu(wrong_group.g, pt, (const uint8_t*)dst.data(), dst.size(),
                                                     (const uint8_t*)msg.data(), msg.size());
    EXPECT_EQ(ret, 0);
    // Optionally check that an error was pushed
    unsigned long err = ERR_peek_last_error();
    EXPECT_NE(err, 0UL);
    // Clear error queue for test hygiene
    ERR_clear_error();
}