#include <string>
#include "gtest/gtest.h"
#include "private_join_and_compute/crypto/context.h"
#include <iomanip>
#include <sstream>

namespace {

class SM3Test : public ::testing::Test {
protected:
    private_join_and_compute::Context context;
    
    // Helper function to convert bytes to hex string
    std::string BytesToHexString(const std::string& bytes) {
        std::stringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0');
        for (unsigned char c : bytes) {
            ss << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
        }
        return ss.str();
    }
};

TEST_F(SM3Test, BasicStrings) {
    // Test "hello"
    EXPECT_EQ(BytesToHexString(context.Sm3String("hello")),
              "BECBBFAAE6548B8BF0CFCAD5A27183CD1BE6093B1CCECCC303D9C61D0A645268");
              
    // Test "ABCDE"
    EXPECT_EQ(BytesToHexString(context.Sm3String("ABCDE")),
              "3D3C180892E9F4B1F0A311F30AEDDA636B3C1D8EACA4EB76A158117A729898AC");
}

TEST_F(SM3Test, UTF8String) {
    // Test UTF8 string "你好"
    EXPECT_EQ(BytesToHexString(context.Sm3String("你好")),
              "78E5C78C5322CA174089E58DC7790ACF8CE9D542BEE6AE4A5A0797D5E356BE61");
}

TEST_F(SM3Test, EmptyString) {
    EXPECT_NO_THROW(context.Sm3String(""));
    // Note: Add specific hash value for empty string if known
}

TEST_F(SM3Test, LongString) {
    std::string long_text = "This small book contains a fairy tale,a story about many things."
                           "First of all,Innocence of Childhood and love.The prince loves his roses,"
                           "but felt disappointed by something the rose said.As doubt grows, he decides "
                           "to explore other planet.The little prince discovers that his rose is not "
                           "the only one of its kind,there are thousands of them in a garden,but then "
                           "he realizes that his rose is special \"because it is she that I have watered; "
                           "because it is she that I have put under the glass globe; because it is she "
                           "that I have sheltered behind the screen\".The fox teaches the prince \"It "
                           "is only with the heart that one can see rightly;what is essential is invisible "
                           "to the eye \"";
                           
    EXPECT_EQ(BytesToHexString(context.Sm3String(long_text)),
              "FC17B7051C7274AF272F6D2C8D1F674E9387C78614891074B938CDDDBF4440CC");
}

TEST_F(SM3Test, SpecialCharacters) {
    EXPECT_NO_THROW(context.Sm3String("!@#$%^&*()_+"));
    EXPECT_NO_THROW(context.Sm3String("\n\t\r"));
}

TEST_F(SM3Test, ConsistentResults) {
    // Same input should produce same hash
    std::string input = "test string";
    std::string hash1 = context.Sm3String(input);
    std::string hash2 = context.Sm3String(input);
    EXPECT_EQ(hash1, hash2);
}

} // namespace