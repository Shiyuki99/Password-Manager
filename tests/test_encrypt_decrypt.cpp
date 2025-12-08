#include <gtest/gtest.h>
#include <sodium.h>
#include <cstring>

#include "core/constants.hpp"
#include "core/types.hpp"
#include "core/entry.hpp"
#include "crypto/encryption.hpp"

class EncryptDecryptTest : public ::testing::Test {
protected:
    unsigned char key[crypto_secretbox_KEYBYTES];

    void SetUp() override {
        if (sodium_init() < 0) {
            FAIL() << "Failed to initialize libsodium";
        }
        // Generate a random key for testing
        randombytes_buf(key, sizeof(key));
    }
};

// Test basic encrypt/decrypt roundtrip
TEST_F(EncryptDecryptTest, BasicRoundtrip) {
    Entry original;
    original.setName("TestEntry");
    original.setUsername("testuser");
    original.setWebsite("https://example.com");
    original.setPassword("supersecretpassword123");
    original.setNotes("Some notes here");
    original.Modf_Time = time(nullptr);

    // Encrypt
    std::vector<unsigned char> encrypted;
    encrypt_entry(key, original, encrypted);

    // Verify encrypted size
    EXPECT_EQ(encrypted.size(), NONCE_SIZE + sizeof(Entry) + TAG_SIZE);

    // Decrypt
    Entry decrypted;
    decrypt_entry(key, decrypted, encrypted.data(), encrypted.size());

    // Verify all fields match
    EXPECT_STREQ(decrypted.Name, original.Name);
    EXPECT_STREQ(decrypted.Username, original.Username);
    EXPECT_STREQ(decrypted.Website, original.Website);
    EXPECT_STREQ(decrypted.Password, original.Password);
    EXPECT_STREQ(decrypted.Notes, original.Notes);
    EXPECT_EQ(decrypted.Modf_Time, original.Modf_Time);
}

// Test that encryption produces different output each time (due to random nonce)
TEST_F(EncryptDecryptTest, DifferentNonces) {
    Entry original;
    original.setName("TestEntry");
    original.setPassword("password");

    std::vector<unsigned char> encrypted1;
    std::vector<unsigned char> encrypted2;

    encrypt_entry(key, original, encrypted1);
    encrypt_entry(key, original, encrypted2);

    // Should have same size
    EXPECT_EQ(encrypted1.size(), encrypted2.size());

    // But different content (due to random nonce)
    EXPECT_NE(encrypted1, encrypted2);

    // Both should decrypt to same entry
    Entry decrypted1, decrypted2;
    decrypt_entry(key, decrypted1, encrypted1.data(), encrypted1.size());
    decrypt_entry(key, decrypted2, encrypted2.data(), encrypted2.size());

    EXPECT_STREQ(decrypted1.Name, decrypted2.Name);
    EXPECT_STREQ(decrypted1.Password, decrypted2.Password);
}

// Test with empty fields
TEST_F(EncryptDecryptTest, EmptyFields) {
    Entry original;
    // All fields are empty by default

    std::vector<unsigned char> encrypted;
    encrypt_entry(key, original, encrypted);

    Entry decrypted;
    decrypt_entry(key, decrypted, encrypted.data(), encrypted.size());

    EXPECT_STREQ(decrypted.Name, "");
    EXPECT_STREQ(decrypted.Username, "");
    EXPECT_STREQ(decrypted.Website, "");
    EXPECT_STREQ(decrypted.Password, "");
    EXPECT_STREQ(decrypted.Notes, "");
}

// Test with max length fields
TEST_F(EncryptDecryptTest, MaxLengthFields) {
    Entry original;

    // Create max-length strings
    std::string maxName(ENTRY_NAME_SIZE - 1, 'A');
    std::string maxUsername(ENTRY_USERNAME_SIZE - 1, 'B');
    std::string maxWebsite(ENTRY_WEBSITE_SIZE - 1, 'C');
    std::string maxPassword(ENTRY_PASSWORD_SIZE - 1, 'D');
    std::string maxNotes(ENTRY_NOTES_SIZE - 1, 'E');

    original.setName(maxName);
    original.setUsername(maxUsername);
    original.setWebsite(maxWebsite);
    original.setPassword(maxPassword);
    original.setNotes(maxNotes);

    std::vector<unsigned char> encrypted;
    encrypt_entry(key, original, encrypted);

    Entry decrypted;
    decrypt_entry(key, decrypted, encrypted.data(), encrypted.size());

    EXPECT_STREQ(decrypted.Name, maxName.c_str());
    EXPECT_STREQ(decrypted.Username, maxUsername.c_str());
    EXPECT_STREQ(decrypted.Website, maxWebsite.c_str());
    EXPECT_STREQ(decrypted.Password, maxPassword.c_str());
    EXPECT_STREQ(decrypted.Notes, maxNotes.c_str());
}

// Test with special characters
TEST_F(EncryptDecryptTest, SpecialCharacters) {
    Entry original;
    original.setName("Test!@#$%^&*()");
    original.setUsername("user\twith\ttabs");
    original.setWebsite("https://example.com/path?query=value&other=123");
    original.setPassword("p@$$w0rd!\"'<>");
    original.setNotes("Notes with\nnewlines\nand unicode: 日本語");

    std::vector<unsigned char> encrypted;
    encrypt_entry(key, original, encrypted);

    Entry decrypted;
    decrypt_entry(key, decrypted, encrypted.data(), encrypted.size());

    EXPECT_STREQ(decrypted.Name, original.Name);
    EXPECT_STREQ(decrypted.Username, original.Username);
    EXPECT_STREQ(decrypted.Website, original.Website);
    EXPECT_STREQ(decrypted.Password, original.Password);
    EXPECT_STREQ(decrypted.Notes, original.Notes);
}

// Test decryption with wrong key fails
TEST_F(EncryptDecryptTest, WrongKeyFails) {
    Entry original;
    original.setName("Secret");
    original.setPassword("topsecret");

    std::vector<unsigned char> encrypted;
    encrypt_entry(key, original, encrypted);

    // Generate a different key
    unsigned char wrongKey[crypto_secretbox_KEYBYTES];
    randombytes_buf(wrongKey, sizeof(wrongKey));

    Entry decrypted;
    EXPECT_THROW(
        decrypt_entry(wrongKey, decrypted, encrypted.data(), encrypted.size()),
        std::runtime_error
    );
}

// Test decryption with corrupted data fails
TEST_F(EncryptDecryptTest, CorruptedDataFails) {
    Entry original;
    original.setName("Secret");

    std::vector<unsigned char> encrypted;
    encrypt_entry(key, original, encrypted);

    // Corrupt a byte in the middle
    encrypted[encrypted.size() / 2] ^= 0xFF;

    Entry decrypted;
    EXPECT_THROW(
        decrypt_entry(key, decrypted, encrypted.data(), encrypted.size()),
        std::runtime_error
    );
}

// Test that sizeof(Entry) matches expected value
TEST_F(EncryptDecryptTest, EntrySizeCheck) {
    std::cout << "sizeof(Entry) = " << sizeof(Entry) << std::endl;
    std::cout << "ENTRY_SIZE = " << ENTRY_SIZE << std::endl;
    std::cout << "ENCRYPTED_ENTRY_SIZE = " << ENCRYPTED_ENTRY_SIZE << std::endl;

    // Verify ENCRYPTED_ENTRY_SIZE is correct
    size_t expected_encrypted_size = NONCE_SIZE + sizeof(Entry) + TAG_SIZE;
    std::cout << "Expected encrypted size = " << expected_encrypted_size << std::endl;

    EXPECT_EQ(ENCRYPTED_ENTRY_SIZE, expected_encrypted_size);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
