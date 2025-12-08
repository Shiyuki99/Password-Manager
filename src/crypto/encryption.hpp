#ifndef CRYPTO_ENCRYPTION_HPP
#define CRYPTO_ENCRYPTION_HPP

#include "../core/types.hpp"
#include "../core/entry.hpp"

// Encryption size constants
constexpr int TAG_SIZE = crypto_aead_chacha20poly1305_ietf_ABYTES;
constexpr int NONCE_SIZE = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;

/**
 * @brief Encrypt an Entry struct using ChaCha20-Poly1305
 * @param key Symmetric key for encryption
 * @param entry Entry struct to encrypt
 * @param out_buff Output buffer: [NONCE][CIPHERTEXT+TAG]
 */
void encrypt_entry(
    const unsigned char *key,
    const Entry &entry,
    std::vector<unsigned char> &out_buff) {

    unsigned char nonce[NONCE_SIZE];
    randombytes_buf(nonce, sizeof(nonce));

    // Encrypt the raw Entry struct bytes
    const unsigned char *plaintext = reinterpret_cast<const unsigned char *>(&entry);
    size_t plaintext_len = sizeof(Entry);

    std::vector<unsigned char> ciphertext(plaintext_len + TAG_SIZE);
    unsigned long long clen;

    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(), &clen,
        plaintext, plaintext_len,
        nullptr, 0,
        nullptr,
        nonce,
        key);

    // Output buffer: [NONCE (12 bytes)][CIPHERTEXT + TAG]
    out_buff.clear();
    out_buff.reserve(NONCE_SIZE + clen);

    // Copy nonce first
    out_buff.insert(out_buff.end(), nonce, nonce + NONCE_SIZE);

    // Then copy ciphertext
    out_buff.insert(out_buff.end(), ciphertext.begin(), ciphertext.begin() + clen);
}

/**
 * @brief Decrypt data back into an Entry struct using ChaCha20-Poly1305
 * @param key Symmetric key for decryption
 * @param entry Output Entry struct
 * @param cipher Input buffer containing [NONCE][CIPHERTEXT+TAG]
 * @param cipher_len Length of the input buffer
 */
void decrypt_entry(
    const unsigned char *key,
    Entry &entry,
    const unsigned char *cipher,
    size_t cipher_len) {

    // Buffer layout: [NONCE (12 bytes)][CIPHERTEXT + TAG]
    const unsigned char *nonce = cipher;
    const unsigned char *ciphertext = cipher + NONCE_SIZE;
    size_t ciphertext_len = cipher_len - NONCE_SIZE;

    // Decrypt into Entry-sized buffer
    std::vector<unsigned char> plaintext(sizeof(Entry));
    unsigned long long plen;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext.data(), &plen,
            nullptr,
            ciphertext, ciphertext_len,
            nullptr, 0,
            nonce,
            key) != 0) {
        throw std::runtime_error("decrypt failed");
    }

    // Copy decrypted data to Entry struct
    if (plen != sizeof(Entry)) {
        throw std::runtime_error("decrypted size mismatch");
    }
    std::memcpy(&entry, plaintext.data(), sizeof(Entry));
}

#endif // CRYPTO_ENCRYPTION_HPP
