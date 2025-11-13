#ifndef HASH_HPP
#define HASH_HPP

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string>
#include <vector>
#include <iostream>
#include <vector>
#include <iomanip>
#include <sodium.h>
#include "vault_handler.hpp"

constexpr int TAG_SIZE = crypto_aead_chacha20poly1305_ietf_ABYTES;
constexpr int HASH_SIZE = crypto_pwhash_STRBYTES;
constexpr int NONCE_SIZE = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;

//string <- char*
std::string argon2id_Hash(std::string passwd) {
   char argon2id[crypto_pwhash_STRBYTES];
   if (crypto_pwhash_argon2id_str(
      argon2id,
      passwd.c_str(),
      passwd.length(),
      crypto_pwhash_OPSLIMIT_SENSITIVE,
      crypto_pwhash_MEMLIMIT_SENSITIVE) != 0)
      std::cerr << "something went wrong!" << std::endl;
   std::string output = argon2id;
   return output;
}

int argon2id_Verifier(std::string hash) {
   std::string passwd = "";

   std::cout << "Please Enter The Password: ";
   std::cin >> passwd;

   while (crypto_pwhash_argon2id_str_verify(
      hash.c_str(),
      passwd.c_str(),
      passwd.length())) {
      std::cout << "Wrong password! Try Again: " << std::endl;
      std::cin >> passwd;
   }

   return 0;
}

/**
 * @brief Generate a symmetric key from a password using Argon2id
 *
 * @param password Input password
 * @param salt Salt value used in key derivation
 * @param key Output buffer for the derived key
 * @return true if key derivation is successful
 * @return false if key derivation fails
 */
bool derive_key_from_password(
   const std::string &password,
   const unsigned char *salt,
   unsigned char key[crypto_secretbox_KEYBYTES]) {

   if (crypto_pwhash(
      key, crypto_secretbox_KEYBYTES,
      password.c_str(), password.size(),
      reinterpret_cast<const unsigned char *>(salt),
      crypto_pwhash_OPSLIMIT_MODERATE,
      crypto_pwhash_MEMLIMIT_MODERATE,
      crypto_pwhash_ALG_ARGON2ID13) != 0) {
      std::cerr << "Key derivation failed (out of memory?)" << std::endl;
      return false;
   }
   return true;
}

void encrypt_data(
   const unsigned char *key,
   const std::string &plaintext,
   std::vector<unsigned char> &enc_entry) {


   unsigned char ciphertext[ENTRY_SIZE + TAG_SIZE];
   unsigned long long ciphertext_len = 0;

   unsigned char nonce[NONCE_SIZE];
   randombytes_buf(nonce, NONCE_SIZE);

   crypto_aead_chacha20poly1305_ietf_encrypt(
      ciphertext, &ciphertext_len,
      reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.length(),
      nullptr, 0,
      nullptr,
      nonce,
      key);

   if (ciphertext_len > sizeof(ciphertext)) {
      throw std::runtime_error("Ciphertext too long for buffer");
   }

   enc_entry.clear();
   enc_entry.insert(enc_entry.end(), nonce, nonce + sizeof(nonce));
   enc_entry.insert(enc_entry.end(), ciphertext, ciphertext + ciphertext_len);
}

void decrypt_data(
   const unsigned char *key,
   unsigned char *plaintext,
   unsigned long long *plaintext_len,
   const unsigned char *ciphertext,
   const unsigned long long ciphertext_len,
   unsigned char nonce[NONCE_SIZE]) {

   crypto_aead_chacha20poly1305_decrypt(
      plaintext, plaintext_len,
      nullptr,
      ciphertext, ciphertext_len,
      nullptr, 0,
      nonce,
      key
   );

}

// we don't use this anymore but keep it for reference, just in case xD.
/**
 * @brief Returns sha3_256 hash of the input string
 *
 * @param input String data to hash
 *
 */
 /* std::string hash_sha3_256(const std::string &input) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    // Init AES-256-CBC
    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1) {
       EVP_MD_CTX_free(ctx);
       return "";
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;


    if (EVP_DigestUpdate(ctx, input.data(), input.size()) != 1) {
       EVP_MD_CTX_free(ctx);
       std::cerr << "DIGEST UPDATE FAILED" << std::endl;
       return "";
    }


    if (EVP_DigestFinal_ex(ctx, hash, &len) != 1) {
       EVP_MD_CTX_free(ctx);
       std::cerr << "DIGEST UPDATE FAILED" << std::endl;

       return "";
    }

    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto i = 0; i < len; i++) {
       oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();

 } */
#endif