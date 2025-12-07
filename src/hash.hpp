#ifndef HASH_HPP
#define HASH_HPP

#include "stdlib_inc.hpp"
#include "const.hpp"
#include "json.hpp"

// Using nlohmann json namespace
using json = nlohmann::json;

constexpr int SALT_SIZE = crypto_pwhash_SALTBYTES;
constexpr int TAG_SIZE = crypto_aead_chacha20poly1305_ietf_ABYTES;
constexpr int HASH_SIZE = crypto_pwhash_STRBYTES;
constexpr int NONCE_SIZE = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;

// Hash password using Argon2id
std::string argon2id_Hash(std::string passwd) {
   char argon2id[crypto_pwhash_STRBYTES];
   if (crypto_pwhash_argon2id_str(
      argon2id,
      passwd.c_str(),
      passwd.length(),
      crypto_pwhash_OPSLIMIT_SENSITIVE,
      crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
      throw std::runtime_error("Password hashing failed");
   }
   std::string output = argon2id;
   return output;
}

// Verify password against hash - adapted for JSON interface
json argon2id_Verifier(std::string stored_hash, std::string input_password) {
   json response;

   try {
      if (crypto_pwhash_argon2id_str_verify(
         stored_hash.c_str(),
         input_password.c_str(),
         input_password.length()) == 0) {
         response["success"] = true;
         response["message"] = "Password verified successfully";
      } else {
         response["success"] = false;
         response["error"] = "Password verification failed";
      }
   }
   catch (const std::exception &e) {
      response["success"] = false;
      response["error"] = std::string("Exception during password verification: ") + e.what();
   }

   return response;
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

/**
 * @brief Encrypt data using ChaCha20-Poly1305 with fixed-size output
 *
 * @param key Symmetric key for encryption
 * @param plaintext Data to be encrypted
 * @param out_buff Output buffer for the encrypted data (ENTRY_SIZE bytes total)
 * @param max_output_size Maximum allowed size for output
 */
void encrypt_data(
   const unsigned char *key,
   const std::string &plaintext,
   std::vector<unsigned char> &out_buff) {

   unsigned char nonce[NONCE_SIZE];
   randombytes_buf(nonce, sizeof(nonce));

   std::vector<unsigned char> ciphertext(plaintext.size() + TAG_SIZE);

   unsigned long long clen;

   crypto_aead_chacha20poly1305_ietf_encrypt(
      ciphertext.data(), &clen,
      (const unsigned char *)plaintext.data(), plaintext.size(),
      nullptr, 0,
      nullptr,
      nonce,
      key);

   // Create output buffer with fixed size ENCRYPTED_ENTRY_SIZE
   out_buff.clear();
   out_buff.resize(ENCRYPTED_ENTRY_SIZE, 0); // Initialize with zeros

   // Copy nonce first
   std::copy(nonce, nonce + NONCE_SIZE, out_buff.begin());

   // Then copy ciphertext after nonce
   std::copy(ciphertext.begin(), ciphertext.begin() + clen, out_buff.begin() + NONCE_SIZE);

}


/**
 * @brief Decrypt data using ChaCha20-Poly1305 expecting fixed-size input
 *
 * @param key Symmetric key for decryption
 * @param out_buff Output buffer for the decrypted data
 * @param cipher Input buffer containing nonce + ciphertext (fixed ENTRY_SIZE)
 * @param cipher_len Length of the input buffer
 */
void decrypt_data(
   const unsigned char *key,
   std::string &out_buff,
   const unsigned char *cipher,
   unsigned long long cipher_len) {



   const unsigned char *nonce = cipher;
   const unsigned char *ciphertext = cipher + NONCE_SIZE;



   // Try to decrypt with the actual ciphertext length
   std::vector<unsigned char> plaintext(ENTRY_SIZE + NONCE_SIZE); // allocate enough space

   unsigned long long plen;

   if (crypto_aead_chacha20poly1305_ietf_decrypt(
      plaintext.data(), &plen,
      nullptr,
      ciphertext, cipher_len, // use actual length
      nullptr, 0,
      nonce,
      key) != 0) {
      throw std::runtime_error("decrypt failed");
   }

   plaintext.resize(plen);
   out_buff.assign(plaintext.begin(), plaintext.end());
}

#endif