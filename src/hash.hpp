#ifndef HASH_HPP
#define HASH_HPP

#include "stdlib_inc.hpp"
#include "const.hpp"

constexpr int SALT_SIZE = crypto_pwhash_SALTBYTES;
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

/**
 * @brief Encrypt data using ChaCha20-Poly1305
 *
 * @param key Symmetric key for encryption
 * @param plaintext Data to be encrypted
 * @param out_buff Output buffer for the encrypted data (nonce + ciphertext)
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

   ciphertext.resize(clen);

   out_buff.clear();
   out_buff.insert(out_buff.end(), nonce, nonce + sizeof(nonce));
   out_buff.insert(out_buff.end(), ciphertext.begin(), ciphertext.end());
}


/**
 * @brief Decrypt data using ChaCha20-Poly1305
 *
 * @param key Symmetric key for decryption
 * @param out_buff Output buffer for the decrypted data
 * @param cipher Input buffer containing nonce + ciphertext
 * @param cipher_len Length of the input buffer
 */
void decrypt_data(
   const unsigned char *key,
   std::string &out_buff,
   const unsigned char *cipher,
   unsigned long long cipher_len) {


   const unsigned char *nonce = cipher;
   const unsigned char *c = cipher + NONCE_SIZE;

   unsigned long long clen = cipher_len - NONCE_SIZE;

   std::vector<unsigned char> plaintext(clen); // max possible

   unsigned long long plen;

   if (crypto_aead_chacha20poly1305_ietf_decrypt(
      plaintext.data(), &plen,
      nullptr,
      c, clen,
      nullptr, 0,
      nonce,
      key) != 0) {
      throw std::runtime_error("decrypt failed");
   }

   plaintext.resize(plen);
   out_buff.assign(plaintext.begin(), plaintext.end());
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