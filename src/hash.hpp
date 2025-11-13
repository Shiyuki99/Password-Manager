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