#ifndef HASH_HPP
#define HASH_HPP

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string>
#include <vector>
#include <iostream>
#include <vector>
#include <iomanip>

/**
 * @brief Returns sha3_256 hash of the input string
 *
 * @param input String data to hash
 *
 */
std::string hash_sha3_256(const std::string &input) {

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

}
#endif