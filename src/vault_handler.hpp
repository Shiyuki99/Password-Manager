#ifndef VAULT_HANDLER
#define VAULT_HANDLER

#include <string>
#include <vector>
#include <iostream>
#include <vector>
#include <chrono>
#include <fstream>
#include "hash.hpp"
#include "utils.hpp"

constexpr int SIGNATURE_SIZE = 8;
constexpr int VERSION_SIZE = 8;
constexpr int NAME_SIZE = 32;
constexpr int PASSWORD_SIZE = 32;
constexpr int SALT_SIZE = crypto_pwhash_SALTBYTES;
constexpr int HEADER_SIZE = 128;
constexpr int ENTRY_SIZE = 256;

/**
 * @brief Store vault header metadata
 * @param signature, version, name, entries,created, updated
 *
 *
 */
typedef struct VaultHeader {
   char signature[SIGNATURE_SIZE];
   char version[VERSION_SIZE];
   char name[NAME_SIZE];
   size_t entries;
   time_t created;
   time_t updated;
   unsigned char salt[SALT_SIZE];

   void write(std::ostream &out) const {
      out.write(signature, sizeof(signature));
      out.write(version, sizeof(version));
      out.write(name, sizeof(name));
      out.write(reinterpret_cast<const char *>(&entries), sizeof(entries));
      out.write(reinterpret_cast<const char *>(&created), sizeof(created));
      out.write(reinterpret_cast<const char *>(&updated), sizeof(updated));
      out.write(reinterpret_cast<const char *>(salt), sizeof(salt));
   }

   void read(std::istream &in) {
      in.read(signature, sizeof(signature));
      in.read(version, sizeof(version));
      in.read(name, sizeof(name));
      in.read(reinterpret_cast<char *>(&entries), sizeof(entries));
      in.read(reinterpret_cast<char *>(&created), sizeof(created));
      in.read(reinterpret_cast<char *>(&updated), sizeof(updated));
      in.read(reinterpret_cast<char *>(salt), sizeof(salt));
   }
} VaultHeader;


/**
 * @brief Class to handle passwords vault.
 *
 */
class vault_handler {

   vault_handler() {}
   ~vault_handler() { file.close(); free(buffer); }

private:
   std::fstream file;
   VaultHeader header;
   std::string passwd;
   std::vector<std::string> entries;
   const unsigned char *key;
   unsigned char *nonce;

public:
   void *buffer = nullptr;

   void Open(std::string file_path) {
      file.open(file_path, std::ios::in | std::ios::out | std::ios::binary);
      header.read(file);
   }

   bool Authenticate() {
      bool auth = false;
      std::cout << "Enter password(press q to quit): ";
      std::string input_passwd;
      input_passwd = safe_input(PASSWORD_SIZE);
      if (argon2id_Verifier(argon2id_Hash(input_passwd)) == 0) {
         auth = true;
      }
      if (input_passwd == "q" || input_passwd == "Q") {
         return false;
      }
      while (!auth) {
         std::cout << "Enter password(press q to quit): ";
         input_passwd = safe_input(PASSWORD_SIZE);
         if (argon2id_Verifier(argon2id_Hash(input_passwd)) == 0) {
            auth = true;
         }
         if (input_passwd == "q" || input_passwd == "Q") {
            return false;
         }
      }
      passwd = input_passwd;
      return auth;
   }

   void LoadData() {
      file.seekg(HEADER_SIZE + HASH_SIZE, std::ios::beg);
      std::vector<std::string> dec_entries;

      for (size_t i = 0; i < header.entries; i++) {
         std::vector<unsigned char> entry_buffer(ENTRY_SIZE + TAG_SIZE);
         if (!file.read(reinterpret_cast<char *>(entry_buffer.data()), ENTRY_SIZE + TAG_SIZE)) {
            std::cerr << "Failed to read entry " << i << std::endl;
            std::cerr << "Only " << file.gcount() << " bytes were read." << std::endl;
            break;
         }
         decrypt_data(
            key,
            reinterpret_cast<unsigned char *>(dec_entries[i].data()),
            nullptr,
            entry_buffer.data(),
            0,
            nonce
         );
      }
      // Decrypt entries here and store in entries vector
      // ...
   }

   void AddEntry() {}


};
#endif