#ifndef VAULT_HANDLER_HPP
#define VAULT_HANDLER_HPP

#include "hash.hpp"
#include "utils.hpp"
#include "json.hpp"
#include <fstream>
#include <sstream>
#include <cstring>

using json = nlohmann::json;

typedef struct VaultHeader {
   char signature[SIGNATURE_SIZE]{};
   char version[VERSION_SIZE]{};
   char hash[HASH_SIZE]{};
   unsigned char salt[SALT_SIZE]{};
   char name[NAME_SIZE]{};
   size_t entries{};
   time_t created{};
   time_t updated{};

   VaultHeader() {
      std::memcpy(signature, SIGNATURE, SIGNATURE_SIZE);
      std::memcpy(version, CURR_VERSION, VERSION_SIZE);
      created = std::time(nullptr);
      updated = created;
      entries = 0;
   }

   VaultHeader(const char *vault_name) : VaultHeader() {
      std::strncpy(name, vault_name, NAME_SIZE - 1);
      name[NAME_SIZE - 1] = '\0';
   }

   void write(std::ostream &out) const {
      out.write(reinterpret_cast<const char *>(this), sizeof(VaultHeader));
   }

   void read(std::istream &in) {
      in.read(reinterpret_cast<char *>(this), sizeof(VaultHeader));
   }
} VaultHeader;


class vault_handler {
private:
   std::fstream file;
   VaultHeader header;
   std::vector<Entry> entries;
   unsigned char key[crypto_secretbox_KEYBYTES];
   bool authenticated = false;
   std::string file_path;

public:
   ~vault_handler() {
      if (file.is_open()) {
         file.close();
      }
   }

   json Create(const std::string &path, const std::string &password, const std::string &vault_name = "Vault") {
      json response;

      if (std::filesystem::exists(path)) {
         response["success"] = false;
         response["error"] = "File already exists: " + path;
         return response;
      }

      std::ofstream out(path, std::ios::binary);
      if (!out.is_open()) {
         response["success"] = false;
         response["error"] = "Failed to create file: " + path;
         return response;
      }

      VaultHeader new_header;
      if (!vault_name.empty()) {
         std::strncpy(new_header.name, vault_name.c_str(), NAME_SIZE - 1);
         new_header.name[NAME_SIZE - 1] = '\0';
      }

      randombytes_buf(new_header.salt, SALT_SIZE);
      std::string hashed = argon2id_Hash(password);
      std::memcpy(new_header.hash, hashed.c_str(), HASH_SIZE);

      new_header.write(out);
      out.close();

      // Open the file and set up the handler
      file.open(path, std::ios::in | std::ios::out | std::ios::binary);
      if (!file.is_open()) {
         response["success"] = false;
         response["error"] = "Failed to open file after creation";
         return response;
      }

      header = new_header;
      file_path = path;

      // Derive key for encryption
      if (!derive_key_from_password(password, header.salt, key)) {
         file.close();
         response["success"] = false;
         response["error"] = "Failed to derive key";
         return response;
      }

      authenticated = true;

      response["success"] = true;
      response["message"] = "Vault created successfully";
      response["name"] = std::string(header.name, strnlen(header.name, NAME_SIZE));
      response["entries"] = header.entries;
      return response;
   }

   json Open(const std::string &path) {
      json response;

      if (!std::filesystem::exists(path)) {
         response["success"] = false;
         response["error"] = "File does not exist: " + path;
         return response;
      }

      file.open(path, std::ios::in | std::ios::out | std::ios::binary);
      if (!file.is_open()) {
         response["success"] = false;
         response["error"] = "Failed to open file: " + path;
         return response;
      }

      header.read(file);
      file_path = path;

      if (std::strncmp(header.signature, SIGNATURE, SIGNATURE_SIZE) != 0) {
         file.close();
         response["success"] = false;
         response["error"] = "Invalid vault file";
         return response;
      }

      response["success"] = true;
      response["name"] = std::string(header.name, strnlen(header.name, NAME_SIZE));
      response["entries"] = header.entries;
      return response;
   }

   json Authenticate(const std::string &password) {
      json response;

      if (!file.is_open()) {
         response["success"] = false;
         response["error"] = "No vault is open";
         return response;
      }

      int result = crypto_pwhash_argon2id_str_verify(header.hash, password.c_str(), password.length());
      if (result != 0) {
         response["success"] = false;
         response["error"] = "Invalid password";
         return response;
      }

      if (!derive_key_from_password(password, header.salt, key)) {
         response["success"] = false;
         response["error"] = "Failed to derive key";
         return response;
      }

      authenticated = true;
      response["success"] = true;
      return response;
   }

   json Close() {
      json response;
      if (file.is_open()) {
         file.close();
      }
      authenticated = false;
      entries.clear();
      response["success"] = true;
      return response;
   }

   bool IsOpen() const { return file.is_open(); }
   bool IsAuthenticated() const { return authenticated; }

   json LoadEntries() {
      json response;

      if (!file.is_open()) {
         response["success"] = false;
         response["error"] = "No vault is open";
         return response;
      }

      if (!authenticated) {
         response["success"] = false;
         response["error"] = "Not authenticated";
         return response;
      }

      entries.clear();

      for (size_t i = 0; i < header.entries; i++) {
         size_t offset = sizeof(VaultHeader) + (i * ENTRY_SIZE);
         file.seekg(offset);

         unsigned char encrypted[ENTRY_SIZE];
         file.read(reinterpret_cast<char *>(encrypted), ENTRY_SIZE);

         std::string decrypted;
         try {
            decrypt_data(key, decrypted, encrypted, ENTRY_SIZE);
         }
         catch (const std::exception &e) {
            response["success"] = false;
            response["error"] = "Failed to decrypt entry " + std::to_string(i);
            return response;
         }

         Entry entry;
         std::memcpy(&entry, decrypted.data(), sizeof(Entry));
         entries.push_back(entry);
      }

      response["success"] = true;
      response["entries"] = header.entries;
      return response;
   }

   json AddEntry(const Entry &entry) {
      json response;

      if (!file.is_open()) {
         response["success"] = false;
         response["error"] = "No vault is open";
         return response;
      }

      if (!authenticated) {
         response["success"] = false;
         response["error"] = "Not authenticated";
         return response;
      }

      std::string plaintext(reinterpret_cast<const char *>(&entry), sizeof(Entry));

      std::vector<unsigned char> encrypted;
      encrypt_data(key, plaintext, encrypted);

      size_t offset = sizeof(VaultHeader) + (header.entries * ENTRY_SIZE);
      file.seekp(offset);
      file.write(reinterpret_cast<const char *>(encrypted.data()), encrypted.size());

      header.entries++;
      header.updated = std::time(nullptr);

      file.seekp(0);
      header.write(file);
      file.flush();

      entries.push_back(entry);

      response["success"] = true;
      response["entries"] = header.entries;
      return response;
   }

   const std::vector<Entry> &GetEntries() const { return entries; }
};

#endif