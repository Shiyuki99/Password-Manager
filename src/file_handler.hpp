#ifndef FILE_HANDLER
#define FILE_HANDLER

#include <string>
#include <vector>
#include <iostream>
#include <vector>
#include <chrono>
#include <fstream>

const int SIGNATURE_SIZE = 8;
const int VERSION_SIZE = 8;
const int NAME_SIZE = 32;
const int HEADER_SIZE = 128;

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

   void write(std::ostream &out) const {
      out.write(signature, sizeof(signature));
      out.write(version, sizeof(version));
      out.write(name, sizeof(name));
      out.write(reinterpret_cast<const char *>(&entries), sizeof(entries));
      out.write(reinterpret_cast<const char *>(&created), sizeof(created));
      out.write(reinterpret_cast<const char *>(&updated), sizeof(updated));
   }

   void read(std::istream &in) {
      in.read(signature, sizeof(signature));
      in.read(version, sizeof(version));
      in.read(name, sizeof(name));
      in.read(reinterpret_cast<char *>(&entries), sizeof(entries));
      in.read(reinterpret_cast<char *>(&created), sizeof(created));
      in.read(reinterpret_cast<char *>(&updated), sizeof(updated));
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

public:
   void *buffer = nullptr;
   void Open(std::string file_path) {
      file.open(file_path, std::ios::in | std::ios::out | std::ios::binary);
      header.read(file);
   }


};
#endif