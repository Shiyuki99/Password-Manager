#ifndef CORE_CONSTANTS_HPP
#define CORE_CONSTANTS_HPP

#include <cstddef>
#include <ctime>

// Vault file format constants
constexpr size_t SIGNATURE_SIZE = 8;
constexpr size_t VERSION_SIZE = 8;
constexpr size_t NAME_SIZE = 32;
constexpr size_t PASSWORD_SIZE = 32;
constexpr size_t HEADER_SIZE = 128;

// Entry field size constants
constexpr size_t ENTRY_NAME_SIZE = 32;
constexpr size_t ENTRY_USERNAME_SIZE = 32;
constexpr size_t ENTRY_WEBSITE_SIZE = 64;
constexpr size_t ENTRY_PASSWORD_SIZE = 64;
constexpr size_t ENTRY_NOTES_SIZE = 128;
constexpr size_t ENTRY_SIZE = ENTRY_NAME_SIZE + ENTRY_USERNAME_SIZE + ENTRY_WEBSITE_SIZE + ENTRY_PASSWORD_SIZE + ENTRY_NOTES_SIZE + sizeof(time_t);

// Encrypted entry size: NONCE(12) + sizeof(Entry) + TAG(16)
// sizeof(Entry) = 320 (fields) + 8 (time_t) = 328, plus NONCE + TAG = 356
constexpr size_t ENCRYPTED_ENTRY_SIZE = 356;

// Vault file signature and version
constexpr char SIGNATURE[SIGNATURE_SIZE] = "SHPD";
constexpr char CURR_VERSION[VERSION_SIZE] = "0.1";

#endif // CORE_CONSTANTS_HPP
