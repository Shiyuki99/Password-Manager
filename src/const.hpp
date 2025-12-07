#ifndef CONST_HPP
#define CONST_HPP

constexpr size_t SIGNATURE_SIZE = 8;
constexpr size_t VERSION_SIZE = 8;
constexpr size_t NAME_SIZE = 32;
constexpr size_t PASSWORD_SIZE = 32;
constexpr size_t HEADER_SIZE = 128;
constexpr size_t ENTRY_NAME_SIZE = 32;
constexpr size_t ENTRY_USERNAME_SIZE = 32;
constexpr size_t ENTRY_WEBSITE_SIZE = 64;
constexpr size_t ENTRY_PASSWORD_SIZE = 64;
constexpr size_t ENTRY_NOTES_SIZE = 128;
constexpr size_t ENTRY_SIZE = ENTRY_NAME_SIZE + ENTRY_USERNAME_SIZE + ENTRY_WEBSITE_SIZE + ENTRY_PASSWORD_SIZE + ENTRY_NOTES_SIZE;
// Encrypted entry size: NONCE(12) + JSON(~2000 with escaped nulls) + TAG(16)
// JSON escapes null bytes as \u0000 (6 chars each), so worst case is ~6x raw size
constexpr size_t ENCRYPTED_ENTRY_SIZE = 2048;
constexpr char SIGNATURE[SIGNATURE_SIZE] = "SHPD";
constexpr char CURR_VERSION[VERSION_SIZE] = "0.1";
#endif