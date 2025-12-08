#ifndef VAULT_HEADER_HPP
#define VAULT_HEADER_HPP

#include "../core/types.hpp"
#include "../core/constants.hpp"
#include "../crypto/hashing.hpp"

/**
 * @brief Struct representing the vault file header
 */
struct VaultHeader {
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
};

#endif // VAULT_HEADER_HPP
