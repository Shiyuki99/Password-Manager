#ifndef VAULT_VAULT_HPP
#define VAULT_VAULT_HPP

#include "vault_header.hpp"
#include "../core/entry.hpp"
#include "../crypto/encryption.hpp"
#include "../lib/json.hpp"

using json = nlohmann::json;

/**
 * @brief Vault handler class for managing encrypted vault files
 */
class Vault {
private:
    std::fstream file;
    VaultHeader header;
    std::vector<Entry> entries;
    unsigned char key[crypto_secretbox_KEYBYTES];
    bool authenticated = false;
    std::string file_path;

public:
    ~Vault() {
        if (file.is_open()) {
            file.close();
        }
    }

    json create(const std::string &path, const std::string &password, const std::string &vault_name = "Vault") {
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
        std::string hashed = hash_password(password);
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

    json open(const std::string &path) {
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

    json authenticate(const std::string &password) {
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

    json close() {
        json response;
        if (file.is_open()) {
            file.close();
        }
        authenticated = false;
        entries.clear();
        response["success"] = true;
        return response;
    }

    bool is_open() const { return file.is_open(); }
    bool is_authenticated() const { return authenticated; }

    json load_entries() {
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
            size_t offset = sizeof(VaultHeader) + (i * ENCRYPTED_ENTRY_SIZE);
            file.seekg(offset);

            unsigned char encrypted[ENCRYPTED_ENTRY_SIZE];
            file.read(reinterpret_cast<char *>(encrypted), ENCRYPTED_ENTRY_SIZE);

            try {
                Entry entry;
                decrypt_entry(key, entry, encrypted, ENCRYPTED_ENTRY_SIZE);
                entries.push_back(entry);
            }
            catch (const std::exception &e) {
                response["success"] = false;
                response["error"] = "Failed to decrypt entry " + std::to_string(i) + ": " + e.what();
                return response;
            }
        }

        response["success"] = true;
        response["entries"] = header.entries;
        return response;
    }

    json add_entry(const Entry &entry) {
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

        // Encrypt Entry struct directly
        std::vector<unsigned char> encrypted{};
        encrypt_entry(key, entry, encrypted);

        size_t offset = sizeof(VaultHeader) + (header.entries * ENCRYPTED_ENTRY_SIZE);
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

    json modify_entry(size_t index, const Entry &entry) {
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

        if (index >= header.entries) {
            response["success"] = false;
            response["error"] = "Invalid entry index";
            return response;
        }

        // Encrypt Entry struct (same as add_entry)
        std::vector<unsigned char> encrypted{};
        encrypt_entry(key, entry, encrypted);

        size_t offset = sizeof(VaultHeader) + (index * ENCRYPTED_ENTRY_SIZE);
        file.seekp(offset);
        file.write(reinterpret_cast<const char *>(encrypted.data()), encrypted.size());

        header.updated = std::time(nullptr);
        file.seekp(0);
        header.write(file);
        file.flush();

        // Update in-memory entries if loaded
        if (index < entries.size()) {
            entries[index] = entry;
        }

        response["success"] = true;
        response["entries"] = header.entries;
        return response;
    }

    json delete_entry(size_t index) {
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

        if (index >= header.entries) {
            response["success"] = false;
            response["error"] = "Invalid entry index";
            return response;
        }

        // Remove from memory vector
        if (index < entries.size()) {
            entries.erase(entries.begin() + index);
        }

        // Shift remaining entries in the file
        for (size_t i = index; i < header.entries - 1; i++) {
            size_t src_offset = sizeof(VaultHeader) + ((i + 1) * ENCRYPTED_ENTRY_SIZE);
            size_t dst_offset = sizeof(VaultHeader) + (i * ENCRYPTED_ENTRY_SIZE);

            // Read the next entry
            unsigned char buffer[ENCRYPTED_ENTRY_SIZE];
            file.seekg(src_offset);
            file.read(reinterpret_cast<char *>(buffer), ENCRYPTED_ENTRY_SIZE);

            // Write it to the current position
            file.seekp(dst_offset);
            file.write(reinterpret_cast<const char *>(buffer), ENCRYPTED_ENTRY_SIZE);
        }

        // Update header
        header.entries--;
        header.updated = std::time(nullptr);

        file.seekp(0);
        header.write(file);
        file.flush();

        // Truncate file to new size (optional but cleaner)
        size_t new_size = sizeof(VaultHeader) + (header.entries * ENCRYPTED_ENTRY_SIZE);
        std::filesystem::resize_file(file_path, new_size);

        response["success"] = true;
        response["entries"] = header.entries;
        return response;
    }

    const std::vector<Entry> &get_entries() const { return entries; }
};

#endif // VAULT_VAULT_HPP
