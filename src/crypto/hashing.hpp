#ifndef CRYPTO_HASHING_HPP
#define CRYPTO_HASHING_HPP

#include "../core/types.hpp"
#include "../lib/json.hpp"

using json = nlohmann::json;

// Crypto size constants
constexpr int SALT_SIZE = crypto_pwhash_SALTBYTES;
constexpr int HASH_SIZE = crypto_pwhash_STRBYTES;

/**
 * @brief Hash a password using Argon2id
 * @param password Password to hash
 * @return Hashed password string
 */
std::string hash_password(const std::string &password) {
    char hashed[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_argon2id_str(
            hashed,
            password.c_str(),
            password.length(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        throw std::runtime_error("Password hashing failed");
    }
    return std::string(hashed);
}

/**
 * @brief Verify a password against a stored hash
 * @param stored_hash The stored hash to verify against
 * @param password The password to verify
 * @return JSON response with success status
 */
json verify_password(const std::string &stored_hash, const std::string &password) {
    json response;

    try {
        if (crypto_pwhash_argon2id_str_verify(
                stored_hash.c_str(),
                password.c_str(),
                password.length()) == 0) {
            response["success"] = true;
            response["message"] = "Password verified successfully";
        } else {
            response["success"] = false;
            response["error"] = "Password verification failed";
        }
    } catch (const std::exception &e) {
        response["success"] = false;
        response["error"] = std::string("Exception during password verification: ") + e.what();
    }

    return response;
}

/**
 * @brief Derive a symmetric key from a password using Argon2id
 * @param password Input password
 * @param salt Salt value used in key derivation
 * @param key Output buffer for the derived key
 * @return true if key derivation is successful, false otherwise
 */
bool derive_key_from_password(
    const std::string &password,
    const unsigned char *salt,
    unsigned char key[crypto_secretbox_KEYBYTES]) {

    if (crypto_pwhash(
            key, crypto_secretbox_KEYBYTES,
            password.c_str(), password.size(),
            reinterpret_cast<const unsigned char *>(salt),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        std::cerr << "Key derivation failed (out of memory?)" << std::endl;
        return false;
    }
    return true;
}

#endif // CRYPTO_HASHING_HPP
