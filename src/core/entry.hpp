#ifndef CORE_ENTRY_HPP
#define CORE_ENTRY_HPP

#include "types.hpp"
#include "constants.hpp"

/**
 * @brief Struct to represent a vault entry.
 * Contains: Name, Username, Website, Password, Notes, Modification Time
 */
struct Entry {
    char Name[ENTRY_NAME_SIZE]{};
    char Username[ENTRY_USERNAME_SIZE]{};
    char Website[ENTRY_WEBSITE_SIZE]{};
    char Password[ENTRY_PASSWORD_SIZE]{};
    char Notes[ENTRY_NOTES_SIZE]{};
    time_t Modf_Time{};

    Entry() : Modf_Time(0) {}

    // Setters for fixed-size fields (fills with nulls)
    void setName(const std::string &val) {
        std::memset(Name, '\0', ENTRY_NAME_SIZE);
        std::memcpy(Name, val.c_str(), std::min(val.size(), ENTRY_NAME_SIZE - 1));
    }

    void setUsername(const std::string &val) {
        std::memset(Username, '\0', ENTRY_USERNAME_SIZE);
        std::memcpy(Username, val.c_str(), std::min(val.size(), ENTRY_USERNAME_SIZE - 1));
    }

    void setWebsite(const std::string &val) {
        std::memset(Website, '\0', ENTRY_WEBSITE_SIZE);
        std::memcpy(Website, val.c_str(), std::min(val.size(), ENTRY_WEBSITE_SIZE - 1));
    }

    void setPassword(const std::string &val) {
        std::memset(Password, '\0', ENTRY_PASSWORD_SIZE);
        std::memcpy(Password, val.c_str(), std::min(val.size(), ENTRY_PASSWORD_SIZE - 1));
    }

    void setNotes(const std::string &val) {
        std::memset(Notes, '\0', ENTRY_NOTES_SIZE);
        std::memcpy(Notes, val.c_str(), std::min(val.size(), ENTRY_NOTES_SIZE - 1));
    }
};

#endif // CORE_ENTRY_HPP
