#ifndef API_SERIALIZERS_HPP
#define API_SERIALIZERS_HPP

#include "../core/entry.hpp"
#include "../core/constants.hpp"
#include "../lib/json.hpp"

using json = nlohmann::json;

/**
 * @brief Convert an Entry struct to JSON
 */
json entry_to_json(const Entry &e) {
    return json{
        {"name", e.Name},
        {"username", e.Username},
        {"website", e.Website},
        {"password", e.Password},
        {"notes", e.Notes},
        {"modf_time", e.Modf_Time}
    };
}

/**
 * @brief Convert JSON to an Entry struct
 */
Entry json_to_entry(const json &j) {
    Entry e;
    e.setName(j.value("name", ""));
    e.setUsername(j.value("username", ""));
    e.setWebsite(j.value("website", ""));
    e.setPassword(j.value("password", ""));
    e.setNotes(j.value("notes", ""));
    e.Modf_Time = j.value("modf_time", time(nullptr));
    return e;
}

/**
 * @brief Convert an Entry struct to a string representation
 */
std::string entry_to_string(const Entry &e) {
    return "Name: " + std::string(e.Name) + " " +
           "Username: " + std::string(e.Username) + " " +
           "Website: " + std::string(e.Website) + " " +
           "Password: " + std::string(e.Password) + " " +
           "Notes: " + std::string(e.Notes) + " " +
           "Modified: " + std::to_string(e.Modf_Time);
}

/**
 * @brief Create an Entry from JSON input with validation
 */
json create_entry_from_json(const json &input_json) {
    json response;

    try {
        Entry entry;

        std::string name = input_json.value("name", "");
        std::string username = input_json.value("username", "");
        std::string website = input_json.value("website", "");
        std::string password = input_json.value("password", "");
        std::string notes = input_json.value("notes", "");

        // Validate required fields
        if (name.empty() || username.empty() || website.empty() || password.empty()) {
            response["success"] = false;
            response["error"] = "Missing required fields: name, username, website, or password";
            return response;
        }

        // Validate field lengths
        if (name.length() > ENTRY_NAME_SIZE - 1) {
            response["success"] = false;
            response["error"] = "Name too long (max " + std::to_string(ENTRY_NAME_SIZE - 1) + " characters)";
            return response;
        }

        if (username.length() > ENTRY_USERNAME_SIZE - 1) {
            response["success"] = false;
            response["error"] = "Username too long (max " + std::to_string(ENTRY_USERNAME_SIZE - 1) + " characters)";
            return response;
        }

        if (website.length() > ENTRY_WEBSITE_SIZE - 1) {
            response["success"] = false;
            response["error"] = "Website too long (max " + std::to_string(ENTRY_WEBSITE_SIZE - 1) + " characters)";
            return response;
        }

        if (notes.length() > ENTRY_NOTES_SIZE - 1) {
            response["success"] = false;
            response["error"] = "Notes too long (max " + std::to_string(ENTRY_NOTES_SIZE - 1) + " characters)";
            return response;
        }

        entry.setName(name);
        entry.setUsername(username);
        entry.setWebsite(website);
        entry.setPassword(password);
        entry.setNotes(notes);
        entry.Modf_Time = input_json.value("modf_time", time(nullptr));

        response["success"] = true;
        response["entry"] = entry_to_json(entry);
        response["message"] = "Entry created successfully";

        return response;
    }
    catch (const std::exception &e) {
        response["success"] = false;
        response["error"] = std::string("Error creating entry: ") + e.what();
        return response;
    }
}

#endif // API_SERIALIZERS_HPP
