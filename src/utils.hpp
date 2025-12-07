#ifndef UTILS_HPP
#define UTILS_HPP

#include "stdlib_inc.hpp"
#include "json.hpp" // Include JSON library

// Using nlohmann json namespace
using json = nlohmann::json;

// Safe input function - adapted for JSON interface
std::string safe_input_json(size_t max_len, const std::string &input) {
   if (input.size() > max_len) {
      return input.substr(0, max_len);
   }
   return input;
}

const std::vector<std::string> presets = {
    "abcdefghijklmnopqrstuvwxy",
    "ABCDEFGHIJKLMNOPQRSTUVWXY",
    "0123456789",
    R"(!"#$%&'()*+,-.:;<=>?[\]^_{|}~)",
};

// Field size constants for Entry


/**
 * @brief Struct to represent a vault entry.
 * Name, Username, Website, Password, Notes, Modification Time
 *
 */
typedef struct Entry {
   std::string Name{};
   std::string Username{};
   std::string Website{};
   std::string Password{};
   std::string Notes{};
   time_t Modf_Time{};

   Entry() : Name(ENTRY_NAME_SIZE, '\0'),
      Username(ENTRY_USERNAME_SIZE, '\0'),
      Website(ENTRY_WEBSITE_SIZE, '\0'),
      Password(ENTRY_PASSWORD_SIZE, '\0'),
      Notes(ENTRY_NOTES_SIZE, '\0'),
      Modf_Time(0) {
   }

   // Helper to set fields with fixed size (fills with nulls)
   void setName(const std::string &val) {
      Name.assign(ENTRY_NAME_SIZE, '\0');
      std::memcpy(Name.data(), val.c_str(), std::min(val.size(), ENTRY_NAME_SIZE - 1));
   }
   void setUsername(const std::string &val) {
      Username.assign(ENTRY_USERNAME_SIZE, '\0');
      std::memcpy(Username.data(), val.c_str(), std::min(val.size(), ENTRY_USERNAME_SIZE - 1));
   }
   void setWebsite(const std::string &val) {
      Website.assign(ENTRY_WEBSITE_SIZE, '\0');
      std::memcpy(Website.data(), val.c_str(), std::min(val.size(), ENTRY_WEBSITE_SIZE - 1));
   }
   void setPassword(const std::string &val) {
      Password.assign(ENTRY_PASSWORD_SIZE, '\0');
      std::memcpy(Password.data(), val.c_str(), std::min(val.size(), ENTRY_PASSWORD_SIZE - 1));
   }
   void setNotes(const std::string &val) {
      Notes.assign(ENTRY_NOTES_SIZE, '\0');
      std::memcpy(Notes.data(), val.c_str(), std::min(val.size(), ENTRY_NOTES_SIZE - 1));
   }
} Entry;

// Convert Entry to JSON
json EntryToJson(const Entry &e) {
   return json{
      {"name", e.Name},
      {"username", e.Username},
      {"website", e.Website},
      {"password", e.Password},  // In real implementation, don't include password in responses
      {"notes", e.Notes},        // Include notes too
      {"modf_time", e.Modf_Time}
   };
}

// Convert JSON to Entry
Entry JsonToEntry(const json &j) {
   Entry e;
   e.Name = j.value("name", "");
   e.Username = j.value("username", "");
   e.Website = j.value("website", "");
   e.Password = j.value("password", "");
   e.Notes = j.value("notes", "");  // Add notes field
   e.Modf_Time = j.value("modf_time", time(nullptr));
   return e;
}

std::string EntryToString(const Entry &e) {
   return "Name: " + e.Name + " " +
      "Username: " + e.Username + " " +
      "Website: " + e.Website + " " +
      "Password: " + e.Password + " " +
      "Notes: " + e.Notes + " " +
      "Modified: " + std::to_string(e.Modf_Time);
}

// Create password - adapted for JSON interface
json Create_Password(const std::string &option, const std::string &param = "") {
   json result;

   if (option == "manual" || option == "m" || option == "M") {
      result["type"] = "manual";
      result["message"] = "Password will be provided manually";
   } else if (option == "generate" || option == "g" || option == "G") {
      result["type"] = "generated";
      result["message"] = "Password generation requested";

      // Validate param if provided
      std::unordered_set<char> allowed = { '1', '2', '3', '4' };
      std::vector<std::string> char_sets;

      for (char c : param) {
         if (allowed.count(c)) {
            char_sets.push_back(presets[c - '1']); // Assuming presets are in order 1,2,3,4
         }
      }

      if (char_sets.empty()) {
         // Default to first three sets
         for (int i = 0; i < 3; i++) {
            char_sets.push_back(presets[i]);
         }
      }

      result["char_sets"] = char_sets;
   } else {
      result["type"] = "error";
      result["message"] = "Invalid option. Use 'manual' or 'generate'";
   }

   return result;
}

// Create entry from JSON data
json CreateEntryFromJson(const json &input_json) {
   json response;

   try {
      Entry entry;

      // Extract data from JSON and use setters for fixed-size fields
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
      response["entry"] = EntryToJson(entry);
      response["message"] = "Entry created successfully";

      return response;
   }
   catch (const std::exception &e) {
      response["success"] = false;
      response["error"] = std::string("Error creating entry: ") + e.what();
      return response;
   }
}

#endif