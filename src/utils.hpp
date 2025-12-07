#ifndef UTILS_HPP
#define UTILS_HPP

#include "stdlib_inc.hpp"
#include "json.hpp" // Include JSON library

// Using nlohmann json namespace
using json = nlohmann::json;

// Safe input function - adapted for JSON interface
std::string safe_input_json(size_t max_len, const std::string& input) {
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

/**
 * @brief Struct to represent a vault entry.
 * Name, Username, Website, Password, Notes, Modification Time
 *
 */
typedef struct Entry {
   std::string Name;
   std::string Username;
   std::string Website;
   std::string Password;
   std::string Notes;  // Add Notes field
   time_t Modf_Time;
} Entry;

// Convert Entry to JSON
json EntryToJson(const Entry &e) {
   return json{
      {"name", e.Name},
      {"username", e.Username},
      {"website", e.Website},
      {"password", e.Password},  // In real implementation, don't include password in responses
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
   e.Modf_Time = j.value("modf_time", time(nullptr));
   return e;
}

std::string EntryToString(const Entry &e) {
   return "Name: " + e.Name + " " +
      "Username: " + e.Username + " " +
      "Website: " + e.Website + " " +
      "Password: " + e.Password + " " +
      "Modified: " + std::to_string(e.Modf_Time);
}

// Create password - adapted for JSON interface
json Create_Password(const std::string& option, const std::string& param = "") {
   json result;
   
   if (option == "manual" || option == "m" || option == "M") {
      result["type"] = "manual";
      result["message"] = "Password will be provided manually";
   } else if (option == "generate" || option == "g" || option == "G") {
      result["type"] = "generated";
      result["message"] = "Password generation requested";
      
      // Validate param if provided
      std::unordered_set<char> allowed = {'1', '2', '3', '4'};
      std::vector<std::string> char_sets;
      
      for (char c : param) {
         if (allowed.count(c)) {
            char_sets.push_back(presets[c-'1']); // Assuming presets are in order 1,2,3,4
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
json CreateEntryFromJson(const json& input_json) {
   json response;

   try {
      Entry entry;

      // Extract data from JSON
      entry.Name = input_json.value("name", "");
      entry.Username = input_json.value("username", "");
      entry.Website = input_json.value("website", "");
      entry.Password = input_json.value("password", "");
      entry.Modf_Time = input_json.value("modf_time", time(nullptr));

      // Validate required fields
      if (entry.Name.empty() || entry.Username.empty() || entry.Website.empty() || entry.Password.empty()) {
         response["success"] = false;
         response["error"] = "Missing required fields: name, username, website, or password";
         return response;
      }

      // Validate field lengths
      if (entry.Name.length() > 32) {
         response["success"] = false;
         response["error"] = "Name too long (max 32 characters)";
         return response;
      }

      if (entry.Username.length() > 32) {
         response["success"] = false;
         response["error"] = "Username too long (max 32 characters)";
         return response;
      }

      if (entry.Website.length() > 32) {
         response["success"] = false;
         response["error"] = "Website too long (max 32 characters)";
         return response;
      }

      response["success"] = true;
      response["entry"] = EntryToJson(entry);  // Use the EntryToJson function instead
      response["message"] = "Entry created successfully";

      return response;
   } catch (const std::exception& e) {
      response["success"] = false;
      response["error"] = std::string("Error creating entry: ") + e.what();
      return response;
   }
}

#endif