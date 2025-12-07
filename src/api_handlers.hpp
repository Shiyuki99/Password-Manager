#ifndef API_HANDLERS_HPP
#define API_HANDLERS_HPP

#include "vault_handler.hpp"
#include "httplib.h"
#include "json.hpp"
#include <dirent.h>
#include <sys/stat.h>
#include <cstring>

using json = nlohmann::json;

class ApiHandlers {
private:
    vault_handler vault;

public:
    // List directory contents for file browser
    void handle_browse(const httplib::Request &req, httplib::Response &res) {
        json response;

        try {
            json request_data = json::parse(req.body);
            std::string path = request_data.value("path", "");

            // Default to home directory
            if (path.empty()) {
                const char *home = getenv("HOME");
                path = home ? home : "/";
            }

            // Expand ~ to home directory
            if (!path.empty() && path[0] == '~') {
                const char *home = getenv("HOME");
                if (home) {
                    path = std::string(home) + path.substr(1);
                }
            }

            DIR *dir = opendir(path.c_str());
            if (!dir) {
                response["success"] = false;
                response["error"] = "Cannot open directory: " + path;
                res.set_content(response.dump(), "application/json");
                return;
            }

            json items = json::array();
            struct dirent *entry;

            while ((entry = readdir(dir)) != nullptr) {
                std::string name = entry->d_name;

                // Skip . but keep ..
                if (name == ".") continue;
                // Skip hidden files except ..
                if (name[0] == '.' && name != "..") continue;

                std::string full_path = path;
                if (path.back() != '/') full_path += '/';
                full_path += name;

                struct stat st;
                if (stat(full_path.c_str(), &st) == 0) {
                    bool is_dir = S_ISDIR(st.st_mode);
                    bool is_shpd = name.size() > 5 && name.substr(name.size() - 5) == ".shpd";

                    // Show directories and .shpd files
                    if (is_dir || is_shpd) {
                        json item;
                        item["name"] = name;
                        item["path"] = full_path;
                        item["is_dir"] = is_dir;
                        items.push_back(item);
                    }
                }
            }
            closedir(dir);

            response["success"] = true;
            response["path"] = path;
            response["items"] = items;
        }
        catch (const std::exception &e) {
            response["success"] = false;
            response["error"] = std::string("Exception: ") + e.what();
        }

        res.set_content(response.dump(), "application/json");
    }

    // Handle vault create request
    void handle_create_vault(const httplib::Request &req, httplib::Response &res) {
        json response;

        try {
            json request_data = json::parse(req.body);
            std::string path = request_data.value("path", "");
            std::string password = request_data.value("password", "");
            std::string name = request_data.value("name", "Vault");

            // Expand ~ to home directory
            if (!path.empty() && path[0] == '~') {
                const char *home = getenv("HOME");
                if (home) {
                    path = std::string(home) + path.substr(1);
                }
            }

            if (path.empty() || password.empty()) {
                response["success"] = false;
                response["error"] = "Path and password are required";
            } else {
                response = vault.Create(path, password, name);
            }
        }
        catch (const std::exception &e) {
            response["success"] = false;
            response["error"] = std::string("Exception: ") + e.what();
        }

        res.set_content(response.dump(), "application/json");
    }

    // Handle vault open request
    void handle_open_vault(const httplib::Request &req, httplib::Response &res) {
        json response;

        try {
            json request_data = json::parse(req.body);
            std::string path = request_data.value("path", "");

            // Expand ~ to home directory
            if (!path.empty() && path[0] == '~') {
                const char *home = getenv("HOME");
                if (home) {
                    path = std::string(home) + path.substr(1);
                }
            }

            if (path.empty()) {
                response["success"] = false;
                response["error"] = "Path is required";
            } else {
                response = vault.Open(path);
            }
        }
        catch (const std::exception &e) {
            response["success"] = false;
            response["error"] = std::string("Exception: ") + e.what();
        }

        res.set_content(response.dump(), "application/json");
    }

    // Handle vault authentication
    void handle_authenticate(const httplib::Request &req, httplib::Response &res) {
        json response;

        try {
            json request_data = json::parse(req.body);
            std::string password = request_data.value("password", "");

            if (password.empty()) {
                response["success"] = false;
                response["error"] = "Password is required";
            } else {
                response = vault.Authenticate(password);
            }
        }
        catch (const std::exception &e) {
            response["success"] = false;
            response["error"] = std::string("Exception: ") + e.what();
        }

        res.set_content(response.dump(), "application/json");
    }

    // Handle loading vault data
    void handle_load_data(const httplib::Request &req, httplib::Response &res) {
        json response;

        try {
            response = vault.LoadEntries();
        }
        catch (const std::exception &e) {
            response["success"] = false;
            response["error"] = std::string("Exception: ") + e.what();
        }

        res.set_content(response.dump(), "application/json");
    }

    // Handle getting entries
    void handle_get_entries(const httplib::Request &req, httplib::Response &res) {
        json response;

        try {
            const auto &entries = vault.GetEntries();
            json entries_json = json::array();

            for (const auto &entry : entries) {
                json e;
                e["name"] = entry.Name;
                e["username"] = entry.Username;
                e["password"] = entry.Password;
                e["url"] = entry.Website;
                e["notes"] = entry.Notes;
                entries_json.push_back(e);
            }

            response["success"] = true;
            response["entries"] = entries_json;
        }
        catch (const std::exception &e) {
            response["success"] = false;
            response["error"] = std::string("Exception: ") + e.what();
        }

        res.set_content(response.dump(), "application/json");
    }

    // Handle adding a new entry
    void handle_add_entry(const httplib::Request &req, httplib::Response &res) {
        json response;

        try {
            json request_data = json::parse(req.body);

            Entry entry = {};
            entry.Name = request_data.value("name", "");
            entry.Username = request_data.value("username", "");
            entry.Password = request_data.value("password", "");
            entry.Website = request_data.value("url", "");
            entry.Notes = request_data.value("notes", "");
            entry.Modf_Time = time(nullptr);

            if (entry.Name.empty() || entry.Password.empty()) {
                response["success"] = false;
                response["error"] = "Name and password are required";
            } else {
                response = vault.AddEntry(entry);
            }
        }
        catch (const std::exception &e) {
            response["success"] = false;
            response["error"] = std::string("Exception: ") + e.what();
        }

        res.set_content(response.dump(), "application/json");
    }

    // Handle vault close
    void handle_close_vault(const httplib::Request &req, httplib::Response &res) {
        json response;

        try {
            response = vault.Close();
        }
        catch (const std::exception &e) {
            response["success"] = false;
            response["error"] = std::string("Exception: ") + e.what();
        }

        res.set_content(response.dump(), "application/json");
    }

    // Handle vault status check
    void handle_vault_status(const httplib::Request &req, httplib::Response &res) {
        json response;

        try {
            response["success"] = true;
            response["is_open"] = vault.IsOpen();
            response["is_authenticated"] = vault.IsAuthenticated();
        }
        catch (const std::exception &e) {
            response["success"] = false;
            response["error"] = std::string("Exception: ") + e.what();
        }

        res.set_content(response.dump(), "application/json");
    }
};

#endif