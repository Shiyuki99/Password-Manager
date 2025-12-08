#include <iostream>
#include "api/handlers.hpp"

using namespace httplib;
using json = nlohmann::json;

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    // Create server instance on port 8080
    Server svr;
    ApiHandlers handlers;

    // Serve static files from webui directory
    svr.set_mount_point("/", "./webui");

    // Set up API routes
    svr.Post("/api/browse", [&handlers](const Request &req, Response &res) {
        handlers.handle_browse(req, res);
    });

    svr.Post("/api/vault/create", [&handlers](const Request &req, Response &res) {
        handlers.handle_create_vault(req, res);
    });

    svr.Post("/api/vault/open", [&handlers](const Request &req, Response &res) {
        handlers.handle_open_vault(req, res);
    });

    svr.Post("/api/vault/authenticate", [&handlers](const Request &req, Response &res) {
        handlers.handle_authenticate(req, res);
    });

    svr.Post("/api/vault/close", [&handlers](const Request &req, Response &res) {
        handlers.handle_close_vault(req, res);
    });

    svr.Post("/api/entries/load", [&handlers](const Request &req, Response &res) {
        handlers.handle_load_data(req, res);
    });

    svr.Get("/api/entries", [&handlers](const Request &req, Response &res) {
        handlers.handle_get_entries(req, res);
    });

    svr.Post("/api/entries/add", [&handlers](const Request &req, Response &res) {
        handlers.handle_add_entry(req, res);
    });

    svr.Get("/api/vault/status", [&handlers](const Request &req, Response &res) {
        handlers.handle_vault_status(req, res);
    });

    // Handle root path to serve index.html
    svr.Get("/", [](const Request &, Response &res) {
        std::ifstream file("./webui/index.html");
        if (file.is_open()) {
            std::string content((std::istreambuf_iterator<char>(file)),
                std::istreambuf_iterator<char>());
            res.set_content(content, "text/html");
        } else {
            res.status = 404;
            res.set_content("404 Not Found", "text/plain");
        }
    });

    // Error handler
    svr.set_error_handler([](const Request &req, Response &res) {
        json error_response = {
            {"success", false},
            {"error", "Error: " + std::to_string(res.status)},
            {"path", req.path}
        };
        res.set_content(error_response.dump(), "application/json");
    });

    std::cout << "Starting Password Manager server on port 8080..." << std::endl;
    std::cout << "Open your browser and go to http://localhost:8080 to access the UI" << std::endl;

    // Start the server
    svr.listen("0.0.0.0", 8080);

    return 0;
}
