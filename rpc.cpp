#include "rpc.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <univalue.h>

#include <algorithm>
#include <cstring>
#include <set>
#include <sstream>
#include <stdexcept>

AddressCache::AddressCache(Addresses bootstrap)
    : current(std::make_shared<const Addresses>(std::move(bootstrap))) {}

void AddressCache::Replace(Addresses addresses) {
    auto next = std::make_shared<const Addresses>(std::move(addresses));
    std::lock_guard<std::mutex> lock(mutex);
    current = std::move(next);
}

std::shared_ptr<const Addresses> AddressCache::Snapshot() {
    std::lock_guard<std::mutex> lock(mutex);
    return current;
}

namespace {
bool PortValid(const std::string& s) {
    return !s.empty() && s.size() <= 5 && s.find_first_not_of("0123456789") == std::string::npos &&
           std::stoul(s) > 0 && std::stoul(s) <= 65535;
}

bool ParseAddress(const std::string& service, addr_t& address) {
    std::string ip = service;
    if (ip.empty()) return false;
    if (ip[0] == '[') {
        const auto end = ip.find(']');
        if (end == std::string::npos) return false;
        const auto tail = ip.substr(end + 1);
        if (!tail.empty() && (tail[0] != ':' || !PortValid(tail.substr(1)))) return false;
        ip = ip.substr(1, end - 1);
    } else if (std::count(ip.begin(), ip.end(), ':') == 1) {
        const auto colon = ip.find(':');
        if (!PortValid(ip.substr(colon + 1))) return false;
        ip.resize(colon);
    }
    address = {};
    if (inet_pton(AF_INET, ip.c_str(), address.data.v4) == 1) {
        address.v = 4;
    } else if (inet_pton(AF_INET6, ip.c_str(), address.data.v6) == 1) {
        static const unsigned char mapped[12] = {0,0,0,0,0,0,0,0,0,0,255,255};
        if (std::memcmp(address.data.v6, mapped, 12) == 0) {
            std::memmove(address.data.v4, address.data.v6 + 12, 4);
            address.v = 4;
        } else {
            address.v = 6;
        }
    } else {
        return false; // Never resolve hostnames or contact individual masternodes.
    }
    if (address.v == 4)
        return address.data.v4[0] != 0 && address.data.v4[0] != 127 && address.data.v4[0] < 224;
    static const unsigned char zero[16] = {};
    static const unsigned char loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    return std::memcmp(address.data.v6, zero, 16) != 0 &&
           std::memcmp(address.data.v6, loopback, 16) != 0 && address.data.v6[0] != 255;
}

void AddAddress(const std::string& service, Addresses& out, std::set<std::string>& seen) {
    addr_t address;
    if (!ParseAddress(service, address)) return;
    const auto key = std::string(1, static_cast<char>(address.v)) +
        std::string(reinterpret_cast<const char*>(&address.data), address.v == 4 ? 4 : 16);
    if (seen.insert(key).second) out.push_back(address);
}

constexpr size_t MaxResponse = 32 * 1024 * 1024;
size_t Receive(char* data, size_t size, size_t count, void* context) {
    auto& response = *static_cast<std::string*>(context);
    if (size && count > (MaxResponse - response.size()) / size) return 0;
    const size_t bytes = size * count;
    try { response.append(data, bytes); }
    catch (...) { return 0; }
    return bytes;
}
}

Addresses ParseBootstrap(const std::string& nodes) {
    std::string input = nodes;
    std::replace(input.begin(), input.end(), ',', ' ');
    std::istringstream stream(input);
    Addresses addresses;
    std::set<std::string> seen;
    std::string service;
    while (stream >> service) {
        addr_t address;
        if (!ParseAddress(service, address)) throw std::runtime_error("BOOTSTRAP_NODES contains an invalid IP address");
        AddAddress(service, addresses, seen);
    }
    return addresses;
}

Addresses ParseMasternodes(const std::string& response) {
    UniValue root;
    if (!root.read(response) || !root.isObject()) throw std::runtime_error("RPC returned invalid JSON");
    if (!root.exists("error") || !root["error"].isNull()) throw std::runtime_error("RPC returned an error");
    const auto& result = root["result"];
    if (!result.isObject()) throw std::runtime_error("RPC masternode list result must be an object");
    Addresses addresses;
    std::set<std::string> seen;
    for (const auto& node : result.getValues()) {
        if (!node.isObject() || !node["status"].isStr())
            throw std::runtime_error("RPC masternode list has an invalid entry");
        if (node["status"].get_str() != "ENABLED") continue;
        if (node.exists("addresses") && !node["addresses"].isObject())
            throw std::runtime_error("RPC masternode has invalid addresses");
        const auto& services = node["addresses"]["core_p2p"];
        if (services.isArray()) {
            for (const auto& service : services.getValues()) {
                if (!service.isStr()) throw std::runtime_error("RPC core_p2p address must be a string");
                AddAddress(service.get_str(), addresses, seen);
            }
        } else if (!services.isNull()) {
            throw std::runtime_error("RPC core_p2p addresses must be an array");
        } else if (node["address"].isStr()) {
            // Older PirateCash versions expose just the primary P2P service.
            AddAddress(node["address"].get_str(), addresses, seen);
        } else {
            throw std::runtime_error("RPC masternode has no P2P address field");
        }
    }
    return addresses;
}

Addresses FetchMasternodes(const Config& config) {
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    if (!curl) throw std::runtime_error("Cannot initialize RPC HTTP client");
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(
        curl_slist_append(nullptr, "Content-Type: application/json"), curl_slist_free_all);
    if (!headers) throw std::runtime_error("Cannot initialize RPC HTTP headers");
    std::string response;
    char errorBuffer[CURL_ERROR_SIZE] = {};
    curl_easy_setopt(curl.get(), CURLOPT_ERRORBUFFER, errorBuffer);
    curl_easy_setopt(curl.get(), CURLOPT_URL, config.rpcUrl.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_USERNAME, config.rpcUser.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_PASSWORD, config.rpcPassword.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS,
        "{\"jsonrpc\":\"1.0\",\"id\":\"dnsseed\",\"method\":\"masternode\",\"params\":[\"list\",\"json\"]}");
    curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, static_cast<long>(config.timeoutSeconds));
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, static_cast<long>(config.timeoutSeconds));
    curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_NOPROXY, "*");
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, Receive);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    const auto status = curl_easy_perform(curl.get());
    if (status != CURLE_OK)
        throw std::runtime_error(std::string("RPC request failed: ") +
            (errorBuffer[0] ? errorBuffer : curl_easy_strerror(status)));
    long httpStatus = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &httpStatus);
    if (httpStatus != 200) throw std::runtime_error("RPC HTTP status " + std::to_string(httpStatus));
    return ParseMasternodes(response);
}
