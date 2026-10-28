#include "config.h"

#include <cstdlib>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <map>
#include <stdexcept>

namespace {
std::string Trim(const std::string& s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    return first == std::string::npos ? "" : s.substr(first, s.find_last_not_of(" \t\r\n") - first + 1);
}

std::map<std::string, std::string> LoadEnv() {
    std::map<std::string, std::string> values;
    std::ifstream file(".env");
    std::string line;
    int number = 0;
    while (std::getline(file, line)) {
        ++number;
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue;
        if (line.compare(0, 7, "export ") == 0) line = Trim(line.substr(7));
        const auto equal = line.find('=');
        if (equal == std::string::npos || equal == 0)
            throw std::runtime_error("Invalid .env assignment on line " + std::to_string(number));
        std::string key = Trim(line.substr(0, equal));
        std::string value = Trim(line.substr(equal + 1));
        if (!value.empty() && (value[0] == '\'' || value[0] == '"')) {
            const auto closing = value.find(value[0], 1);
            if (closing == std::string::npos)
                throw std::runtime_error("Unclosed .env quote on line " + std::to_string(number));
            const auto tail = Trim(value.substr(closing + 1));
            if (!tail.empty() && tail[0] != '#')
                throw std::runtime_error("Invalid .env quote on line " + std::to_string(number));
            value = value.substr(1, closing - 1);
        } else {
            const auto comment = value.find(" #");
            if (comment != std::string::npos) value = Trim(value.substr(0, comment));
        }
        values[key] = value;
    }
    return values;
}

int Number(const std::string& key, const std::string& value, int min, int max) {
    if (value.empty() || value.find_first_not_of("0123456789") != std::string::npos)
        throw std::runtime_error(key + " must be an integer");
    unsigned long n;
    try { n = std::stoul(value); }
    catch (...) { throw std::runtime_error(key + " is out of range"); }
    if (n < static_cast<unsigned long>(min) || n > static_cast<unsigned long>(max))
        throw std::runtime_error(key + " is out of range");
    return static_cast<int>(n);
}

void CheckName(const std::string& name, const std::string& key) {
    if (name.empty() || name.size() > 253) throw std::runtime_error("Invalid " + key);
    size_t length = 0;
    for (const unsigned char c : name) {
        if (c == '.') {
            if (length == 0 || length > 63) throw std::runtime_error("Invalid " + key);
            length = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '_'))
                throw std::runtime_error("Invalid " + key);
            ++length;
        }
    }
    if (length == 0 || length > 63) throw std::runtime_error("Invalid " + key);
}
}

Config Config::Load(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--help" || std::string(argv[i]) == "-?") {
            std::cout << "PirateCash RPC DNS seed\nUsage: " << argv[0]
                      << " [-h host] [-n nameserver] [-m SOA-mailbox] [-p port] [-d DNS-threads]\n"
                      << "Settings are loaded from .env; environment variables override .env.\n"
                      << "See .env.example for RPC, polling, bootstrap and DNS settings.\n";
            std::exit(0);
        }
    }
    const auto env = LoadEnv();
    const auto get = [&](const std::string& key, const std::string& fallback) {
        const char* value = std::getenv(key.c_str());
        if (value) return std::string(value);
        const auto it = env.find(key);
        return it == env.end() ? fallback : it->second;
    };
    const auto number = [&](const std::string& key, int fallback, int min, int max) {
        return Number(key, get(key, std::to_string(fallback)), min, max);
    };
    Config c;
    c.rpcUrl = get("RPC_URL", "http://127.0.0.1:19606/");
    c.rpcUser = get("RPC_USER", "");
    c.rpcPassword = get("RPC_PASSWORD", "");
    c.bootstrap = get("BOOTSTRAP_NODES", "");
    c.pollSeconds = number("RPC_POLL_INTERVAL", 300, 1, 86400);
    c.timeoutSeconds = number("RPC_TIMEOUT", 10, 1, 300);
    c.host = get("DNS_HOST", "");
    c.ns = get("DNS_NS", "");
    c.mbox = get("DNS_MBOX", "");
    c.port = number("DNS_PORT", 53, 1, 65535);
    c.dnsThreads = number("DNS_THREADS", 4, 1, 128);
    c.ttl = number("DNS_TTL", 300, 1, 86400);
    c.nsTtl = number("DNS_NS_TTL", 40000, 1, 604800);

    int option;
    while ((option = getopt(argc, argv, "h:n:m:p:d:")) != -1) {
        switch (option) {
        case 'h': c.host = optarg; break;
        case 'n': c.ns = optarg; break;
        case 'm': c.mbox = optarg; break;
        case 'p': c.port = Number("DNS_PORT", optarg, 1, 65535); break;
        case 'd': c.dnsThreads = Number("DNS_THREADS", optarg, 1, 128); break;
        default: throw std::runtime_error("Unknown option; use --help");
        }
    }
    if (optind != argc) throw std::runtime_error("Unexpected argument; use --help");
    for (auto* name : {&c.host, &c.ns, &c.mbox}) {
        if (!name->empty() && name->back() == '.') name->pop_back();
    }
    CheckName(c.host, "DNS_HOST");
    CheckName(c.ns, "DNS_NS");
    if (c.mbox.empty()) c.mbox = "hostmaster." + c.host;
    CheckName(c.mbox, "DNS_MBOX (replace @ with .)");
    if (c.rpcUrl.compare(0, 7, "http://") != 0 && c.rpcUrl.compare(0, 8, "https://") != 0)
        throw std::runtime_error("RPC_URL must use http:// or https://");
    return c;
}
