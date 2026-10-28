#include "config.h"
#include "rpc.h"

#include <curl/curl.h>
#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <random>
#include <stdexcept>
#include <strings.h>
#include <thread>

namespace {
struct DnsContext {
    dns_opt_t options;
    AddressCache* cache;
    std::mt19937 random{std::random_device{}()};
};

int GetIPList(void* context, char* hostname, addr_t* out, int max, int ipv4, int ipv6) {
    auto& dns = *static_cast<DnsContext*>(context);
    if (max <= 0 || strcasecmp(hostname, dns.options.host) != 0) return 0;
    const auto snapshot = dns.cache->Snapshot();
    Addresses eligible;
    eligible.reserve(snapshot->size());
    for (const auto& address : *snapshot) {
        if ((ipv4 && address.v == 4) || (ipv6 && address.v == 6)) eligible.push_back(address);
    }
    const size_t count = std::min(eligible.size(), static_cast<size_t>(max));
    // Partial Fisher-Yates: a random sample without duplicates for each reply.
    for (size_t i = 0; i < count; ++i) {
        const size_t j = std::uniform_int_distribution<size_t>(i, eligible.size() - 1)(dns.random);
        std::swap(eligible[i], eligible[j]);
        out[i] = eligible[i];
    }
    return static_cast<int>(count);
}

void Poll(const Config& config, AddressCache& cache, bool& receivedActiveNodes) {
    try {
        auto addresses = FetchMasternodes(config);
        if (addresses.empty()) {
            // An authoritative empty list must remove nodes that became banned.
            cache.Replace(ParseBootstrap(config.bootstrap));
            std::cerr << "RPC has no active IP addresses; using " << cache.Snapshot()->size() << " bootstrap addresses\n";
        } else {
            const auto count = addresses.size();
            cache.Replace(std::move(addresses));
            receivedActiveNodes = true;
            std::cerr << "RPC cache updated: " << count << " active IP addresses\n";
        }
    } catch (const std::exception& error) {
        // A transport/JSON/RPC error never overwrites the current snapshot.
        std::cerr << error.what() << "; keeping " << cache.Snapshot()->size()
                  << (receivedActiveNodes ? " cached addresses\n" : " bootstrap addresses\n");
    }
}
}

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    try {
        const Config config = Config::Load(argc, argv);
        AddressCache cache(ParseBootstrap(config.bootstrap));
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
            throw std::runtime_error("Cannot initialize libcurl");
        // Complete the initial fetch before accepting DNS queries.
        bool receivedActiveNodes = false;
        Poll(config, cache, receivedActiveNodes);
        if (dnslisten(config.port) != 0) throw std::runtime_error("Cannot bind DNS UDP port " + std::to_string(config.port));
        std::vector<std::unique_ptr<DnsContext>> contexts;
        for (int i = 0; i < config.dnsThreads; ++i) {
            auto context = std::make_unique<DnsContext>();
            context->options = {config.port, config.ttl, config.nsTtl,
                                config.host.c_str(), config.ns.c_str(), config.mbox.c_str(), GetIPList, context.get(), 0};
            context->cache = &cache;
            auto* ptr = context.get();
            contexts.push_back(std::move(context));
            std::thread([ptr] {
                if (dnsserver(&ptr->options) != 0) {
                    std::cerr << "DNS worker failed\n";
                    std::_Exit(1);
                }
            }).detach();
        }
        std::cerr << "Serving " << config.host << " on UDP port " << config.port
                  << "; RPC polling every " << config.pollSeconds << " seconds\n";
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(config.pollSeconds));
            Poll(config, cache, receivedActiveNodes);
        }
    } catch (const std::exception& error) {
        std::cerr << "dnsseed: " << error.what() << '\n';
        return 1;
    }
}
