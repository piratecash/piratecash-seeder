#ifndef DNSSEED_RPC_H
#define DNSSEED_RPC_H

#include "config.h"
extern "C" {
#include "dns.h"
}

#include <memory>
#include <mutex>
#include <string>
#include <vector>

using Addresses = std::vector<addr_t>;

// Immutable snapshots keep DNS workers independent of RPC network activity.
class AddressCache {
    std::mutex mutex;
    std::shared_ptr<const Addresses> current;
public:
    explicit AddressCache(Addresses bootstrap);
    void Replace(Addresses addresses);
    std::shared_ptr<const Addresses> Snapshot();
};

Addresses ParseBootstrap(const std::string& nodes);
Addresses ParseMasternodes(const std::string& response);
Addresses FetchMasternodes(const Config& config);

#endif
