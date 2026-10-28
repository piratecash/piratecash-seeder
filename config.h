#ifndef DNSSEED_CONFIG_H
#define DNSSEED_CONFIG_H

#include <string>

struct Config {
    std::string rpcUrl, rpcUser, rpcPassword, bootstrap;
    std::string host, ns, mbox;
    int pollSeconds, timeoutSeconds, port, dnsThreads, ttl, nsTtl;

    static Config Load(int argc, char** argv);
};

#endif
