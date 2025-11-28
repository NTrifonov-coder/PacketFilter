#ifndef STATISTICS_COLLECTOR_H
#define STATISTICS_COLLECTOR_H

#include "types/Statistics.h"
#include "types/Packet.h"
#include <atomic>
#include <thread>
#include <memory>
#include <functional>

class StatisticsCollector {
public:
    using StatsCallback = std::function<void(const SnifferStats&)>;

    StatisticsCollector(const std::shared_ptr<SnifferStats>& stats);
    ~StatisticsCollector();

    void startCollection(int interval_ms = 2000);
    void stopCollection();
    bool isRunning() const;

    void setStatsCallback(const StatsCallback& callback);
    void setLiveStatsEnabled(bool enabled);

    void analyzePacket(const CapturedPacket& packet) const;

private:
    void collectionLoop() const;
    void processIPPacket(const ip* iph) const;

    static const ip* extractIPHeaderFromPacket(const CapturedPacket& packet);

    std::atomic<bool> running_{false};
    std::thread collectionThread_;
    std::shared_ptr<SnifferStats> stats_;
    StatsCallback statsCallback_;
    bool show_live_stats_;
    int collection_interval_ms_;
};

#endif