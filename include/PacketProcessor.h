#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include "types/Packet.h"
#include "types/Statistics.h"
#include <functional>
#include <memory>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>

class PacketProcessor {
public:
    using PacketCallback = std::function<void(const CapturedPacket&)>;

    PacketProcessor(size_t max_queue_size = 10000);
    ~PacketProcessor();

    // Non-copyable
    PacketProcessor(const PacketProcessor&) = delete;
    PacketProcessor& operator=(const PacketProcessor&) = delete;

    void setPacketCallback(PacketCallback callback);
    void setStatisticsCollector(std::shared_ptr<SnifferStats> stats);

    bool addPacket(std::unique_ptr<CapturedPacket> packet);
    void startProcessing();
    void stopProcessing();
    bool isRunning() const;

    size_t getQueueSize() const;
    size_t getMaxQueueSize() const;

private:
    void processingLoop();

    std::atomic<bool> running_{false};
    std::thread processingThread_;

    std::queue<std::unique_ptr<CapturedPacket>> packetQueue_;
    mutable std::mutex queueMutex_;
    std::condition_variable queueCV_;

    size_t max_queue_size_;
    PacketCallback packetCallback_;
    std::shared_ptr<SnifferStats> stats_;
};

#endif