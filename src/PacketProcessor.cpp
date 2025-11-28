#include "PacketProcessor.h"
#include <iostream>
#include <utility>

PacketProcessor::PacketProcessor(const size_t max_queue_size)
    : max_queue_size_(max_queue_size) {
}

PacketProcessor::~PacketProcessor() {
    stopProcessing();
}

void PacketProcessor::setPacketCallback(PacketCallback callback) {
    packetCallback_ = std::move(callback);
}

void PacketProcessor::setStatisticsCollector(std::shared_ptr<SnifferStats> stats) {
    stats_ = std::move(stats);
}

bool PacketProcessor::addPacket(std::unique_ptr<CapturedPacket> packet) {
    // Заключваме само за бързата проверка и добавянето
    std::lock_guard lock(queueMutex_);

    if (packetQueue_.size() >= max_queue_size_) {
        if (stats_) {
            ++stats_->queue_drops;
        }
        return false;
    }

    packetQueue_.push(std::move(packet));
    queueCV_.notify_one(); // Събуждаме нишката
    return true;
}

void PacketProcessor::startProcessing() {
    if (running_) return;

    running_ = true;
    processingThread_ = std::thread(&PacketProcessor::processingLoop, this);
}

void PacketProcessor::stopProcessing() {
    if (!running_) return;

    running_ = false;
    queueCV_.notify_all(); // Събуждаме нишката, за да може да излезе от wait

    if (processingThread_.joinable()) {
        processingThread_.join();
    }

    // Почистване на останалите пакети (ако има такива след спирането)
    std::lock_guard lock(queueMutex_);
    while (!packetQueue_.empty()) {
        packetQueue_.pop();
    }
}

bool PacketProcessor::isRunning() const {
    return running_;
}

size_t PacketProcessor::getQueueSize() const {
    std::lock_guard lock(queueMutex_);
    return packetQueue_.size();
}

size_t PacketProcessor::getMaxQueueSize() const {
    return max_queue_size_;
}

void PacketProcessor::processingLoop() {
    // while (running_ || !empty) гарантира, че ще обработим опашката докрай
    // дори след като stopProcessing() е извикан (Graceful Shutdown)
    while (running_ || !packetQueue_.empty()) {
        std::unique_ptr<CapturedPacket> packet;

        {
            std::unique_lock<std::mutex> lock(queueMutex_);

            // Чакаме, докато има пакети ИЛИ докато ни спрат
            queueCV_.wait(lock, [this]() {
                return !packetQueue_.empty() || !running_;
            });

            // Ако сме спрени И опашката е празна -> излизаме
            if (!running_ && packetQueue_.empty()) {
                break;
            }

            if (!packetQueue_.empty()) {
                packet = std::move(packetQueue_.front());
                packetQueue_.pop();
            }
        }

        // Обработката е извън критичната секция (lock), за да не блокираме Producer-а
        if (packet) {
            try {
                if (packetCallback_) {
                    packetCallback_(*packet);
                }

            } catch (const std::exception& e) {
                if (stats_) {
                    ++stats_->processing_errors;
                }
                std::cerr << "Error processing packet: " << e.what() << std::endl;
            }
        }
    }
}