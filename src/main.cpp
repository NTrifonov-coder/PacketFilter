#include "PacketSniffer.h"
#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <csignal>
#include <thread>
#include <chrono>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <termios.h>
    #include <sys/select.h>
#endif

std::unique_ptr<PacketSniffer> global_sniffer;

// =========================================================
// 1. ПРОВЕРКА ЗА ПРАВА
// =========================================================
bool isElevated() {
#ifdef _WIN32
    DWORD fRet = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation,
                                sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) CloseHandle(hToken);
    return fRet;
#else
    return geteuid() == 0;
#endif
}

// =========================================================
// 2. SIGNAL HANDLER
// =========================================================
void signalHandler(int signum) {
    if (global_sniffer && global_sniffer->isRunning()) {
        std::cout << "\n[!] Stopping capture..." << std::endl;
        global_sniffer->stop();
    }
}

// =========================================================
// 3. БЕЗОПАСНА ПРОВЕРКА ЗА Q (НЕ чупи PowerShell!!!)
// =========================================================
bool isKeyPressed() {
#ifdef _WIN32
    if (GetConsoleWindow() == GetForegroundWindow()) {
        SHORT ks = GetKeyState('Q');   // безопасно!
        if (ks & 0x8000) {
            return true;
        }
    }
#endif
    return false;
}

// =========================================================
// 4. HELPERS
// =========================================================
void printUsage(const std::string& program_name) {
    std::cout << "Usage: " << program_name << " [options]\n"
              << "Options:\n"
              << "  -i <interface>    Network interface name\n"
              << "  -f <filter>       BPF filter\n"
              << "  -c <count>        Packet count limit\n"
              << "  -v                Verbose mode\n"
              << "  -q                Quiet mode\n"
              << "  -l                List interfaces\n";
}

std::vector<std::pair<std::string, std::string>> getInterfaceList() {
    std::vector<std::pair<std::string, std::string>> interfaces;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        return interfaces;

    for (const pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::string desc = d->description ? d->description : "No description";
        interfaces.emplace_back(d->name, desc);
    }

    pcap_freealldevs(alldevs);
    return interfaces;
}

std::string chooseInterfaceInteractive() {
    auto interfaces = getInterfaceList();
    if (interfaces.empty()) {
        std::cerr << "No interfaces found! (Admin rights?)" << std::endl;
        return "";
    }

    std::cout << "\n=== Available Interfaces ===" << std::endl;
    for (size_t i = 0; i < interfaces.size(); ++i)
        std::cout << i << ". " << interfaces[i].second << std::endl;

    while (true) {
        std::cout << "Select interface: ";
        std::string input;
        std::getline(std::cin, input);
        try {
            size_t idx = std::stoul(input);
            if (idx < interfaces.size()) return interfaces[idx].first;
        } catch (...) {}
    }
}

// =========================================================
// 5. MAIN
// =========================================================
int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);

    // Проверка за админ права
    if (!isElevated()) {
        std::cerr << "[ERROR] Admin rights required!" << std::endl;
        return 1;
    }

    std::string interface_name, filter_exp;
    size_t packet_count = 0;
    bool verbose = false;
    bool live_stats = true;
    bool list_mode = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) interface_name = argv[++i];
        else if (arg == "-f" && i + 1 < argc) filter_exp = argv[++i];
        else if (arg == "-c" && i + 1 < argc) packet_count = std::stoul(argv[++i]);
        else if (arg == "-v") verbose = true;
        else if (arg == "-q") live_stats = false;
        else if (arg == "-l") list_mode = true;
    }

    if (verbose) live_stats = false;

    if (list_mode) {
        for (const auto&[fst, snd] : getInterfaceList())
            std::cout << snd << "\n";
        return 0;
    }

    try {
        if (interface_name.empty()) {
            interface_name = chooseInterfaceInteractive();
            if (interface_name.empty()) return 1;
        }

        global_sniffer = std::make_unique<PacketSniffer>(packet_count, verbose, live_stats);

        if (!global_sniffer->initialize(interface_name, filter_exp))
            return 1;

        std::cout << "\n=== Starting Sniffer ===\n";
        std::cout << "Press 'Q' to stop...\n";

        global_sniffer->start();

        // Основен цикъл
        while (global_sniffer->isRunning()) {
            if (isKeyPressed()) {
                std::cout << "\n[User Input] Stopping..." << std::endl;
                global_sniffer->stop();
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        global_sniffer->stop();

        std::cout << "\n\n=== Capture Finished ===" << std::endl;
        global_sniffer->printFinalReport();

        global_sniffer.reset();

#ifdef _WIN32
        // ВЪЗСТАНОВЯВА ИНПУТ РЕЖИМА НА POWERSHELL
        const HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode;
        if (GetConsoleMode(hIn, &mode)) {
            SetConsoleMode(hIn,
                           mode | ENABLE_PROCESSED_INPUT |
                           ENABLE_LINE_INPUT |
                           ENABLE_ECHO_INPUT);
        }
        FlushConsoleInputBuffer(hIn);
#endif

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
