cmake_minimum_required(VERSION 3.10)
project(PacketFilter)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# WinPcap paths (запазвам твоите пътища)
set(PCAP_INCLUDE_DIR "D:/PROJECTS/C++/WpdPack/Include")
set(PCAP_LIBRARY_DIR "D:/PROJECTS/C++/WpdPack/Lib/x64")

if(NOT EXISTS "${PCAP_INCLUDE_DIR}")
    message(WARNING "WinPcap Include dir not found at: ${PCAP_INCLUDE_DIR}. Check your paths!")
endif()

include_directories(include ${PCAP_INCLUDE_DIR})
link_directories(${PCAP_LIBRARY_DIR})

set(SOURCES
        src/main.cpp
        src/PacketSniffer.cpp
        src/PacketProcessor.cpp
        src/StatisticsCollector.cpp
        src/PacketAnalyzer.cpp
        src/types/Packet.cpp
        src/types/Statistics.cpp
)

add_executable(PacketFilter ${SOURCES})

if(MINGW)
    target_link_options(PacketFilter PRIVATE -static)
endif()

# ПРОМЯНА: Добавена е библиотеката 'Packet', която е част от WinPcap драйвера
target_link_libraries(PacketFilter wpcap Packet ws2_32 iphlpapi)

# ПРОМЯНА: Правилни флагове според операционната система
if(MSVC)
    # Настройки за Visual Studio (Windows)
    target_compile_definitions(PacketFilter PRIVATE -D_WIN32_WINNT=0x0600)
    target_compile_options(PacketFilter PRIVATE
            /W4     # Warning Level 4
            /O2     # Optimize
    )
else()
    # Настройки за GCC/Clang (Linux/MinGW)
    target_compile_options(PacketFilter PRIVATE
            -Wall
            -Wextra
            -O2
            -pthread # Нужен за std::thread на Linux
    )
endif()