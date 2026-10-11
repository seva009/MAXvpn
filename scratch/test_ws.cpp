#include <iostream>
#include <rtc/rtc.hpp>
#include <thread>
#include <chrono>

int main() {
    rtc::InitLogger(rtc::LogLevel::Warning);
    rtc::WebSocket ws;
    bool connected = false;

    ws.onOpen([&]() {
        std::cout << "[WS] Connected successfully!" << std::endl;
        connected = true;
    });

    ws.onError([](std::string err) {
        std::cerr << "[WS Error]: " << err << std::endl;
    });

    rtc::WebSocket::Configuration config;
    std::cout << "Connecting to wss://api.oneme.ru/websocket..." << std::endl;
    ws.open("wss://api.oneme.ru/websocket", config);

    for (int i = 0; i < 20; ++i) {
        if (connected) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (connected) {
        std::cout << "SUCCESS! rtc::WebSocket connected to OneMe TLS gateway." << std::endl;
    } else {
        std::cout << "Timed out waiting for connection." << std::endl;
    }
    ws.close();
    return 0;
}
