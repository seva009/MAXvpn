#include <iostream>
#include <rtc/rtc.hpp>
#include <thread>
#include <chrono>

int main() {
    rtc::InitLogger(rtc::LogLevel::Info);
    rtc::WebSocket ws;
    bool connected = false;

    ws.onOpen([&]() {
        std::cout << "[WS] OPENED successfully!" << std::endl;
        connected = true;
    });

    ws.onError([](std::string err) {
        std::cerr << "[WS Error]: " << err << std::endl;
    });

    ws.onClosed([]() {
        std::cout << "[WS Closed]" << std::endl;
    });

    std::cout << "Connecting to wss://api.oneme.ru/websocket..." << std::endl;
    ws.open("wss://api.oneme.ru/websocket");

    for (int i = 0; i < 30; ++i) {
        if (connected) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (connected) {
        std::cout << "SUCCESS! Connected to OneMe gateway without extra headers!" << std::endl;
    } else {
        std::cout << "Failed / Timed out." << std::endl;
    }
    return 0;
}
