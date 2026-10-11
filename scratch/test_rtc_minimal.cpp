#include <iostream>
#include <rtc/rtc.hpp>
#include <nlohmann/json.hpp>

int main() {
    rtc::InitLogger(rtc::LogLevel::Info);
    rtc::Configuration config;
    rtc::PeerConnection pc(config);
    nlohmann::json j = {{"status", "ok"}};
    std::cout << "LibDataChannel & nlohmann::json initialized! JSON: " << j.dump() << std::endl;
    return 0;
}
