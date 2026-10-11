#include <iostream>
#include <vector>
#include <lz4.h>
#include <nlohmann/json.hpp>

int main() {
    nlohmann::json j = {{"cmd", 0}, {"seq", 1}, {"name", "test"}};
    std::vector<uint8_t> mp = nlohmann::json::to_msgpack(j);
    std::cout << "MsgPack size: " << mp.size() << std::endl;

    auto unpacked = nlohmann::json::from_msgpack(mp);
    std::cout << "Unpacked json: " << unpacked.dump() << std::endl;

    std::string text = "Hello LZ4 compression test from C++!";
    std::vector<char> comp(128);
    int comp_size = LZ4_compress_default(text.data(), comp.data(), text.size(), comp.size());
    std::cout << "Compressed size: " << comp_size << std::endl;

    std::vector<char> decomp(128);
    int decomp_size = LZ4_decompress_safe(comp.data(), decomp.data(), comp_size, decomp.size());
    std::string decomp_str(decomp.data(), decomp_size);
    std::cout << "Decompressed: " << decomp_str << std::endl;

    return 0;
}
