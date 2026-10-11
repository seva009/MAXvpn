#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

std::vector<uint8_t> sha256(const std::string& input) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256((const unsigned char*)input.data(), input.size(), hash.data());
    return hash;
}

int main() {
    std::ifstream file("scratch/pkt_from_py.bin", std::ios::binary);
    std::vector<uint8_t> pkt((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::cout << "Read " << pkt.size() << " bytes from Python" << std::endl;

    if (pkt.size() < 12 + 16 + 5) {
        std::cerr << "Packet too short!" << std::endl;
        return 1;
    }

    auto key = sha256("my_secret_key");
    const uint8_t* nonce = pkt.data();
    size_t ct_with_tag_len = pkt.size() - 12;
    size_t ct_len = ct_with_tag_len - 16;
    const uint8_t* ct = pkt.data() + 12;
    const uint8_t* tag = pkt.data() + 12 + ct_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), nonce);

    std::vector<uint8_t> plain(ct_len);
    int outlen = 0;
    EVP_DecryptUpdate(ctx, plain.data(), &outlen, ct, ct_len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    int final_outlen = 0;
    int ret = EVP_DecryptFinal_ex(ctx, plain.data() + outlen, &final_outlen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1) {
        std::cerr << "DECRYPT FAILED!" << std::endl;
        return 1;
    }

    std::cout << "DECRYPT SUCCESS! Plaintext size: " << plain.size() << std::endl;

    uint8_t msg_type = plain[0];
    uint32_t conn_id = ntohl(*(uint32_t*)(plain.data() + 1));
    uint16_t port = ntohs(*(uint16_t*)(plain.data() + 5));
    std::string host((char*)plain.data() + 7, plain.size() - 7);

    std::cout << "msg_type: " << (int)msg_type << std::endl;
    std::cout << "conn_id:  " << conn_id << std::endl;
    std::cout << "port:     " << port << std::endl;
    std::cout << "host:     " << host << std::endl;

    if (msg_type == 1 && conn_id == 12345 && port == 80 && host == "example.com") {
        std::cout << "ALL CHECKS PASSED 100%!" << std::endl;
    }
    return 0;
}
