#include <iostream>
#include <vector>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

std::vector<uint8_t> sha256(const std::string& input) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256((const unsigned char*)input.data(), input.size(), hash.data());
    return hash;
}

int main() {
    auto key = sha256("test_secret");
    std::cout << "SHA256 key size: " << key.size() << std::endl;

    std::string plaintext = "Hello WebRTC from C++!";
    std::vector<uint8_t> nonce(12);
    RAND_bytes(nonce.data(), 12);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data());

    std::vector<uint8_t> ciphertext(plaintext.size());
    int outlen = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, (const unsigned char*)plaintext.data(), plaintext.size());

    int final_outlen = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &final_outlen);

    std::vector<uint8_t> tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    std::cout << "Encrypted successfully! Ciphertext size: " << outlen << ", Tag size: " << tag.size() << std::endl;

    // Decrypt
    EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(dctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(dctx, NULL, NULL, key.data(), nonce.data());

    std::vector<uint8_t> decrypted(ciphertext.size());
    int dec_len = 0;
    EVP_DecryptUpdate(dctx, decrypted.data(), &dec_len, ciphertext.data(), outlen);

    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
    int ret = EVP_DecryptFinal_ex(dctx, decrypted.data() + dec_len, &final_outlen);
    EVP_CIPHER_CTX_free(dctx);

    std::cout << "Decrypt result: " << ret << " (1 = success)" << std::endl;
    std::string result(decrypted.begin(), decrypted.begin() + dec_len);
    std::cout << "Decrypted text: " << result << std::endl;
    return 0;
}
