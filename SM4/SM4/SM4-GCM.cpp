#include <cstdint>
#include <cstdio>
#include <cstring>
#include <immintrin.h>
#include <chrono>
#include <stdexcept>

using TimePoint = std::chrono::steady_clock::time_point;
using MicroSec = std::chrono::microseconds;

constexpr uint32_t FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };

constexpr uint32_t CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1,
    0xA8AFB6BD, 0xC4CBD2D9, 0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9, 0xC0C7CED5, 0xDCE3EAF1,
    0xF8FF060D, 0x141B2229, 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209, 0x10171E25, 0x2C333A41,
    0x484F565D, 0x646B7279 };

constexpr uint8_t SBox[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2,
    0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4,
    0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA,
    0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2,
    0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B,
    0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2,
    0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30,
    0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45,
    0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41,
    0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
    0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
    0xD7, 0xCB, 0x39, 0x48 };

// 位操作宏
#define CIRCULAR_SHIFT(val, bits) (((val) << (bits)) | ((val) >> (32 - (bits))))
#define VEC_ROTATE(vec, n) _mm_xor_si128(_mm_slli_epi32(vec, n), _mm_srli_epi32(vec, 32 - (n)))

// 并行异或操作
#define VEC_XOR3(a, b, c) _mm_xor_si128(a, _mm_xor_si128(b, c))
#define VEC_XOR4(a, b, c, d) _mm_xor_si128(a, VEC_XOR3(b, c, d))
#define VEC_XOR5(a, b, c, d, e) _mm_xor_si128(a, VEC_XOR4(b, c, d, e))
#define VEC_XOR6(a, b, c, d, e, f) _mm_xor_si128(a, VEC_XOR5(b, c, d, e, f))

// 密钥加载
#define EXPAND_KEY(idx) \
    k[idx] = (key[(idx)*4] << 24) | (key[(idx)*4+1] << 16) | \
             (key[(idx)*4+2] << 8) | key[(idx)*4+3]; \
    k[idx] ^= FK[idx]

// 密钥扩展迭代
#define KEY_EXPANSION(iter) \
    tmp = k[1] ^ k[2] ^ k[3] ^ CK[iter]; \
    tmp = (SBox[tmp >> 24] << 24) | \
          (SBox[(tmp >> 16) & 0xFF] << 16) | \
          (SBox[(tmp >> 8) & 0xFF] << 8) | \
          SBox[tmp & 0xFF]; \
    round_keys[iter] = k[0] ^ tmp ^ CIRCULAR_SHIFT(tmp, 13) ^ CIRCULAR_SHIFT(tmp, 23); \
    k[0] = k[1]; k[1] = k[2]; k[2] = k[3]; k[3] = round_keys[iter]

// 加密轮迭代
#define CIPHER_ROUND(iter, mode) \
    k_vec = _mm_set1_epi32((mode) ? round_keys[31 - (iter)] : round_keys[iter]); \
    temp_vec = VEC_XOR4(state[1], state[2], state[3], k_vec); \
    temp_vec = CryptoPrimitives::TransformSBox(temp_vec); \
    temp_vec = VEC_XOR6(state[0], temp_vec, VEC_ROTATE(temp_vec, 2), \
        VEC_ROTATE(temp_vec, 10), VEC_ROTATE(temp_vec, 18), \
        VEC_ROTATE(temp_vec, 24)); \
    state[0] = state[1]; state[1] = state[2]; \
    state[2] = state[3]; state[3] = temp_vec

namespace CryptoPrimitives {

    // 有限域变换矩阵
    const __m128i AES_Forward_Matrix = _mm_set_epi8(
        0x22, 0x58, 0x1a, 0x60, 0x02, 0x78, 0x3a, 0x40,
        0x62, 0x18, 0x5a, 0x20, 0x42, 0x38, 0x7a, 0x00);

    const __m128i AES_Reverse_Matrix = _mm_set_epi8(
        0xe2, 0x28, 0x95, 0x5f, 0x69, 0xa3, 0x1e, 0xd4,
        0x36, 0xfc, 0x41, 0x8b, 0xbd, 0x77, 0xca, 0x00);

    const __m128i SM4_Forward_Matrix = _mm_set_epi8(
        0x14, 0x07, 0xc6, 0xd5, 0x6c, 0x7f, 0xbe, 0xad,
        0xb9, 0xaa, 0x6b, 0x78, 0xc1, 0xd2, 0x13, 0x00);

    const __m128i SM4_Reverse_Matrix = _mm_set_epi8(
        0xd8, 0xb8, 0xfa, 0x9a, 0xc5, 0xa5, 0xe7, 0x87,
        0x5f, 0x3f, 0x7d, 0x1d, 0x42, 0x22, 0x60, 0x00);

    // 矩阵乘法变换
    inline __m128i MatrixMul(__m128i x, __m128i upper, __m128i lower) {
        return _mm_xor_si128(
            _mm_shuffle_epi8(lower, _mm_and_si128(x, _mm_set1_epi32(0x0F0F0F0F))),
            _mm_shuffle_epi8(upper, _mm_and_si128(_mm_srli_epi16(x, 4), _mm_set1_epi32(0x0F0F0F0F)))
        );
    }

    // SBox转换（使用AES-NI）
    inline __m128i TransformSBox(__m128i input) {
        const __m128i shuffle_mask = _mm_set_epi8(
            0x03, 0x06, 0x09, 0x0c, 0x0f, 0x02, 0x05, 0x08,
            0x0b, 0x0e, 0x01, 0x04, 0x07, 0x0a, 0x0d, 0x00);

        input = _mm_shuffle_epi8(input, shuffle_mask);
        input = _mm_xor_si128(
            MatrixMul(input, AES_Forward_Matrix, AES_Reverse_Matrix),
            _mm_set1_epi8(0x23));

        input = _mm_aesenclast_si128(input, _mm_setzero_si128());

        return _mm_xor_si128(
            MatrixMul(input, SM4_Forward_Matrix, SM4_Reverse_Matrix),
            _mm_set1_epi8(0x3B));
    }

} // namespace CryptoPrimitives

class SM4Cipher {
public:
    static void Gen_Round_Keys(const uint8_t* key, uint32_t* round_keys) {
        uint32_t k[4];
        uint32_t tmp;

        EXPAND_KEY(0);
        EXPAND_KEY(1);
        EXPAND_KEY(2);
        EXPAND_KEY(3);

        // 完全展开密钥扩展
        KEY_EXPANSION(0);
        KEY_EXPANSION(1);
        KEY_EXPANSION(2);
        KEY_EXPANSION(3);
        KEY_EXPANSION(4);
        KEY_EXPANSION(5);
        KEY_EXPANSION(6);
        KEY_EXPANSION(7);
        KEY_EXPANSION(8);
        KEY_EXPANSION(9);
        KEY_EXPANSION(10);
        KEY_EXPANSION(11);
        KEY_EXPANSION(12);
        KEY_EXPANSION(13);
        KEY_EXPANSION(14);
        KEY_EXPANSION(15);
        KEY_EXPANSION(16);
        KEY_EXPANSION(17);
        KEY_EXPANSION(18);
        KEY_EXPANSION(19);
        KEY_EXPANSION(20);
        KEY_EXPANSION(21);
        KEY_EXPANSION(22);
        KEY_EXPANSION(23);
        KEY_EXPANSION(24);
        KEY_EXPANSION(25);
        KEY_EXPANSION(26);
        KEY_EXPANSION(27);
        KEY_EXPANSION(28);
        KEY_EXPANSION(29);
        KEY_EXPANSION(30);
        KEY_EXPANSION(31);
    }

    static void ProcessBlock(const uint8_t* input, uint8_t* output,
        const uint32_t* round_keys, bool decrypt_mode) {
        __m128i state[4];
        __m128i temp_vec, k_vec;
        const __m128i shuffle_vector = _mm_setr_epi8(
            3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);

        __m128i data_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input));

        // 初始数据重组
        state[0] = _mm_unpacklo_epi64(_mm_unpacklo_epi32(data_block, data_block),
            _mm_unpacklo_epi32(data_block, data_block));
        state[1] = _mm_unpackhi_epi64(_mm_unpacklo_epi32(data_block, data_block),
            _mm_unpacklo_epi32(data_block, data_block));
        state[2] = _mm_unpacklo_epi64(_mm_unpackhi_epi32(data_block, data_block),
            _mm_unpackhi_epi32(data_block, data_block));
        state[3] = _mm_unpackhi_epi64(_mm_unpackhi_epi32(data_block, data_block),
            _mm_unpackhi_epi32(data_block, data_block));

        for (int i = 0; i < 4; i++) {
            state[i] = _mm_shuffle_epi8(state[i], shuffle_vector);
        }

        // 完全展开32轮加密/解密
        CIPHER_ROUND(0, decrypt_mode);
        CIPHER_ROUND(1, decrypt_mode);
        CIPHER_ROUND(2, decrypt_mode);
        CIPHER_ROUND(3, decrypt_mode);
        CIPHER_ROUND(4, decrypt_mode);
        CIPHER_ROUND(5, decrypt_mode);
        CIPHER_ROUND(6, decrypt_mode);
        CIPHER_ROUND(7, decrypt_mode);
        CIPHER_ROUND(8, decrypt_mode);
        CIPHER_ROUND(9, decrypt_mode);
        CIPHER_ROUND(10, decrypt_mode);
        CIPHER_ROUND(11, decrypt_mode);
        CIPHER_ROUND(12, decrypt_mode);
        CIPHER_ROUND(13, decrypt_mode);
        CIPHER_ROUND(14, decrypt_mode);
        CIPHER_ROUND(15, decrypt_mode);
        CIPHER_ROUND(16, decrypt_mode);
        CIPHER_ROUND(17, decrypt_mode);
        CIPHER_ROUND(18, decrypt_mode);
        CIPHER_ROUND(19, decrypt_mode);
        CIPHER_ROUND(20, decrypt_mode);
        CIPHER_ROUND(21, decrypt_mode);
        CIPHER_ROUND(22, decrypt_mode);
        CIPHER_ROUND(23, decrypt_mode);
        CIPHER_ROUND(24, decrypt_mode);
        CIPHER_ROUND(25, decrypt_mode);
        CIPHER_ROUND(26, decrypt_mode);
        CIPHER_ROUND(27, decrypt_mode);
        CIPHER_ROUND(28, decrypt_mode);
        CIPHER_ROUND(29, decrypt_mode);
        CIPHER_ROUND(30, decrypt_mode);
        CIPHER_ROUND(31, decrypt_mode);

        // 最终数据重组
        for (int i = 0; i < 4; i++) {
            state[i] = _mm_shuffle_epi8(state[i], shuffle_vector);
        }

        __m128i result = _mm_unpacklo_epi64(
            _mm_unpacklo_epi32(state[3], state[2]),
            _mm_unpacklo_epi32(state[1], state[0]));

        _mm_storeu_si128(reinterpret_cast<__m128i*>(output), result);
    }
};

// ======================== SM4-GCM 实现 ========================
class SM4_GCM {
private:
    uint32_t round_keys[32];
    uint8_t H[16]; // GHASH子密钥

    // 计数器递增 (32位大端序)
    static void IncrementCounter(uint8_t* counter) {
        for (int i = 15; i >= 12; i--) {
            if (++counter[i] != 0) break;
        }
    }

    // 计算GHASH函数
    void GHASH(const uint8_t* aad, size_t aad_len,
        const uint8_t* ciphertext, size_t cipher_len,
        uint8_t* result) {
        uint8_t buffer[16] = { 0 };

        // 处理AAD
        size_t pos = 0;
        while (pos < aad_len) {
            size_t block_size = (aad_len - pos) > 16 ? 16 : aad_len - pos;
            for (size_t i = 0; i < block_size; i++) {
                buffer[i] ^= aad[pos + i];
            }
            GaloisMultiply(buffer);
            pos += block_size;
        }

        // 处理密文
        pos = 0;
        while (pos < cipher_len) {
            size_t block_size = (cipher_len - pos) > 16 ? 16 : cipher_len - pos;
            for (size_t i = 0; i < block_size; i++) {
                buffer[i] ^= ciphertext[pos + i];
            }
            GaloisMultiply(buffer);
            pos += block_size;
        }

        // 添加长度块 (AAD长度 + 密文长度)
        uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
        uint64_t cipher_bits = static_cast<uint64_t>(cipher_len) * 8;
        for (int i = 7; i >= 0; i--) {
            buffer[15 - i] ^= static_cast<uint8_t>(aad_bits >> (i * 8));
        }
        for (int i = 7; i >= 0; i--) {
            buffer[7 - i] ^= static_cast<uint8_t>(cipher_bits >> (i * 8));
        }
        GaloisMultiply(buffer);

        memcpy(result, buffer, 16);
    }

    // Galois域乘法 (128位)
    void GaloisMultiply(uint8_t* x) {
        uint8_t z[16] = { 0 };
        uint8_t v[16];
        memcpy(v, H, 16);

        for (int i = 0; i < 16; i++) {
            uint8_t byte = x[i];
            for (int j = 7; j >= 0; j--) {
                if (byte & (1 << j)) {
                    for (int k = 0; k < 16; k++) {
                        z[k] ^= v[k];
                    }
                }

                bool lsb = v[15] & 0x01;
                for (int k = 15; k > 0; k--) {
                    v[k] = (v[k] >> 1) | ((v[k - 1] & 0x01) << 7);
                }
                v[0] >>= 1;

                if (lsb) {
                    v[0] ^= 0xE1; // 不可约多项式 x^128 + x^7 + x^2 + x + 1
                }
            }
        }

        memcpy(x, z, 16);
    }

public:
    // 构造函数：生成轮密钥并计算GHASH子密钥
    SM4_GCM(const uint8_t* key) {
        SM4Cipher::Gen_Round_Keys(key, round_keys);

        // 计算H = SM4_Encrypt(0^128)
        uint8_t zero_block[16] = { 0 };
        SM4Cipher::ProcessBlock(zero_block, H, round_keys, false);
    }

    // GCM加密
    void Encrypt(const uint8_t* iv, const uint8_t* aad, size_t aad_len,
        const uint8_t* plaintext, uint8_t* ciphertext, size_t len,
        uint8_t* tag, size_t tag_len = 16) {
        if (tag_len > 16) {
            throw std::invalid_argument("Tag length must be <= 16 bytes");
        }

        uint8_t J0[16]; // 初始计数器
        memcpy(J0, iv, 12);
        memset(J0 + 12, 0, 4);
        J0[15] = 0x01;

        uint8_t counter_block[16];
        memcpy(counter_block, J0, 16);
        IncrementCounter(counter_block); // J0 + 1

        // CTR模式加密
        size_t full_blocks = len / 16;
        size_t remainder = len % 16;

        for (size_t i = 0; i < full_blocks; i++) {
            uint8_t keystream[16];
            SM4Cipher::ProcessBlock(counter_block, keystream, round_keys, false);

            for (int j = 0; j < 16; j++) {
                ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ keystream[j];
            }

            IncrementCounter(counter_block);
        }

        // 处理剩余部分
        if (remainder > 0) {
            uint8_t keystream[16];
            SM4Cipher::ProcessBlock(counter_block, keystream, round_keys, false);

            for (size_t j = 0; j < remainder; j++) {
                ciphertext[full_blocks * 16 + j] =
                    plaintext[full_blocks * 16 + j] ^ keystream[j];
            }
        }

        // 计算GHASH
        uint8_t ghash_result[16];
        GHASH(aad, aad_len, ciphertext, len, ghash_result);

        // 计算认证标签 T = GHASH XOR E(K, J0)
        uint8_t encrypted_J0[16];
        SM4Cipher::ProcessBlock(J0, encrypted_J0, round_keys, false);

        for (size_t i = 0; i < tag_len; i++) {
            tag[i] = ghash_result[i] ^ encrypted_J0[i];
        }
    }

    // GCM解密
    bool Decrypt(const uint8_t* iv, const uint8_t* aad, size_t aad_len,
        const uint8_t* ciphertext, uint8_t* plaintext, size_t len,
        const uint8_t* tag, size_t tag_len = 16) {
        if (tag_len > 16) {
            throw std::invalid_argument("Tag length must be <= 16 bytes");
        }

        // 先计算GHASH
        uint8_t ghash_result[16];
        GHASH(aad, aad_len, ciphertext, len, ghash_result);

        // 计算预期标签
        uint8_t J0[16];
        memcpy(J0, iv, 12);
        memset(J0 + 12, 0, 4);
        J0[15] = 0x01;

        uint8_t encrypted_J0[16];
        SM4Cipher::ProcessBlock(J0, encrypted_J0, round_keys, false);

        uint8_t expected_tag[16];
        for (size_t i = 0; i < tag_len; i++) {
            expected_tag[i] = ghash_result[i] ^ encrypted_J0[i];
        }

        // 验证标签
        if (memcmp(expected_tag, tag, tag_len))
        {
            return false; // 认证失败
        }

        uint8_t counter_block[16];
        memcpy(counter_block, J0, 16);
        IncrementCounter(counter_block); // J0 + 1

        size_t full_blocks = len / 16;
        size_t remainder = len % 16;

        for (size_t i = 0; i < full_blocks; i++) {
            uint8_t keystream[16];
            SM4Cipher::ProcessBlock(counter_block, keystream, round_keys, false);

            for (int j = 0; j < 16; j++) {
                plaintext[i * 16 + j] = ciphertext[i * 16 + j] ^ keystream[j];
            }

            IncrementCounter(counter_block);
        }

        if (remainder > 0) {
            uint8_t keystream[16];
            SM4Cipher::ProcessBlock(counter_block, keystream, round_keys, false);

            for (size_t j = 0; j < remainder; j++) {
                plaintext[full_blocks * 16 + j] =
                    ciphertext[full_blocks * 16 + j] ^ keystream[j];
            }
        }

        return true; // 认证成功
    }
};

// 性能测试函数
void RunPerformanceTest(uint8_t* data, const uint32_t* round_keys,
    bool mode, const char* operation_name, int iterations = 10000) {
    uint8_t temp[16];
    memcpy(temp, data, 16);


    for (int i = 0; i < 1000; i++) {
        SM4Cipher::ProcessBlock(temp, data, round_keys, mode);
    }

    TimePoint start = std::chrono::steady_clock::now();
    for (int i = 0; i < iterations; i++) {
        SM4Cipher::ProcessBlock(temp, data, round_keys, mode);
    }
    TimePoint end = std::chrono::steady_clock::now();

    auto duration = std::chrono::duration_cast<MicroSec>(end - start).count();
    printf("%s time: %.2f μs (avg over %d runs)\n",
        operation_name, duration / (double)iterations, iterations);
}

// 数据输出函数
void DisplayData(const char* label, const uint8_t* data, size_t size) {
    printf("%s:\n", label);
    for (size_t i = 0; i < size; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n\n");
}

// GCM测试函数
void TestSM4_GCM() {
    // 测试向量 (符合NIST标准)
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };

    uint8_t iv[12] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98 };

    uint8_t aad[20] = {
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x41,
        0x41, 0x44, 0x00, 0x00 };
    size_t aad_len = 18; // 实际使用的AAD长度

    uint8_t plaintext[64] = {
        0x53, 0x4D, 0x34, 0x2D, 0x47, 0x43, 0x4D, 0x20,
        0x54, 0x65, 0x73, 0x74, 0x20, 0x50, 0x6C, 0x61,
        0x69, 0x6E, 0x74, 0x65, 0x78, 0x74, 0x20, 0x44,
        0x61, 0x74, 0x61, 0x20, 0x66, 0x6F, 0x72, 0x20,
        0x53, 0x4D, 0x34, 0x2D, 0x47, 0x43, 0x4D, 0x20,
        0x4D, 0x6F, 0x64, 0x65, 0x20, 0x49, 0x6D, 0x70,
        0x6C, 0x65, 0x6D, 0x65, 0x6E, 0x74, 0x61, 0x74,
        0x69, 0x6F, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00 };
    size_t plaintext_len = 60;

    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    uint8_t tag[16];

    // 初始化GCM
    SM4_GCM sm4_gcm(key);

    // 加密
    sm4_gcm.Encrypt(iv, aad, aad_len, plaintext, ciphertext, plaintext_len, tag);

    // 显示结果
    DisplayData("Original plaintext", plaintext, plaintext_len);
    DisplayData("Ciphertext", ciphertext, plaintext_len);
    DisplayData("Authentication Tag", tag, 16);

    // 解密
    bool success = sm4_gcm.Decrypt(iv, aad, aad_len, ciphertext, decrypted, plaintext_len, tag);

    if (success) {
        printf("Authentication successful!\n\n");
        DisplayData("Decrypted plaintext", decrypted, plaintext_len);

        // 验证解密是否正确
        if (memcmp(plaintext, decrypted, plaintext_len)) {
            printf("Decryption error: plaintext mismatch\n");
        }
        else {
            printf("Decryption verified: plaintext matches original\n");
        }
    }
    else {
        printf("Authentication failed!\n");
    }
    // 篡改测试
    printf("\nTesting tamper detection...\n");
    uint8_t tampered_tag[16];
    memcpy(tampered_tag, tag, 16);
    tampered_tag[0] ^= 0x01; // 修改标签

    bool tamper_success = sm4_gcm.Decrypt(iv, aad, aad_len,
        ciphertext, decrypted,
        plaintext_len, tampered_tag);
    if (tamper_success) {
        printf("ERROR: Tampered tag accepted!\n");
    }
    else {
        printf("Tampered tag correctly rejected\n");
    }

}

int main() {
    // SM4-GCM测试
    printf("\n==================== SM4-GCM TEST ====================\n");
    TestSM4_GCM();

    return 0;
}