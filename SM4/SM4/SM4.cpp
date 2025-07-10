#include <cstdint>
#include <cstdio>
#include <cstring>
#include <immintrin.h>
#include <chrono>

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

int main() {
    uint8_t test_data[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };

    uint8_t secret_key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };

    uint32_t round_keys[32];

    // 密钥扩展
    SM4Cipher::Gen_Round_Keys(secret_key, round_keys);

    // 显示原始数据
    DisplayData("Original plaintext", test_data, 16);

    // 单次加密测试
    uint8_t cipher[16];
    SM4Cipher::ProcessBlock(test_data, cipher, round_keys, false);
    DisplayData("Ciphertext (single run)", cipher, 16);

    // 单次解密测试
    uint8_t decrypted[16];
    SM4Cipher::ProcessBlock(cipher, decrypted, round_keys, true);
    DisplayData("Decrypted plaintext (single run)", decrypted, 16);

    // 性能测试
    RunPerformanceTest(test_data, round_keys, false, "Encryption");
    RunPerformanceTest(cipher, round_keys, true, "Decryption");

    return 0;
}