#include <iostream>
#include <cstring>
#include <cstdint>
#include <iomanip>
#include <immintrin.h>
#include <vector>
#include <thread>
#include <algorithm>
#include <chrono>

// �궨��
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x)&(y)) | ((~(x))&(z)))

const uint32_t Tj[64] = {
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A
};

const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// SIMD��������
inline __m128i mm_rotl_epi32(__m128i x, int n) {
    return _mm_or_si128(_mm_slli_epi32(x, n), _mm_srli_epi32(x, 32 - n));
}

void sm3_compress_optimized(uint32_t state[8], const uint8_t block[64]) {
    // ��Ϣ��չ - ʹ��SIMD����W�������
    uint32_t W[68];

    // ����ǰ16����
    for (int i = 0; i < 16; i++) {
        W[i] = (block[4 * i] << 24) | (block[4 * i + 1] << 16) |
            (block[4 * i + 2] << 8) | block[4 * i + 3];
    }

    // ʹ��SIMD����W[16..67]
    for (int j = 16; j < 68; j++) {
        // ���㵥��W[j] - ���ֱ���������ȷ����ȷ��
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
    }

    // ʹ��SIMD����W1���飨W1[j] = W[j] ^ W[j+4]��
    uint32_t W1[64];
    for (int j = 0; j < 64; j += 4) {
        __m128i wj = _mm_loadu_si128((__m128i*)(W + j));
        __m128i wj4 = _mm_loadu_si128((__m128i*)(W + j + 4));
        __m128i w1 = _mm_xor_si128(wj, wj4);
        _mm_storeu_si128((__m128i*)(W1 + j), w1);
    }

    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    // ��ѭ�� - ʹ��SIMD���ٳ�������
    for (int j = 0; j < 64; j++) {
        // ʹ��SIMDԤ���س�����ÿ�ε���һ��ֵ��
        __m128i tj_vec = _mm_set1_epi32(Tj[j]);
        __m128i w_vec = _mm_set1_epi32(W[j]);
        __m128i w1_vec = _mm_set1_epi32(W1[j]);

        // ��ȡֵ
        uint32_t tj = _mm_extract_epi32(tj_vec, 0);
        uint32_t w_val = _mm_extract_epi32(w_vec, 0);
        uint32_t w1_val = _mm_extract_epi32(w1_vec, 0);

        // ����SS1, SS2
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(tj, j % 32)), 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);

        // ����TT1, TT2
        uint32_t TT1, TT2;
        if (j < 16) {
            TT1 = FF0(A, B, C) + D + SS2 + w1_val;
            TT2 = GG0(E, F, G) + H + SS1 + w_val;
        }
        else {
            TT1 = FF1(A, B, C) + D + SS2 + w1_val;
            TT2 = GG1(E, F, G) + H + SS1 + w_val;
        }

        // ����״̬
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// ���д�������
void process_blocks(uint32_t* state, const uint8_t* blocks, size_t num_blocks) {
    for (size_t i = 0; i < num_blocks; i++) {
        sm3_compress_optimized(state, blocks + i * 64);
    }
}

// �Ż���Ĺ�ϣ���� - ���д�������
void sm3_hash_parallel(const uint8_t* msg, size_t len, uint8_t hash[32]) {
    uint64_t bit_len = static_cast<uint64_t>(len) * 8;
    size_t pad_len = ((len + 1 + 8 + 63) / 64) * 64;
    uint8_t* padded = new uint8_t[pad_len]();
    memcpy(padded, msg, len);
    padded[len] = 0x80;
    for (int i = 0; i < 8; ++i) {
        padded[pad_len - 8 + i] = (bit_len >> ((7 - i) * 8)) & 0xFF;
    }

    uint32_t state[8];
    memcpy(state, IV, sizeof(IV));

    const size_t num_blocks = pad_len / 64;
    const size_t num_threads = std::min<size_t>(std::thread::hardware_concurrency(), num_blocks);

    // ����������ٻ�ֻ��һ���̣߳���˳����
    if (num_blocks < 128 || num_threads <= 1) {
        for (size_t i = 0; i < num_blocks; i++) {
            sm3_compress_optimized(state, padded + i * 64);
        }
    }
    else {
        // Ϊÿ���̴߳���״̬����
        std::vector<std::vector<uint32_t>> thread_states(num_threads, std::vector<uint32_t>(8));
        for (size_t i = 0; i < num_threads; i++) {
            memcpy(thread_states[i].data(), IV, sizeof(IV));
        }

        // ����ÿ���̴߳���Ŀ���
        const size_t blocks_per_thread = num_blocks / num_threads;
        const size_t remaining_blocks = num_blocks % num_threads;

        std::vector<std::thread> threads;
        size_t start_block = 0;

        // �����̴߳�����ԵĿ�
        for (size_t i = 0; i < num_threads; i++) {
            size_t block_count = blocks_per_thread + (i < remaining_blocks ? 1 : 0);
            if (block_count == 0) continue;

            threads.emplace_back([&, i, start_block, block_count]() {
                process_blocks(thread_states[i].data(),
                    padded + start_block * 64,
                    block_count);
                });

            start_block += block_count;
        }

        // �ȴ������߳����
        for (auto& t : threads) {
            t.join();
        }

        // �ϲ�״̬
        memcpy(state, IV, sizeof(IV));
        for (size_t i = 0; i < num_threads; i++) {
            // ���м�״̬��Ϊһ�������ѹ��
            uint8_t state_block[64];
            for (int j = 0; j < 8; j++) {
                state_block[4 * j] = (thread_states[i][j] >> 24) & 0xFF;
                state_block[4 * j + 1] = (thread_states[i][j] >> 16) & 0xFF;
                state_block[4 * j + 2] = (thread_states[i][j] >> 8) & 0xFF;
                state_block[4 * j + 3] = thread_states[i][j] & 0xFF;
            }
            sm3_compress_optimized(state, state_block);
        }
    }

    delete[] padded;

    // �����ϣֵ
    for (int i = 0; i < 8; ++i) {
        hash[4 * i + 0] = (state[i] >> 24) & 0xFF;
        hash[4 * i + 1] = (state[i] >> 16) & 0xFF;
        hash[4 * i + 2] = (state[i] >> 8) & 0xFF;
        hash[4 * i + 3] = state[i] & 0xFF;
    }
}

void sm3_hash_custom_iv(const uint8_t* msg, size_t len, uint8_t hash[32], const uint32_t iv[8], uint64_t total_bit_len) {
    // ������䳤��
    size_t pad_len = ((len + 1 + 8 + 63) / 64) * 64;
    uint8_t* padded = new uint8_t[pad_len]();
    memcpy(padded, msg, len);
    padded[len] = 0x80; // ��ӱ���1

    for (int i = 0; i < 8; ++i) {
        padded[pad_len - 8 + i] = (total_bit_len >> ((7 - i) * 8)) & 0xFF;
    }

    // ��ʼ��״̬��ʹ�ô����IV��
    uint32_t state[8];
    memcpy(state, iv, sizeof(uint32_t) * 8);
    size_t num_blocks = pad_len / 64;
    for (size_t i = 0; i < num_blocks; i++) {
        sm3_compress_optimized(state, padded + i * 64);
    }

    delete[] padded;

    // �����ϣֵ
    for (int i = 0; i < 8; ++i) {
        hash[4 * i + 0] = (state[i] >> 24) & 0xFF;
        hash[4 * i + 1] = (state[i] >> 16) & 0xFF;
        hash[4 * i + 2] = (state[i] >> 8) & 0xFF;
        hash[4 * i + 3] = state[i] & 0xFF;
    }
}

// ������չ��������
void length_extension_attack(const uint8_t* original_hash, const char* append_msg, size_t append_len, size_t original_padded_len, uint8_t new_hash[32]) {
    // ��ԭʼ��ϣֵת��ΪIV���飨�����ת������
    uint32_t iv_state[8];
    for (int i = 0; i < 8; i++) {
        iv_state[i] = (original_hash[4 * i] << 24) |
            (original_hash[4 * i + 1] << 16) |
            (original_hash[4 * i + 2] << 8) |
            original_hash[4 * i + 3];
    }

    // �����ܱ��س��� = (ԭʼ���󳤶� + ������Ϣ����) * 8
    uint64_t total_bit_len = uint64_t(original_padded_len + append_len) * 8;

    // ���㹥���õ��Ĺ�ϣ
    sm3_hash_custom_iv(
        reinterpret_cast<const uint8_t*>(append_msg),
        append_len,
        new_hash,
        iv_state,
        total_bit_len
    );
}

// ����ԭʼ��Ϣ����ĳ���
size_t calculate_padded_length(size_t len) {
    return ((len + 1 + 8 + 63) / 64) * 64;
}


void print_hash(const uint8_t hash[32]) {
    for (int i = 0; i < 32; ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    std::cout << std::endl;
}
/*
int main() {
    const char* message = "abc";
    uint8_t hash[32];
    auto start = std::chrono::high_resolution_clock::now();
    sm3_hash_parallel((const uint8_t*)message, strlen(message), hash);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;

    std::cout << "����: " << message << std::endl;
    std::cout << "SM3ժҪ: ";
    print_hash(hash);

    std::cout << "�����ʱ: " << elapsed.count() << " ms" << std::endl;
    return 0;
}
*/