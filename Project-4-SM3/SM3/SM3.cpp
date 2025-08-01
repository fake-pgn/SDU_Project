#include <iostream>
#include <cstring>
#include <cstdint>
#include <iomanip>

// 宏定义（轮函数与移位）
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))
#define FF(x,y,z,j) ((j)<16 ? ((x) ^ (y) ^ (z)) : (((x)&(y)) | ((x)&(z)) | ((y)&(z))))
#define GG(x,y,z,j) ((j)<16 ? ((x) ^ (y) ^ (z)) : (((x)&(y)) | ((~(x))&(z))))

// 64轮轮常量表
const uint32_t T[64] = {
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A
};

// 初始向量 IV
const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// 压缩函数
void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68] = { 0 }, W1[64] = { 0 };

    // 消息扩展
    for (int i = 0; i < 16; ++i) {
        W[i] = (block[4 * i] << 24) |
            (block[4 * i + 1] << 16) |
            (block[4 * i + 2] << 8) |
            (block[4 * i + 3]);
    }

    for (int j = 16; j < 68; ++j) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
    }

    for (int j = 0; j < 64; ++j) {
        W1[j] = W[j] ^ W[j + 4];
    }

    // 压缩变量
    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    for (int j = 0; j < 64; ++j) {
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 更新状态
    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// SM3 主函数
void sm3_hash(const uint8_t* msg, size_t len, uint8_t hash[32]) {
    uint64_t bit_len = len * 8;
    size_t pad_len = ((len + 1 + 8 + 63) / 64) * 64;
    uint8_t* padded = new uint8_t[pad_len];
    memset(padded, 0, pad_len);
    memcpy(padded, msg, len);
    padded[len] = 0x80;
    for (int i = 0; i < 8; ++i) {
        padded[pad_len - 8 + i] = (bit_len >> ((7 - i) * 8)) & 0xFF;
    }

    uint32_t state[8];
    memcpy(state, IV, sizeof(IV));

    for (size_t i = 0; i < pad_len; i += 64) {
        sm3_compress(state, padded + i);
    }

    delete[] padded;

    for (int i = 0; i < 8; ++i) {
        hash[4 * i + 0] = (state[i] >> 24) & 0xFF;
        hash[4 * i + 1] = (state[i] >> 16) & 0xFF;
        hash[4 * i + 2] = (state[i] >> 8) & 0xFF;
        hash[4 * i + 3] = (state[i]) & 0xFF;
    }
}

void print_hash(const uint8_t hash[32]) {
    for (int i = 0; i < 32; ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    std::cout << std::endl;
}

int main() {
    const char* message = "abc";
    uint8_t hash[32];

    sm3_hash((const uint8_t*)message, strlen(message), hash);

    std::cout << "输入: " << message << std::endl;
    std::cout << "SM3摘要: ";
    print_hash(hash);

    const uint8_t expected[32] = {
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
        0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
        0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
        0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
    };
    std::cout << "是否正确: " << (memcmp(hash, expected, 32) == 0 ? "是" : "否") << std::endl;

    return 0;
}
