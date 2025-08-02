#include "SM3.h"

int main() {
    // 原始消息
    const char* message = "abc";
    size_t len_message = strlen(message);

    // 步骤1: 计算原始消息的哈希
    uint8_t original_hash[32];
    sm3_hash_parallel(reinterpret_cast<const uint8_t*>(message), len_message, original_hash);
    std::cout << "原始消息哈希: ";
    print_hash(original_hash);

    // 步骤2: 计算原始消息填充后的长度
    size_t padded_len = calculate_padded_length(len_message);

    // 步骤3: 进行长度扩展攻击
    const char* append_msg = "abc"; // 附加消息
    size_t append_len = strlen(append_msg);
    uint8_t attack_hash[32];
    length_extension_attack(original_hash, append_msg, append_len, padded_len, attack_hash);
    std::cout << "攻击预测哈希: ";
    print_hash(attack_hash);

    // 步骤4: 构造完整消息并计算实际哈希
    // 完整消息 = 原始消息 + 填充 + 附加消息
    uint8_t* padded_orig = new uint8_t[padded_len]();
    memcpy(padded_orig, message, len_message);
    padded_orig[len_message] = 0x80; // SM3填充规则
    uint64_t bit_len_orig = len_message * 8;
    for (int i = 0; i < 8; ++i) {
        padded_orig[padded_len - 8 + i] = (bit_len_orig >> ((7 - i) * 8)) & 0xFF;
    }

    uint8_t* full_msg = new uint8_t[padded_len + append_len];
    memcpy(full_msg, padded_orig, padded_len);
    memcpy(full_msg + padded_len, append_msg, append_len);

    uint8_t actual_hash[32];
    sm3_hash_parallel(full_msg, padded_len + append_len, actual_hash);
    std::cout << "实际完整哈希: ";
    print_hash(actual_hash);

    // 验证攻击是否成功
    if (memcmp(attack_hash, actual_hash, 32) == 0) {
        std::cout << "攻击成功! 哈希值匹配。" << std::endl;
    }
    else {
        std::cout << "攻击失败! 哈希值不匹配。" << std::endl;
    }

    delete[] padded_orig;
    delete[] full_msg;
    return 0;
}