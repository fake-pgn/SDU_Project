#include "merkle_tree.h"
#include <iostream>
#include <random>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <memory>
#include <cstring> 

using namespace std;

MerkleTree::MerkleTree() {}

// 创建叶子节点
void MerkleTree::createLeaves(const vector<vector<uint8_t>>& data) {
    leaves.clear();
    leaves.reserve(data.size());

    for (const auto& item : data) {
        auto leaf = make_shared<Node>();
        sm3_hash_parallel(item.data(), item.size(), leaf->hash);
        leaves.push_back(leaf);
    }
    // 对叶子节点按哈希值排序
    sort(leaves.begin(), leaves.end(), HashCompare());
}

// 递归构建树
shared_ptr<MerkleTree::Node>
MerkleTree::buildTreeRecursive(vector<shared_ptr<Node>>& nodes) {
    if (nodes.empty()) return nullptr;
    if (nodes.size() == 1) return nodes[0];

    // 如果节点数为奇数，复制最后一个节点
    if (nodes.size() % 2 != 0) {
        auto lastNode = nodes.back();
        auto copyNode = make_shared<Node>();
        memcpy(copyNode->hash, lastNode->hash, 32);
        nodes.push_back(copyNode);
    }

    vector<shared_ptr<Node>> parents;
    parents.reserve(nodes.size() / 2);

    for (size_t i = 0; i < nodes.size(); i += 2) {
        auto parent = make_shared<Node>();
        parent->left = nodes[i];
        parent->right = nodes[i + 1];

        // 计算父节点哈希
        uint8_t combined[64];
        memcpy(combined, nodes[i]->hash, 32);
        memcpy(combined + 32, nodes[i + 1]->hash, 32);
        sm3_hash_parallel(combined, 64, parent->hash);
        nodes[i]->parent = parent;
        nodes[i + 1]->parent = parent;

        parents.push_back(parent);
    }

    return buildTreeRecursive(parents);
}

// 构建 Merkle 树
void MerkleTree::buildTree(const vector<vector<uint8_t>>& data) {
    root = nullptr;
    createLeaves(data);
    vector<shared_ptr<Node>> currentLevel = leaves;
    root = buildTreeRecursive(currentLevel);
}

// 获取根哈希
const uint8_t* MerkleTree::getRootHash() const {
    return root ? root->hash : nullptr;
}

// 查找叶子节点
shared_ptr<MerkleTree::Node>
MerkleTree::findLeaf(const uint8_t* hash) const {
    auto it = lower_bound(leaves.begin(), leaves.end(), hash, HashCompare());

    if (it != leaves.end() && compareHashes((*it)->hash, hash) == 0) {
        return *it;
    }
    return nullptr;
}

// 生成节点证明路径
vector<MerkleTree::ProofNode>
MerkleTree::generateProofPath(shared_ptr<Node> node) const {
    vector<ProofNode> proof;

    while (node && !node->parent.expired()) {
        auto parent = node->parent.lock();
        ProofNode pnode;

        if (parent->left == node) {
            // 当前节点是左子节点
            memcpy(pnode.left, node->hash, 32);
            memcpy(pnode.right, parent->right->hash, 32);
            pnode.isLeft = true;
        }
        else {
            // 当前节点是右子节点
            memcpy(pnode.left, parent->left->hash, 32);
            memcpy(pnode.right, node->hash, 32);
            pnode.isLeft = false;
        }

        proof.push_back(pnode);
        node = parent;
    }

    // 保持从叶子到根的顺序（不反转）
    return proof;
}

// 生成存在性证明
vector<MerkleTree::ProofNode>
MerkleTree::generateInclusionProof(const uint8_t* leafHash) const {
    auto leaf = findLeaf(leafHash);
    if (!leaf) return {};
    return generateProofPath(leaf);
}

// 验证存在性证明
bool MerkleTree::verifyInclusionProof(
    const uint8_t* leafHash,
    const uint8_t* rootHash,
    const vector<ProofNode>& proof) {

    if (proof.empty()) {
        return compareHashes(leafHash, rootHash) == 0;
    }

    uint8_t currentHash[32];
    memcpy(currentHash, leafHash, 32);

    for (const auto& pnode : proof) {
        uint8_t combined[64];

        if (pnode.isLeft) {
            memcpy(combined, currentHash, 32);
            memcpy(combined + 32, pnode.right, 32);
        }
        else {
            memcpy(combined, pnode.left, 32);
            memcpy(combined + 32, currentHash, 32);
        }
        // 计算父节点哈希
        sm3_hash_parallel(combined, 64, currentHash);
    }
    // 验证最终哈希与根哈希一致
    return compareHashes(currentHash, rootHash) == 0;
}

// 比较哈希值
int MerkleTree::compareHashes(const uint8_t* hash1, const uint8_t* hash2) {
    return memcmp(hash1, hash2, 32);
}

// 查找前驱和后继叶子
pair<shared_ptr<MerkleTree::Node>, shared_ptr<MerkleTree::Node>>
MerkleTree::findPredecessorSuccessor(const uint8_t* hash) const {
    auto dummy = make_shared<Node>();
    memcpy(dummy->hash, hash, 32);

    auto it = upper_bound(leaves.begin(), leaves.end(), dummy, HashCompare());

    shared_ptr<Node> predecessor = nullptr;
    shared_ptr<Node> successor = nullptr;

    if (it != leaves.begin()) {
        predecessor = *(it - 1);
    }

    if (it != leaves.end()) {
        successor = *it;
    }
    return { predecessor, successor };
}

// 生成不存在性证明
pair<vector<MerkleTree::ProofNode>, vector<MerkleTree::ProofNode>>
MerkleTree::generateExclusionProof(const uint8_t* nonLeafHash) const {
    auto result = findPredecessorSuccessor(nonLeafHash);
    auto predecessor = result.first;
    auto successor = result.second;

    if (!predecessor || !successor) {
        return {};
    }
    // 验证 nonLeafHash 确实在两者之间
    if (compareHashes(predecessor->hash, nonLeafHash) >= 0 ||
        compareHashes(successor->hash, nonLeafHash) <= 0) {
        return {};
    }
    return {
        generateProofPath(predecessor),
        generateProofPath(successor)
    };
}

// 验证不存在性证明
bool MerkleTree::verifyExclusionProof(
    const uint8_t* nonLeafHash,
    const uint8_t* rootHash,
    const pair<vector<ProofNode>, vector<ProofNode>>& proof) {

    const auto& predProof = proof.first;
    const auto& succProof = proof.second;

    if (predProof.empty() || succProof.empty()) {
        return false;
    }

    // 验证前驱证明 - 提取前驱叶子哈希
    uint8_t predLeafHash[32];
    if (predProof[0].isLeft) {
        memcpy(predLeafHash, predProof[0].left, 32);
    }
    else {
        memcpy(predLeafHash, predProof[0].right, 32);
    }

    if (!verifyInclusionProof(predLeafHash, rootHash, predProof)) {
        return false;
    }

    // 验证后继证明 - 提取后继叶子哈希
    uint8_t succLeafHash[32];
    if (succProof[0].isLeft) {
        memcpy(succLeafHash, succProof[0].left, 32);
    }
    else {
        memcpy(succLeafHash, succProof[0].right, 32);
    }

    if (!verifyInclusionProof(succLeafHash, rootHash, succProof)) {
        return false;
    }

    // 验证 nonLeafHash 在两者之间
    return compareHashes(predLeafHash, nonLeafHash) < 0 &&
        compareHashes(succLeafHash, nonLeafHash) > 0;
}

vector<vector<uint8_t>> generate_data(size_t count, size_t length) {
    vector<vector<uint8_t>> data;
    data.reserve(count);

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<unsigned> dis(0, 255);

    for (size_t i = 0; i < count; i++) {
        vector<uint8_t> item(length);
        for (size_t j = 0; j < length; j++) {
            item[j] = static_cast<uint8_t>(dis(gen));
        }
        data.push_back(item);
    }

    return data;
}

void print_merkle_hash(const uint8_t* hash) {
    for (int i = 0; i < 32; i++) {
        cout << hex << setw(2) << setfill('0')
            << static_cast<int>(hash[i]);
    }
    cout << dec << endl;
}

void print_proof_node(const MerkleTree::ProofNode& node) {
    cout << "ProofNode: " << (node.isLeft ? "Left" : "Right") << endl;
    cout << "  Left:  ";
    print_merkle_hash(node.left);
    cout << "  Right: ";
    print_merkle_hash(node.right);
}

int main() {
    const size_t LEAF_COUNT = 100000;
    const size_t DATA_LENGTH = 64;

    // 生成测试数据
    cout << "生成 " << LEAF_COUNT << " 个叶子的测试数据..." << endl;
    auto testData = generate_data(LEAF_COUNT, DATA_LENGTH);

    // 创建 Merkle 树
    cout << "构建 Merkle 树..." << endl;
    MerkleTree tree;

    auto start = chrono::high_resolution_clock::now();
    tree.buildTree(testData);
    auto end = chrono::high_resolution_clock::now();

    chrono::duration<double> duration = end - start;
    cout << "构建耗时: " << duration.count() << " 秒" << endl;
    cout << "根哈希: ";
    print_merkle_hash(tree.getRootHash());

    // 测试存在性证明
    size_t testIndex = 12345;
    uint8_t testLeafHash[32];
    sm3_hash_parallel(testData[testIndex].data(), testData[testIndex].size(), testLeafHash);

    cout << "\n存在性证明:" << endl;

    start = chrono::high_resolution_clock::now();
    auto inclusionProof = tree.generateInclusionProof(testLeafHash);
    end = chrono::high_resolution_clock::now();
    duration = end - start;

    cout << "证明生成时间: " << duration.count() << " 秒" << endl;
    cout << "路径长度: " << inclusionProof.size() << " 层" << endl;

    start = chrono::high_resolution_clock::now();
    bool valid = MerkleTree::verifyInclusionProof(testLeafHash, tree.getRootHash(), inclusionProof);
    end = chrono::high_resolution_clock::now();
    duration = end - start;

    cout << "验证时间: " << duration.count() << " 秒" << endl;
    cout << "结果: " << (valid ? "有效" : "无效") << endl;

    // 测试不存在性证明 
    vector<uint8_t> nonExistent(DATA_LENGTH, 0x55);
    uint8_t nonExistentHash[32];
    sm3_hash_parallel(nonExistent.data(), nonExistent.size(), nonExistentHash);

    cout << "\n不存在性证明:" << endl;

    start = chrono::high_resolution_clock::now();
    auto exclusionProof = tree.generateExclusionProof(nonExistentHash);
    end = chrono::high_resolution_clock::now();
    duration = end - start;

    cout << "证明生成时间: " << duration.count() << " 秒" << endl;

    start = chrono::high_resolution_clock::now();
    valid = MerkleTree::verifyExclusionProof(
        nonExistentHash, tree.getRootHash(), exclusionProof);
    end = chrono::high_resolution_clock::now();
    duration = end - start;

    cout << "验证时间: " << duration.count() << " 秒" << endl;
    cout << "结果: " << (valid ? "有效" : "无效") << endl;

    return 0;
}