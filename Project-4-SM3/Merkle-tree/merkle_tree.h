#include "SM3.h"
#include <vector>
#include <string>
#include <algorithm>
#include <functional>
#include <memory>

class MerkleTree {
public:
    struct Node {
        uint8_t hash[32];
        std::shared_ptr<Node> left;
        std::shared_ptr<Node> right;
        std::weak_ptr<Node> parent;

        Node() {
            memset(hash, 0, 32);
        }
    };

    struct ProofNode {
        uint8_t left[32];
        uint8_t right[32];
        bool isLeft;
    };
    MerkleTree();

    void buildTree(const std::vector<std::vector<uint8_t>>& data);

    const uint8_t* getRootHash() const;

    // ���ɴ�����֤��
    std::vector<ProofNode> generateInclusionProof(const uint8_t* leafHash) const;

    // ��֤������֤��
    static bool verifyInclusionProof(const uint8_t* leafHash,
        const uint8_t* rootHash,
        const std::vector<ProofNode>& proof);

    // ���ɲ�������֤��
    std::pair<std::vector<ProofNode>, std::vector<ProofNode>>
        generateExclusionProof(const uint8_t* nonLeafHash) const;

    // ��֤��������֤��
    static bool verifyExclusionProof(const uint8_t* nonLeafHash,
        const uint8_t* rootHash,
        const std::pair<std::vector<ProofNode>,
        std::vector<ProofNode>>&proof);

private:
    std::shared_ptr<Node> root;
    std::vector<std::shared_ptr<Node>> leaves;

    void createLeaves(const std::vector<std::vector<uint8_t>>& data);

    std::shared_ptr<Node> buildTreeRecursive(std::vector<std::shared_ptr<Node>>& nodes);

    std::shared_ptr<Node> findLeaf(const uint8_t* hash) const;

    std::pair<std::shared_ptr<Node>, std::shared_ptr<Node>>
        findPredecessorSuccessor(const uint8_t* hash) const;

    // ���ɽڵ�֤��·��
    std::vector<ProofNode> generateProofPath(std::shared_ptr<Node> node) const;

    // �ȽϹ�ϣֵ
    static int compareHashes(const uint8_t* hash1, const uint8_t* hash2);

    // ��ϣ�ȽϺ���
    struct HashCompare {
        bool operator()(const std::shared_ptr<Node>& a, const std::shared_ptr<Node>& b) const {
            return compareHashes(a->hash, b->hash) < 0;
        }

        bool operator()(const std::shared_ptr<Node>& node, const uint8_t* hash) const {
            return compareHashes(node->hash, hash) < 0;
        }

        bool operator()(const uint8_t* hash, const std::shared_ptr<Node>& node) const {
            return compareHashes(hash, node->hash) < 0;
        }
    };
};