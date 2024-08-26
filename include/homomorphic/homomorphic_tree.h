#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <homomorphic_encryp.h>

// 节点结构定义
struct TrieNode {
    unordered_map<string, TrieNode*> children; // 关键字到子节点的映射
    bool isEnd = false;                        // 标记是否是前缀末尾
    string nextHop;                            // 存储路由的下一跳信息
};

class HomomorphicRoutingTree {
private:
    TrieNode* root;
    int n, g_p, mu, t;

    // 加密IP，将IP分为四段加密
    vector<string> encryptIP(const string& ip) {
        vector<string> encryptedSegments;
        vector<int> segments = parseIP(ip);
        
        for (int segment : segments) {
            encryptedSegments.push_back(homomorphic_encrypt(segment, n, g_p, mu, t));
        }
        
        return encryptedSegments;
    }

    // 解析IP地址为四段
    vector<int> parseIP(const string& ip) {
        vector<int> segments;
        size_t start = 0, end = ip.find('.');
        
        while (end != string::npos) {
            segments.push_back(stoi(ip.substr(start, end - start)));
            start = end + 1;
            end = ip.find('.', start);
        }
        segments.push_back(stoi(ip.substr(start)));
        
        return segments;
    }

    // 计算当前节点的关键字（同态加运算并解密计算关键值）
    string computeKey(TrieNode* node, const string& encryptedSegment, bool isEnd) {
        string result = homomorphic_add(node->children.empty() ? "0" : node->children.begin()->first, encryptedSegment);
        int value = decrypt(result); // 假设有一个解密函数
        int key = value + 127;

        if (isEnd) {
            node->isEnd = true;
        }
        
        return to_string(key);
    }

    // 计算匹配优先级的辅助函数
    void computePriorityHelper(TrieNode* node) {
        if (!node) return;

        vector<string> keys;
        for (auto& child : node->children) {
            keys.push_back(child.first);
        }

        for (int i = 0; i < keys.size(); ++i) {
            if (keys[i] == "null-node") {
                int l_index = findNonNullLeft(keys, i);
                int r_index = findNonNullRight(keys, i);

                if (l_index != -1 && r_index != -1) {
                    string l_node = keys[l_index];
                    string r_node = keys[r_index];
                    int l_priority = computePrefixMatch(l_node, keys[i]);
                    int r_priority = computePrefixMatch(r_node, keys[i]);

                    if (l_priority > r_priority) {
                        node->children[l_node]->isEnd = true;
                    } else {
                        node->children[r_node]->isEnd = true;
                    }
                }
            }
        }

        for (auto& child : node->children) {
            computePriorityHelper(child.second);
        }
    }

    // 计算最长前缀匹配的个数
    int computePrefixMatch(const string& node, const string& nullNode) {
        int matchCount = 0;
        for (int i = 0; i < node.size() && i < nullNode.size(); ++i) {
            if (node[i] == nullNode[i]) {
                matchCount++;
            } else {
                break;
            }
        }
        return matchCount;
    }

    // 查找左边第一个非null-node的关键字
    int findNonNullLeft(const vector<string>& keys, int index) {
        for (int i = index - 1; i >= 0; --i) {
            if (keys[i] != "null-node") {
                return i;
            }
        }
        return -1;
    }

    // 查找右边第一个非null-node的关键字
    int findNonNullRight(const vector<string>& keys, int index) {
        for (int i = index + 1; i < keys.size(); ++i) {
            if (keys[i] != "null-node") {
                return i;
            }
        }
        return -1;
    }
    
public:
    HomomorphicRoutingTree(int n, int g_p, int mu, int t)
        : n(n), g_p(g_p), mu(mu), t(t), root(new TrieNode()) {}

    // 添加路由条目
    void insertRoute(const string &ip, const string &nextHop) {
        //创建同态树根节点
        TrieNode* currentNode = root;
        //用同态加密ip
        vector<string> encryptedIP = encryptIP(ip);

        for (int i = 0; i < encryptedIP.size(); ++i) {
            string key = computeKey(currentNode, encryptedIP[i], i == encryptedIP.size() - 1);
            if (!currentNode->children.count(key)) {
                currentNode->children[key] = new TrieNode();
            }
            currentNode = currentNode->children[key];
        }

        currentNode->isEnd = true;
        currentNode->nextHop = nextHop;
    }

    // 计算匹配优先级
    void computePriority() {
        computePriorityHelper(root);
    }


};