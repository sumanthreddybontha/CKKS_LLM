#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <random>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// Simplified Knowledge Graph
class KnowledgeGraph {
public:
    struct Node {
        string id;
        vector<float> embedding;
    };

    void add_node(const string& id, size_t dim) {
        // Initialize with random embeddings
        random_device rd;
        mt19937 gen(rd());
        uniform_real_distribution<float> dist(-1.0, 1.0);
        
        Node node;
        node.id = id;
        node.embedding.resize(dim);
        for (auto& val : node.embedding) {
            val = dist(gen);
        }
        nodes_[id] = node;
    }

    void add_edge(const string& src, const string& dst, float weight) {
        edges_[src].push_back({dst, weight});
    }

    const unordered_map<string, Node>& get_nodes() const { return nodes_; }
    Node& get_node_mutable(const string& id) { return nodes_.at(id); }
    
    const vector<pair<string, float>>& get_edges(const string& node) const {
        static const vector<pair<string, float>> empty;
        auto it = edges_.find(node);
        return it != edges_.end() ? it->second : empty;
    }

private:
    unordered_map<string, Node> nodes_;
    unordered_map<string, vector<pair<string, float>>> edges_;
};

// Graph Embedding Generator
class GraphEmbedder {
public:
    void generate_embeddings(KnowledgeGraph& graph, int epochs = 5) {
        for (int epoch = 0; epoch < epochs; ++epoch) {
            auto nodes_copy = graph.get_nodes();
            for (const auto& [id, _] : nodes_copy) {
                auto& node = graph.get_node_mutable(id);
                vector<float> agg(node.embedding.size(), 0.0f);
                int neighbor_count = 0;
                
                for (const auto& [neighbor, weight] : graph.get_edges(id)) {
                    const auto& neighbor_emb = nodes_copy.at(neighbor).embedding;
                    for (size_t i = 0; i < node.embedding.size(); ++i) {
                        agg[i] += neighbor_emb[i] * weight;
                    }
                    neighbor_count++;
                }

                if (neighbor_count > 0) {
                    for (size_t i = 0; i < node.embedding.size(); ++i) {
                        node.embedding[i] = 0.8f * node.embedding[i] + 0.2f * (agg[i] / neighbor_count);
                    }
                }
            }
        }
    }
};

// HNSW Index with Encrypted Search
class HNSWIndex {
public:
    void build(const KnowledgeGraph& graph) {
        for (const auto& [id, node] : graph.get_nodes()) {
            embeddings_[id] = node.embedding;
        }
    }

    vector<string> knn_search(const vector<float>& query, size_t k) {
        vector<pair<float, string>> scores;
        for (const auto& [id, emb] : embeddings_) {
            float score = cosine_similarity(query, emb);
            scores.emplace_back(score, id);
        }
        
        sort(scores.rbegin(), scores.rend());
        vector<string> result;
        for (size_t i = 0; i < min(k, scores.size()); ++i) {
            result.push_back(scores[i].second);
        }
        return result;
    }

    vector<Ciphertext> encrypt_query(
        const vector<float>& query,
        const CKKSEncoder& encoder,
        const Encryptor& encryptor,
        double scale) const {
        
        vector<Ciphertext> encrypted;
        Plaintext plain;
        vector<double> query_d(query.begin(), query.end());
        encoder.encode(query_d, scale, plain);
        encryptor.encrypt(plain, encrypted.emplace_back());
        return encrypted;
    }

private:
    float cosine_similarity(const vector<float>& a, const vector<float>& b) {
        float dot = 0, norm_a = 0, norm_b = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            dot += a[i] * b[i];
            norm_a += a[i] * a[i];
            norm_b += b[i] * b[i];
        }
        return dot / (sqrt(norm_a) * sqrt(norm_b));
    }

    unordered_map<string, vector<float>> embeddings_;
};

// CKKS Encryption Helper
class CKKSHelper {
public:
    CKKSHelper() {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(8192);
        parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
        context_ = make_shared<SEALContext>(parms);
        
        KeyGenerator keygen(*context_);
        secret_key_ = keygen.secret_key();
        keygen.create_public_key(public_key_);
        keygen.create_relin_keys(relin_keys_);
        
        encoder_ = make_unique<CKKSEncoder>(*context_);
        encryptor_ = make_unique<Encryptor>(*context_, public_key_);
        evaluator_ = make_unique<Evaluator>(*context_);
        decryptor_ = make_unique<Decryptor>(*context_, secret_key_);
    }

    vector<Ciphertext> encrypt(const vector<float>& values, double scale) {
        vector<Ciphertext> encrypted;
        Plaintext plain;
        vector<double> values_d(values.begin(), values.end());
        encoder_->encode(values_d, scale, plain);
        encryptor_->encrypt(plain, encrypted.emplace_back());
        return encrypted;
    }

    vector<float> decrypt(const vector<Ciphertext>& encrypted) {
        vector<float> result;
        Plaintext plain;
        decryptor_->decrypt(encrypted[0], plain);
        
        vector<double> decoded;
        encoder_->decode(plain, decoded);
        result.assign(decoded.begin(), decoded.end());
        return result;
    }

    auto get_encoder() const { return encoder_.get(); }
    auto get_encryptor() const { return encryptor_.get(); }
    auto get_evaluator() const { return evaluator_.get(); }
    auto get_decryptor() const { return decryptor_.get(); }

private:
    shared_ptr<SEALContext> context_;
    SecretKey secret_key_;
    PublicKey public_key_;
    RelinKeys relin_keys_;
    unique_ptr<CKKSEncoder> encoder_;
    unique_ptr<Encryptor> encryptor_;
    unique_ptr<Evaluator> evaluator_;
    unique_ptr<Decryptor> decryptor_;
};

int main() {
    // 1. Create a simple graph
    KnowledgeGraph graph;
    const size_t embedding_dim = 128;
    graph.add_node("A", embedding_dim);
    graph.add_node("B", embedding_dim);
    graph.add_node("C", embedding_dim);
    graph.add_edge("A", "B", 1.0f);
    graph.add_edge("B", "C", 1.0f);
    graph.add_edge("A", "C", 0.5f);

    // 2. Generate embeddings
    GraphEmbedder embedder;
    embedder.generate_embeddings(graph);

    // 3. Build HNSW index
    HNSWIndex index;
    index.build(graph);

    // 4. Setup CKKS encryption
    CKKSHelper ckks;

    // 5. Perform a search
    vector<float> query(embedding_dim, 0.1f); // Example query
    auto results = index.knn_search(query, 2);
    cout << "Top 2 results: ";
    for (const auto& id : results) cout << id << " ";
    cout << endl;

    // 6. Encrypted search
    double scale = pow(2.0, 40);
    auto encrypted_query = index.encrypt_query(
        query, 
        *ckks.get_encoder(), 
        *ckks.get_encryptor(), 
        scale
    );
    
    cout << "Encrypted search completed" << endl;

    return 0;
}