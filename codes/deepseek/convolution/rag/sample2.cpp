#include <iostream>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>  // Added for unordered_set
#include <memory>
#include <mutex>
#include <thread>
#include <cmath>          // Added for pow()
#include <algorithm>      // Added for min(), fill()
#include <stdexcept>      // Added for exception handling
#include <seal/seal.h>

using namespace std;
using namespace seal;

class BatchGraphEmbeddings {
private:
    // Graph data structures
    unordered_map<size_t, vector<pair<size_t, vector<double>>>> adjacency_list;
    map<pair<size_t, size_t>, vector<double>> graph_data;
    
    // SEAL context and crypto objects
    shared_ptr<SEALContext> context;
    unique_ptr<CKKSEncoder> encoder;
    unique_ptr<Encryptor> encryptor;
    unique_ptr<Evaluator> evaluator;
    unique_ptr<Decryptor> decryptor;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    
    // Parallel processing and memory management
    mutex mtx;
    size_t poly_modulus_degree;
    double scale;
    size_t slot_count;
    size_t embedding_size;
    size_t padded_size;
    double padding_value = 0.0;
    
    // Encrypted data storage
    struct NodeEncryptionData {
        size_t plain_idx;
        Ciphertext batch_cipher;
    };
    unordered_map<size_t, NodeEncryptionData> edge_embeddings;

public:
    BatchGraphEmbeddings(const map<pair<size_t, size_t>, vector<double>>& graph, 
                        size_t poly_mod = 8192, double scale_pow = 40.0) 
        : graph_data(graph), poly_modulus_degree(poly_mod), scale(pow(2.0, scale_pow)) {
        
        // Initialize SEAL context
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(poly_modulus_degree);
        vector<int> coeff_mod_bit_sizes = {60, 40, 40, 60};
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, coeff_mod_bit_sizes));
        
        context = make_shared<SEALContext>(parms);
        encoder = make_unique<CKKSEncoder>(*context);
        slot_count = encoder->slot_count();
        
        // Generate keys
        KeyGenerator keygen(*context);
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);
        keygen.create_galois_keys(galois_keys);
        
        encryptor = make_unique<Encryptor>(*context, public_key);
        evaluator = make_unique<Evaluator>(*context);
        decryptor = make_unique<Decryptor>(*context, secret_key);
        
        // Preprocess graph data
        preprocess_graph();
    }

private:
    void preprocess_graph() {
        // Build adjacency list
        for (const auto& edge : graph_data) {
            size_t src = edge.first.first;
            size_t tgt = edge.first.second;
            adjacency_list[src].emplace_back(tgt, edge.second);
        }
        
        // Determine embedding size and padding
        if (!graph_data.empty()) {
            embedding_size = graph_data.begin()->second.size();
            padded_size = ((embedding_size + slot_count - 1) / slot_count) * slot_count;
        }
    }

    Plaintext encode_batch(const vector<vector<double>>& vectors) {
        // Flatten and pad the vectors
        vector<double> flat_data;
        for (const auto& vec : vectors) {
            vector<double> padded_vec = vec;
            padded_vec.resize(padded_size, padding_value);
            flat_data.insert(flat_data.end(), padded_vec.begin(), padded_vec.end());
        }
        
        // Pad to full slot count if needed
        if (flat_data.size() < slot_count) {
            flat_data.resize(slot_count, padding_value);
        }
        
        Plaintext plain;
        encoder->encode(flat_data, scale, plain);
        return plain;
    }

    vector<vector<double>> decode_batch(const Plaintext& plain, size_t expected_vectors) {
        vector<double> decoded;
        encoder->decode(plain, decoded);
        
        vector<vector<double>> result;
        for (size_t i = 0; i < expected_vectors; ++i) {
            size_t start = i * padded_size;
            size_t end = start + embedding_size;
            if (end > decoded.size()) break;
            
            vector<double> vec(decoded.begin() + start, decoded.begin() + end);
            result.push_back(vec);
        }
        
        return result;
    }

public:
    void encrypt_embeddings() {
        // Collect all unique nodes
        unordered_set<size_t> unique_nodes;
        for (const auto& edge : graph_data) {
            unique_nodes.insert(edge.first.first);
            unique_nodes.insert(edge.first.second);
        }
        
        // Process in batches
        size_t batch_size = slot_count / padded_size;
        vector<size_t> node_list(unique_nodes.begin(), unique_nodes.end());
        
        for (size_t i = 0; i < node_list.size(); i += batch_size) {
            size_t end = min(i + batch_size, node_list.size());
            vector<size_t> batch_nodes(node_list.begin() + i, node_list.begin() + end);
            
            // Get embeddings for this batch
            vector<vector<double>> embeddings;
            for (size_t node : batch_nodes) {
                if (!adjacency_list[node].empty()) {
                    embeddings.push_back(adjacency_list[node][0].second);
                } else {
                    embeddings.emplace_back(embedding_size, 0.0);
                }
            }
            
            // Encode and encrypt
            Plaintext plain = encode_batch(embeddings);
            Ciphertext cipher;
            encryptor->encrypt(plain, cipher);
            
            // Store with thread-safe access
            lock_guard<mutex> lock(mtx);
            for (size_t j = 0; j < batch_nodes.size(); ++j) {
                edge_embeddings[batch_nodes[j]] = {j, cipher};
            }
        }
    }

    Ciphertext aggregate_neighbors(size_t node, size_t depth = 1) {
        if (adjacency_list.find(node) == adjacency_list.end()) {
            throw invalid_argument("Node not found in graph");
        }
        
        auto node_data = edge_embeddings.find(node);
        if (node_data == edge_embeddings.end()) {
            throw invalid_argument("Encrypted embeddings not found for node");
        }
        
        Ciphertext cipher = node_data->second.batch_cipher;
        size_t idx = node_data->second.plain_idx;
        
        // Create mask to select the target node's embedding
        vector<double> mask(slot_count, 0.0);
        size_t start_pos = idx * padded_size;
        size_t end_pos = start_pos + padded_size;
        fill(mask.begin() + start_pos, mask.begin() + end_pos, 1.0);
        
        // Encode and encrypt the mask
        Plaintext mask_plain;
        encoder->encode(mask, scale, mask_plain);
        Ciphertext mask_cipher;
        encryptor->encrypt(mask_plain, mask_cipher);
        
        // Multiply to isolate the target embedding
        evaluator->multiply_inplace(cipher, mask_cipher);
        evaluator->relinearize_inplace(cipher, relin_keys);
        
        // For multi-hop aggregation, we would add neighbor traversal here
        if (depth > 1) {
            // Implementation for multi-depth aggregation would go here
            // This would involve secure operations to traverse the graph
        }
        
        return cipher;
    }

    // Utility function to demonstrate decryption
    vector<vector<double>> decrypt_batch(const Ciphertext& cipher, size_t expected_vectors) {
        Plaintext plain;
        decryptor->decrypt(cipher, plain);
        return decode_batch(plain, expected_vectors);
    }

    // Thread-safe parallel processing example
    void parallel_aggregation(const vector<size_t>& nodes, size_t depth) {
        vector<thread> threads;
        vector<Ciphertext> results(nodes.size());
        
        for (size_t i = 0; i < nodes.size(); ++i) {
            threads.emplace_back([this, i, &nodes, depth, &results]() {
                try {
                    results[i] = this->aggregate_neighbors(nodes[i], depth);
                } catch (const exception& e) {
                    cerr << "Error processing node " << nodes[i] << ": " << e.what() << endl;
                }
            });
        }
        
        for (auto& t : threads) {
            if (t.joinable()) t.join();
        }
        
        // Process results here...
    }
};

int main() {
    // Example graph data (source, target) -> embedding vector
    map<pair<size_t, size_t>, vector<double>> graph = {
        {{1, 2}, {0.1, 0.2, 0.3}},
        {{1, 3}, {0.4, 0.5, 0.6}},
        {{2, 3}, {0.7, 0.8, 0.9}},
        {{3, 4}, {1.0, 1.1, 1.2}}
    };
    
    try {
        BatchGraphEmbeddings processor(graph);
        processor.encrypt_embeddings();
        
        // Aggregate neighbors for node 1
        Ciphertext result = processor.aggregate_neighbors(1);
        
        // Decrypt to verify (just for demonstration)
        auto decrypted = processor.decrypt_batch(result, 1);
        cout << "Decrypted embedding: ";
        for (double val : decrypted[0]) {
            cout << val << " ";
        }
        cout << endl;
        
        // Parallel processing example
        vector<size_t> nodes_to_process = {1, 2, 3};
        processor.parallel_aggregation(nodes_to_process, 1);
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}