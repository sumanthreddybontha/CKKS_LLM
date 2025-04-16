#include <iostream>
#include <vector>
#include <memory>
#include <cmath>
#include <chrono>
#include "seal/seal.h"

using namespace std;
using namespace seal;

class MemoryTracker {
public:
    static void print_memory_stats(const string& label = "") {
        cout << label << " - Memory stats (simulated)" << endl;
    }
};

struct EncryptedGraphNode {
    vector<Ciphertext> features;
    vector<size_t> neighbors;
};

class ChunkedGraphProcessor {
    shared_ptr<SEALContext> context;
    shared_ptr<CKKSEncoder> encoder;
    shared_ptr<Encryptor> encryptor;
    shared_ptr<Evaluator> evaluator;
    size_t chunk_size;
    size_t poly_modulus_degree;
    double scale;

public:
    ChunkedGraphProcessor(shared_ptr<SEALContext> ctx, 
                         size_t chunk_sz, 
                         size_t poly_mod, 
                         double sc) 
        : context(ctx), chunk_size(chunk_sz), 
          poly_modulus_degree(poly_mod), scale(sc) {
        encoder = make_shared<CKKSEncoder>(*context);
        evaluator = make_shared<Evaluator>(*context);
    }

    void set_encryptor(shared_ptr<Encryptor> enc) {
        encryptor = enc;
    }

    vector<Ciphertext> process_graph(const vector<EncryptedGraphNode>& graph,
                                   const PublicKey& public_key) {
        try {
            MemoryTracker::print_memory_stats("Before processing");
            
            vector<Ciphertext> results;
            size_t total_nodes = graph.size();
            if (total_nodes == 0) return results;

            size_t num_chunks = ceil(static_cast<double>(total_nodes) / chunk_size);

            // Initialize with encrypted zero
            Plaintext zero_plain;
            vector<double> zero_vec(poly_modulus_degree / 2, 0.0);
            encoder->encode(zero_vec, scale, zero_plain);
            
            Ciphertext zero_cipher;
            encryptor->encrypt(zero_plain, zero_cipher);
            results.push_back(zero_cipher);

            for (size_t chunk_idx = 0; chunk_idx < num_chunks; ++chunk_idx) {
                size_t start = chunk_idx * chunk_size;
                size_t end = min((chunk_idx + 1) * chunk_size, total_nodes);

                process_chunk(graph, start, end, results[0]);
                
                MemoryTracker::print_memory_stats("After chunk " + to_string(chunk_idx));
            }

            return results;
        } catch (const exception& e) {
            cerr << "Error in process_graph: " << e.what() << endl;
            throw;
        }
    }

private:
    void process_chunk(const vector<EncryptedGraphNode>& graph,
                      size_t start_idx, size_t end_idx,
                      Ciphertext& result) {
        try {
            for (size_t i = start_idx; i < end_idx; ++i) {
                const auto& node = graph[i];
                
                if (!node.features.empty()) {
                    Ciphertext aggregated;
                    evaluator->add_many(node.features, aggregated);
                    apply_memory_efficient_attention(aggregated);
                    evaluator->add_inplace(result, aggregated);
                }
            }
        } catch (const exception& e) {
            cerr << "Error in process_chunk: " << e.what() << endl;
            throw;
        }
    }

    void apply_memory_efficient_attention(Ciphertext& cipher) {
        try {
            Plaintext attention_weight;
            vector<double> weight(poly_modulus_degree / 2, 0.5);
            encoder->encode(weight, scale, attention_weight);
            evaluator->multiply_plain_inplace(cipher, attention_weight);
        } catch (const exception& e) {
            cerr << "Error in apply_memory_efficient_attention: " << e.what() << endl;
            throw;
        }
    }
};

class GraphRAG {
    shared_ptr<SEALContext> context;
    EncryptionParameters enc_params;
    size_t poly_modulus_degree;
    double scale;
    size_t chunk_size;

public:
    GraphRAG(size_t poly_mod = 4096, double sc = pow(2.0, 20)) 
        : poly_modulus_degree(poly_mod), scale(sc), chunk_size(100) {
        try {
            enc_params = EncryptionParameters(scheme_type::ckks);
            enc_params.set_poly_modulus_degree(poly_modulus_degree);
            enc_params.set_coeff_modulus(CoeffModulus::Create(
                poly_modulus_degree, { 30, 20, 20, 30 }));
            
            context = make_shared<SEALContext>(enc_params);
        } catch (const exception& e) {
            cerr << "Error during initialization: " << e.what() << endl;
            throw;
        }
    }

    void run() {
        try {
            print_parameters();
            
            KeyGenerator keygen(*context);
            auto secret_key = keygen.secret_key();
            PublicKey public_key;
            keygen.create_public_key(public_key);
            
            Encryptor encryptor(*context, public_key);
            Decryptor decryptor(*context, secret_key);
            CKKSEncoder encoder(*context);

            vector<EncryptedGraphNode> graph = create_sample_graph(encoder, encryptor, 500); // Reduced graph size

            ChunkedGraphProcessor processor(context, chunk_size, poly_modulus_degree, scale);
            processor.set_encryptor(make_shared<Encryptor>(*context, public_key));
            
            auto results = processor.process_graph(graph, public_key);

            cout << "Graph processing completed successfully." << endl;
        } catch (const exception& e) {
            cerr << "Error in run(): " << e.what() << endl;
        }
    }

private:
    void print_parameters() {
        cout << "\nGraph-RAG Parameters:" << endl;
        cout << " - Polynomial modulus degree: " << poly_modulus_degree << endl;
        cout << " - Scale: " << scale << endl;
        cout << " - Chunk size: " << chunk_size << endl;
        
        auto context_data = context->first_context_data();
        cout << "\nSEAL Encryption Parameters:" << endl;
        cout << " - Scheme: CKKS" << endl;
        cout << " - Poly modulus degree: " 
             << context_data->parms().poly_modulus_degree() << endl;
        cout << " - Coeff modulus size: " 
             << context_data->parms().coeff_modulus().size() << endl;
    }

    vector<EncryptedGraphNode> create_sample_graph(CKKSEncoder& encoder, 
                                                 Encryptor& encryptor,
                                                 size_t num_nodes) {
        vector<EncryptedGraphNode> graph;
        size_t feature_dim = 5; // Reduced feature dimension
        
        for (size_t i = 0; i < num_nodes; i++) {
            EncryptedGraphNode node;
            
            // Create 1-3 random features per node
            size_t num_features = 1 + (rand() % 3);
            for (size_t j = 0; j < num_features; j++) {
                try {
                    Plaintext feature_plain;
                    vector<double> feature_vals(poly_modulus_degree / 2, 0.0);
                    
                    // Set only first few values to random
                    for (size_t k = 0; k < 10; k++) {
                        feature_vals[k] = static_cast<double>(rand()) / RAND_MAX;
                    }
                    
                    encoder.encode(feature_vals, scale, feature_plain);
                    
                    Ciphertext feature_cipher;
                    encryptor.encrypt(feature_plain, feature_cipher);
                    node.features.push_back(feature_cipher);
                } catch (const exception& e) {
                    cerr << "Error creating node feature: " << e.what() << endl;
                    throw;
                }
            }
            
            // Create 2-5 random neighbors
            size_t num_neighbors = 2 + (rand() % 4);
            for (size_t j = 0; j < num_neighbors; j++) {
                node.neighbors.push_back(rand() % num_nodes);
            }
            
            graph.push_back(node);
        }
        
        return graph;
    }
};

int main() {
    cout << "Memory-Efficient Graph-RAG with SEAL CKKS" << endl;
    
    try {
        GraphRAG rag(4096); // Reduced polynomial modulus degree
        rag.run();
    } catch (const exception& e) {
        cerr << "Fatal error: " << e.what() << endl;
        return -1;
    }
    
    return 0;
}