#include <iostream>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <seal/seal.h>

using namespace std;
using namespace seal;

class MemoryTracker {
private:
    static atomic<size_t> total_memory;
    static mutex memory_mutex;
    
public:
    static void add_memory(size_t bytes) {
        lock_guard<mutex> lock(memory_mutex);
        total_memory += bytes;
    }
    
    static void remove_memory(size_t bytes) {
        lock_guard<mutex> lock(memory_mutex);
        total_memory -= bytes;
    }
    
    static size_t get_total_memory() {
        return total_memory;
    }
};

atomic<size_t> MemoryTracker::total_memory{0};
mutex MemoryTracker::memory_mutex;

class GraphEmbeddingGenerator {
private:
    shared_ptr<SEALContext> context;
    unique_ptr<CKKSEncoder> encoder;
    unique_ptr<Encryptor> encryptor;
    unique_ptr<Decryptor> decryptor;
    unique_ptr<Evaluator> evaluator;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    mutex encoder_mutex;
    
    size_t poly_modulus_degree;
    double scale;
    size_t chunk_size;
    
    atomic<int> current_noise_budget;
    
public:
    GraphEmbeddingGenerator(size_t poly_modulus_degree = 8192, double scale = pow(2.0, 40), 
                          size_t chunk_size = 1024)
        : poly_modulus_degree(poly_modulus_degree), scale(scale), chunk_size(chunk_size) {
        
        EncryptionParameters params(scheme_type::ckks);
        params.set_poly_modulus_degree(poly_modulus_degree);
        
        // More conservative coefficient modulus
        vector<int> bit_sizes = {50, 30, 30, 50, 50}; // Added more primes for better noise management
        params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, bit_sizes));
        
        context = make_shared<SEALContext>(params, true, sec_level_type::tc128);
        
        if (!context->parameters_set()) {
            throw invalid_argument("SEAL parameters are invalid");
        }
        
        encoder = make_unique<CKKSEncoder>(*context);
        
        KeyGenerator keygen(*context);
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);
        
        encryptor = make_unique<Encryptor>(*context, public_key);
        decryptor = make_unique<Decryptor>(*context, secret_key);
        evaluator = make_unique<Evaluator>(*context);
        
        current_noise_budget = 50; // Initial estimate
        
        size_t mem_usage = poly_modulus_degree * sizeof(double) * 2;
        MemoryTracker::add_memory(mem_usage);
    }
    
    ~GraphEmbeddingGenerator() {
        size_t mem_usage = poly_modulus_degree * sizeof(double) * 2;
        MemoryTracker::remove_memory(mem_usage);
    }
    
    vector<Ciphertext> generate_embeddings(const vector<vector<double>>& graph, 
                                         const vector<size_t>& selected_nodes) {
        vector<Ciphertext> results;
        results.reserve(selected_nodes.size());
        
        if (graph.empty()) return results;
        
        size_t slot_count = encoder->slot_count();
        if (graph[0].size() > slot_count) {
            throw invalid_argument("Graph embedding dimension too large for CKKS parameters");
        }
        
        for (size_t chunk_start = 0; chunk_start < graph.size(); chunk_start += chunk_size) {
            size_t chunk_end = min(chunk_start + chunk_size, graph.size());
            
            vector<Plaintext> plain_chunk;
            vector<Ciphertext> encrypted_chunk;
            
            for (size_t i = chunk_start; i < chunk_end; i++) {
                Plaintext pt;
                {
                    lock_guard<mutex> lock(encoder_mutex);
                    encoder->encode(graph[i], scale, pt);
                }
                plain_chunk.push_back(move(pt));
            }
            
            encrypted_chunk.resize(plain_chunk.size());
            for (size_t i = 0; i < plain_chunk.size(); i++) {
                encryptor->encrypt(plain_chunk[i], encrypted_chunk[i]);
            }
            
            for (size_t node : selected_nodes) {
                if (node >= chunk_start && node < chunk_end) {
                    size_t local_idx = node - chunk_start;
                    results.push_back(encrypted_chunk[local_idx]);
                }
            }
        }
        
        return results;
    }
    
    int get_noise_budget(const Ciphertext& ciphertext) {
        try {
            return decryptor->invariant_noise_budget(ciphertext);
        } catch (const exception& e) {
            cerr << "Error getting noise budget: " << e.what() << endl;
            return -1;
        }
    }
};

int main() {
    try {
        cout << "Initializing GraphEmbeddingGenerator..." << endl;
        GraphEmbeddingGenerator generator(8192, pow(2.0, 40), 512);
        
        vector<vector<double>> graph_data(100, vector<double>(128, 0.5)); // Reduced size for testing
        vector<size_t> selected_nodes = {10, 20, 30, 40, 50};
        
        cout << "Generating encrypted embeddings..." << endl;
        auto encrypted_embeddings = generator.generate_embeddings(graph_data, selected_nodes);
        
        cout << "Generated " << encrypted_embeddings.size() << " encrypted embeddings" << endl;
        
        if (!encrypted_embeddings.empty()) {
            int budget = generator.get_noise_budget(encrypted_embeddings[0]);
            cout << "Noise budget for first ciphertext: " << budget << " bits" << endl;
        }
        
        cout << "Memory usage: " << MemoryTracker::get_total_memory() / (1024 * 1024) << " MB" << endl;
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}