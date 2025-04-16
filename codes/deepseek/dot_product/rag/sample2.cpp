#include <iostream>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <chrono>
#include <numeric>
#include <random>
#include <seal/seal.h>

using namespace std;
using namespace seal;

// Memory tracker for large graph operations
class MemoryTracker {
private:
    size_t total_memory = 0;
    mutex memory_mutex;

public:
    void add_memory(size_t bytes) {
        lock_guard<mutex> lock(memory_mutex);
        total_memory += bytes;
    }

    void free_memory(size_t bytes) {
        lock_guard<mutex> lock(memory_mutex);
        total_memory -= bytes;
    }

    size_t get_total_memory() const {
        return total_memory;
    }

    void print_memory_usage() const {
        cout << "Current memory usage: " << (total_memory / (1024 * 1024)) << " MB" << endl;
    }
};

// Thread-safe parallel vector initializer
class ParallelVectorInitializer {
private:
    mutex init_mutex;
    MemoryTracker& memory_tracker;

public:
    ParallelVectorInitializer(MemoryTracker& tracker) : memory_tracker(tracker) {}

    vector<double> initialize_random_vector(size_t size, double min_val = -1.0, double max_val = 1.0) {
        vector<double> vec(size);
        random_device rd;
        mt19937 gen(rd());
        uniform_real_distribution<> dist(min_val, max_val);

        // Parallel initialization
        size_t num_threads = thread::hardware_concurrency();
        vector<thread> threads;

        auto worker = [&](size_t start, size_t end) {
            for (size_t i = start; i < end; ++i) {
                vec[i] = dist(gen);
            }
        };

        size_t chunk_size = size / num_threads;
        for (size_t t = 0; t < num_threads; ++t) {
            size_t start = t * chunk_size;
            size_t end = (t == num_threads - 1) ? size : start + chunk_size;
            threads.emplace_back(worker, start, end);
        }

        for (auto& t : threads) {
            t.join();
        }

        // Track memory
        memory_tracker.add_memory(size * sizeof(double));
        return vec;
    }
};

// CKKS Dot Product Processor
class CKKSDotProduct {
private:
    unique_ptr<SEALContext> context;
    unique_ptr<CKKSEncoder> encoder;
    unique_ptr<Encryptor> encryptor;
    unique_ptr<Evaluator> evaluator;
    unique_ptr<Decryptor> decryptor;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    MemoryTracker& memory_tracker;

    // Modulus switching parameters
    vector<Modulus> coeff_modulus;
    size_t poly_modulus_degree;
    size_t scale_power;
    double scale;

public:
    CKKSDotProduct(MemoryTracker& tracker, size_t poly_modulus_degree = 8192, int scale_power = 30)
        : memory_tracker(tracker), poly_modulus_degree(poly_modulus_degree), scale_power(scale_power) {
        
        // Initialize SEAL parameters
        EncryptionParameters params(scheme_type::ckks);
        params.set_poly_modulus_degree(poly_modulus_degree);
        
        // Custom coefficient modulus for modulus switching
        coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 40, 30, 30, 40 });
        params.set_coeff_modulus(coeff_modulus);
        
        scale = pow(2.0, scale_power);
        
        // Create SEAL context
        context = make_unique<SEALContext>(params, true, sec_level_type::tc128);
        
        // Generate keys
        KeyGenerator keygen(*context);
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);
        keygen.create_galois_keys(galois_keys);
        
        // Initialize crypto components
        encoder = make_unique<CKKSEncoder>(*context);
        encryptor = make_unique<Encryptor>(*context, public_key);
        evaluator = make_unique<Evaluator>(*context);
        decryptor = make_unique<Decryptor>(*context, secret_key);
        
        // Track memory usage
        size_t key_memory = poly_modulus_degree * coeff_modulus.size() * sizeof(uint64_t) * 4;
        memory_tracker.add_memory(key_memory);
    }

    ~CKKSDotProduct() {
        size_t key_memory = poly_modulus_degree * coeff_modulus.size() * sizeof(uint64_t) * 4;
        memory_tracker.free_memory(key_memory);
    }

    // Batch encode graph embeddings into polynomials
    vector<Plaintext> batch_encode_embeddings(const vector<vector<double>>& embeddings) {
        vector<Plaintext> plaintexts(embeddings.size());
        
        for (size_t i = 0; i < embeddings.size(); ++i) {
            Plaintext pt;
            encoder->encode(embeddings[i], scale, pt);
            plaintexts[i] = move(pt);
        }
        
        // Track memory
        size_t mem_used = embeddings.size() * poly_modulus_degree * coeff_modulus.size() * sizeof(uint64_t);
        memory_tracker.add_memory(mem_used);
        
        return plaintexts;
    }

    // Encrypt plaintexts
    vector<Ciphertext> batch_encrypt(const vector<Plaintext>& plaintexts) {
        vector<Ciphertext> ciphertexts(plaintexts.size());
        
        for (size_t i = 0; i < plaintexts.size(); ++i) {
            encryptor->encrypt(plaintexts[i], ciphertexts[i]);
        }
        
        // Track memory
        size_t mem_used = plaintexts.size() * 2 * poly_modulus_degree * coeff_modulus.size() * sizeof(uint64_t);
        memory_tracker.add_memory(mem_used);
        
        return ciphertexts;
    }

    // Perform secure dot product with modulus switching
    Ciphertext secure_dot_product(const Ciphertext& ct1, const Ciphertext& ct2, bool track_progress = true) {
        Ciphertext result;
        
        // Step 1: Multiply
        if (track_progress) cout << "Multiplying ciphertexts..." << endl;
        evaluator->multiply(ct1, ct2, result);
        
        // Step 2: Relinearize
        if (track_progress) cout << "Relinearizing..." << endl;
        evaluator->relinearize_inplace(result, relin_keys);
        
        // Modulus switching with progress tracking
        for (size_t i = 0; i < coeff_modulus.size() - 1; ++i) {
            if (track_progress) {
                cout << "Modulus switching level " << i + 1 << " of " << coeff_modulus.size() - 1 << endl;
            }
            evaluator->mod_switch_to_next_inplace(result);
        }
        
        return result;
    }

    // Selective extraction from packed polynomials
    vector<double> selective_extract(const Ciphertext& ct, size_t start_idx, size_t length) {
        Plaintext pt;
        decryptor->decrypt(ct, pt);
        
        vector<double> full_result;
        encoder->decode(pt, full_result);
        
        // Extract the desired portion
        vector<double> result(length);
        copy(full_result.begin() + start_idx, full_result.begin() + start_idx + length, result.begin());
        
        return result;
    }

    // Get the scale used for encoding
    double get_scale() const {
        return scale;
    }

    // Get the context for external operations
    const SEALContext& get_context() const {
        return *context;
    }
};

// Example usage for Graph-RAG system
int main() {
    try {
        MemoryTracker memory_tracker;
        
        // Initialize random vectors (graph embeddings)
        ParallelVectorInitializer vector_initializer(memory_tracker);
        size_t embedding_size = 2048; // Reduced size for demo
        size_t num_embeddings = 5;   // Fewer embeddings for demo
        
        cout << "Initializing graph embeddings..." << endl;
        vector<vector<double>> embeddings(num_embeddings);
        for (auto& emb : embeddings) {
            emb = vector_initializer.initialize_random_vector(embedding_size, -0.5, 0.5); // Smaller range
        }
        memory_tracker.print_memory_usage();
        
        // Set up CKKS environment
        cout << "Setting up CKKS environment..." << endl;
        CKKSDotProduct ckks_processor(memory_tracker, 8192, 30); // Explicit parameters
        memory_tracker.print_memory_usage();
        
        // Batch encode and encrypt embeddings
        cout << "Encoding and encrypting embeddings..." << endl;
        auto plaintexts = ckks_processor.batch_encode_embeddings(embeddings);
        auto ciphertexts = ckks_processor.batch_encrypt(plaintexts);
        memory_tracker.print_memory_usage();
        
        // Perform secure dot product between first two embeddings
        cout << "Computing secure dot product..." << endl;
        auto start_time = chrono::high_resolution_clock::now();
        
        Ciphertext dot_product = ckks_processor.secure_dot_product(ciphertexts[0], ciphertexts[1]);
        
        auto end_time = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        cout << "Dot product computation took " << duration.count() << " ms" << endl;
        memory_tracker.print_memory_usage();
        
        // Extract and verify the result
        cout << "Extracting results..." << endl;
        vector<double> result = ckks_processor.selective_extract(dot_product, 0, min(embedding_size, 10UL)); // Only show first 10
        
        // Compute expected result
        double expected = inner_product(
            embeddings[0].begin(), 
            embeddings[0].begin() + min(embedding_size, 10UL),
            embeddings[1].begin(), 
            0.0
        );
        double actual = accumulate(result.begin(), result.end(), 0.0);
        
        cout << "Expected dot product (first 10 elements): " << expected << endl;
        cout << "Computed dot product: " << actual << endl;
        cout << "Relative error: " << abs(expected - actual) / max(abs(expected), 1e-6) * 100 << "%" << endl;
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}