#include <iostream>
#include <iomanip>
#include <vector>
#include <memory>
#include <chrono>
#include "seal/seal.h"

using namespace std;
using namespace seal;
using namespace chrono;

class CKKSOptimizer {
private:
    // Knowledge graph of packing strategies
    struct PackingStrategy {
        size_t poly_degree;
        vector<int> moduli_bits;
        int scale_bits;
        size_t optimal_batch_size;
        string strategy_name;
    };

    vector<PackingStrategy> strategy_graph;

public:
    CKKSOptimizer() {
        // Initialize knowledge graph with packing strategies (would normally come from a DB)
        strategy_graph = {
            {8192, {60, 40, 40, 60}, 40, 4096, "Balanced-8192"},
            {16384, {60, 60, 60, 60}, 50, 8192, "High-Capacity-16384"},
            {32768, {60, 60, 60, 60, 60}, 60, 16384, "Max-Capacity-32768"}
        };
    }

    // RAG Feature 1: Retrieve optimal packing strategy
    PackingStrategy get_optimal_strategy(size_t data_size, const string& hw_profile) {
        // In a real system, this would query the knowledge graph with hardware capabilities
        for (const auto& strategy : strategy_graph) {
            if (data_size <= strategy.poly_degree / 2) {
                cout << "Selected strategy: " << strategy.strategy_name 
                     << " with batch size " << strategy.optimal_batch_size << endl;
                return strategy;
            }
        }
        return strategy_graph.back(); // Default to largest
    }

    // RAG Feature 2: Selective extraction helper
    vector<double> extract_selected_values(const vector<double>& full_vector, 
                                         const vector<size_t>& indices) {
        vector<double> result;
        for (auto idx : indices) {
            if (idx < full_vector.size()) {
                result.push_back(full_vector[idx]);
            }
        }
        return result;
    }

    // RAG Feature 3: Hardware-aware batch size recommendation
    size_t recommend_batch_size(const string& hw_profile) {
        // Simulate hardware detection - in reality would use system profiling
        if (hw_profile.find("highmem") != string::npos) {
            return strategy_graph.back().optimal_batch_size;
        }
        return strategy_graph.front().optimal_batch_size;
    }
};

int main() {
    // Initialize RAG optimizer
    CKKSOptimizer optimizer;

    // Simulation parameters
    const size_t data_size = 4096;
    const string hw_profile = "highmem_xeon";
    vector<size_t> extract_indices = {0, 100, 1000, 4095}; // Positions to verify

    // Get optimal strategy from knowledge graph
    auto strategy = optimizer.get_optimal_strategy(data_size, hw_profile);
    size_t batch_size = optimizer.recommend_batch_size(hw_profile);

    // SEAL setup with optimal parameters
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(strategy.poly_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        strategy.poly_degree, strategy.moduli_bits));

    SEALContext context(parms);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // Crypto components
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Set scale
    double scale = pow(2.0, strategy.scale_bits);

    // Generate full vector of values
    vector<double> input_values(strategy.poly_degree / 2, 0.0);
    for (size_t i = 0; i < input_values.size(); i++) {
        input_values[i] = static_cast<double>(i % 100) / 10.0;
    }

    // Encode and encrypt the full vector
    Plaintext plain;
    encoder.encode(input_values, scale, plain);
    Ciphertext cipher;
    encryptor.encrypt(plain, cipher);

    // Create another vector for operation
    vector<double> input_values2 = input_values;
    for (auto& val : input_values2) { val *= 0.5; }

    Plaintext plain2;
    encoder.encode(input_values2, scale, plain2);
    Ciphertext cipher2;
    encryptor.encrypt(plain2, cipher2);

    // Perform full-vector homomorphic addition
    Ciphertext result;
    auto start = high_resolution_clock::now();
    evaluator.add(cipher, cipher2, result);
    auto stop = high_resolution_clock::now();

    cout << "Vector addition completed in "
         << duration_cast<microseconds>(stop - start).count() << " μs" << endl;

    // Decrypt and decode full result
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    vector<double> full_result;
    encoder.decode(plain_result, full_result);

    // RAG Feature 4: Selective verification
    auto sampled_values = optimizer.extract_selected_values(full_result, extract_indices);
    auto expected_values = optimizer.extract_selected_values(input_values, extract_indices);
    auto expected_values2 = optimizer.extract_selected_values(input_values2, extract_indices);

    cout << "\nSampled verification:" << endl;
    cout << setw(10) << "Index" << setw(15) << "Value1" 
         << setw(15) << "Value2" << setw(15) << "Result" << endl;

    for (size_t i = 0; i < sampled_values.size(); i++) {
        double expected = expected_values[i] + expected_values2[i];
        cout << setw(10) << extract_indices[i] 
             << setw(15) << fixed << setprecision(4) << expected_values[i]
             << setw(15) << expected_values2[i]
             << setw(15) << sampled_values[i]
             << (abs(sampled_values[i] - expected) < 0.001 ? " ✓" : " ✗") << endl;
    }

    return 0;
}