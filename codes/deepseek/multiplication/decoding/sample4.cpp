#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include "seal/seal.h"

using namespace std;
using namespace seal;

mutex cout_mutex;

void parallel_matrix_multiplication() {
    // Parameters setup
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, 
        {50, 30, 30, 50}
    ));
    
    SEALContext context(params);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    // Shared cryptographic objects
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    // Parallel data preparation
    const size_t num_threads = 4;
    vector<vector<double>> thread_matrices(num_threads);
    vector<thread> threads;
    
    auto prepare_data = [&](size_t thread_id) {
        vector<double> matrix(100);
        for (size_t i = 0; i < 100; i++) {
            matrix[i] = static_cast<double>((i + thread_id) % 10) / 10.0;
        }
        lock_guard<mutex> lock(cout_mutex);
        thread_matrices[thread_id] = move(matrix);
        cout << "Thread " << thread_id << " prepared data" << endl;
    };
    
    // Launch threads
    for (size_t i = 0; i < num_threads; i++) {
        threads.emplace_back(prepare_data, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    // Common kernel
    vector<double> kernel(9, 0.1);
    Plaintext plain_kernel;
    encoder.encode(kernel, pow(2.0, 30), plain_kernel);
    
    // Process each matrix (serially for crypto ops)
    for (size_t i = 0; i < num_threads; i++) {
        Plaintext plain_matrix;
        encoder.encode(thread_matrices[i], pow(2.0, 30), plain_matrix);
        
        Ciphertext encrypted_matrix;
        encryptor.encrypt(plain_matrix, encrypted_matrix);
        
        evaluator.multiply_plain_inplace(encrypted_matrix, plain_kernel);
        evaluator.rescale_to_next_inplace(encrypted_matrix);
        
        Plaintext plain_result;
        decryptor.decrypt(encrypted_matrix, plain_result);
        
        vector<double> result;
        encoder.decode(plain_result, result);
        
        lock_guard<mutex> lock(cout_mutex);
        cout << "Thread " << i << " results (first 3 values): ";
        for (size_t j = 0; j < 3; j++) {
            cout << result[j] << " ";
        }
        cout << endl;
    }
}

int main() {
    parallel_matrix_multiplication();
    return 0;
}