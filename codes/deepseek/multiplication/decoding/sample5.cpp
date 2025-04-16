#include <iostream>
#include <vector>
#include <memory>
#ifdef __linux__
#include <sys/resource.h>
#elif _WIN32
#include <windows.h>
#include <psapi.h>
#endif
#include "seal/seal.h"

using namespace std;
using namespace seal;

size_t get_current_memory_usage() {
#ifdef __linux__
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss * 1024; // KB to bytes
#elif _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
    return pmc.WorkingSetSize;
#else
    return 0;
#endif
}

void memory_efficient_matrix_multiplication() {
    cout << "Initial memory: " << get_current_memory_usage() / (1024 * 1024) << " MB" << endl;
    
    // Lean parameters
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 4096; // Smaller poly degree
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, 
        {40, 20, 40}  // Smaller primes
    ));
    
    SEALContext context(params);
    cout << "After context creation: " << get_current_memory_usage() / (1024 * 1024) << " MB" << endl;
    
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    cout << "After key generation: " << get_current_memory_usage() / (1024 * 1024) << " MB" << endl;
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    // Process matrix in 5x5 chunks (25 elements per chunk)
    const size_t chunk_size = 25;
    vector<double> full_matrix(100);
    vector<double> kernel(9, 0.1);
    
    for (size_t i = 0; i < 100; i++) {
        full_matrix[i] = static_cast<double>(i % 10) / 10.0;
    }
    
    // Encode kernel once
    Plaintext plain_kernel;
    encoder.encode(kernel, pow(2.0, 20), plain_kernel);
    
    // Process chunks
    for (size_t chunk_start = 0; chunk_start < 100; chunk_start += chunk_size) {
        size_t current_chunk_size = min(chunk_size, 100 - chunk_start);
        vector<double> chunk(current_chunk_size);
        
        // Copy chunk data
        copy(full_matrix.begin() + chunk_start, 
             full_matrix.begin() + chunk_start + current_chunk_size,
             chunk.begin());
        
        // Encode and encrypt chunk
        Plaintext plain_chunk;
        encoder.encode(chunk, pow(2.0, 20), plain_chunk);
        
        Ciphertext encrypted_chunk;
        encryptor.encrypt(plain_chunk, encrypted_chunk);
        
        cout << "Processing chunk " << (chunk_start / chunk_size) 
             << ", memory: " << get_current_memory_usage() / (1024 * 1024) << " MB" << endl;
        
        // Process chunk
        evaluator.multiply_plain_inplace(encrypted_chunk, plain_kernel);
        evaluator.rescale_to_next_inplace(encrypted_chunk);
        
        // Decrypt and decode
        Plaintext plain_result;
        decryptor.decrypt(encrypted_chunk, plain_result);
        
        vector<double> result;
        encoder.decode(plain_result, result);
        
        cout << "Chunk " << (chunk_start / chunk_size) << " results (first 3 values): ";
        for (size_t i = 0; i < min(3UL, result.size()); i++) {
            cout << result[i] << " ";
        }
        cout << endl;
    }
    
    cout << "Peak memory usage: " << get_current_memory_usage() / (1024 * 1024) << " MB" << endl;
}

int main() {
    memory_efficient_matrix_multiplication();
    return 0;
}