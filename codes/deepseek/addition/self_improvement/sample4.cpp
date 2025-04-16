#include <seal/seal.h>
#include <vector>
#include <iostream>
#include <thread>
#include <mutex>
using namespace seal;
using namespace std;

// Thread-safe function to fill vector chunks
void fill_chunk(vector<double>& vec, size_t start, size_t end, double multiplier) {
    for (size_t i = start; i < end; i++) {
        vec[i] = multiplier * i;
    }
}

int main() {
    // Basic setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 30, 50}));
    
    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    // Core operations (remain serial)
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    Decryptor decryptor(context, secret_key);
    
    // Parallel vector initialization using C++ threads
    constexpr size_t N = 10000;
    vector<double> input(N), input2(N);
    
    // Determine number of threads
    unsigned num_threads = thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4; // Fallback
    
    vector<thread> threads;
    size_t chunk_size = N / num_threads;
    
    // Launch threads
    for (unsigned t = 0; t < num_threads; t++) {
        size_t start = t * chunk_size;
        size_t end = (t == num_threads - 1) ? N : start + chunk_size;
        
        threads.emplace_back(fill_chunk, ref(input), start, end, 1.1);
        threads.emplace_back(fill_chunk, ref(input2), start, end, 2.2);
    }
    
    // Wait for threads to complete
    for (auto& t : threads) {
        t.join();
    }
    
    // Process in chunks (serial cryptographic operations)
    constexpr size_t crypto_chunk_size = 512;
    for (size_t chunk = 0; chunk < N/crypto_chunk_size; chunk++) {
        size_t start = chunk * crypto_chunk_size;
        size_t end = min(start + crypto_chunk_size, N);
        
        vector<double> chunk1(input.begin()+start, input.begin()+end);
        vector<double> chunk2(input2.begin()+start, input2.begin()+end);
        
        Plaintext plain1, plain2;
        encoder.encode(chunk1, pow(2.0, 40), plain1);
        encoder.encode(chunk2, pow(2.0, 40), plain2);
        
        Ciphertext encrypted1, encrypted2;
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        
        evaluator.add_inplace(encrypted1, encrypted2);
        
        // Verify first chunk
        if (chunk == 0) {
            Plaintext plain_result;
            decryptor.decrypt(encrypted1, plain_result);
            
            vector<double> result;
            encoder.decode(plain_result, result);
            
            cout << "First chunk sample result[0]: " << result[0] << endl;
        }
    }
    
    return 0;
}