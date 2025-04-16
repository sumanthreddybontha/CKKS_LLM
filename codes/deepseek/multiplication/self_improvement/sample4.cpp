#include <iostream>
#include <vector>
#include <numeric>
#include <chrono>
#include <algorithm>
#include <mutex>
#include <thread>
#include <random>
#include <seal/seal.h>

using namespace std;
using namespace seal;

mutex cout_mutex;

void safe_print(const string& message) {
    lock_guard<mutex> lock(cout_mutex);
    cout << message << endl;
}

vector<double> generate_vector_serial(size_t size, double min_val, double max_val) {
    vector<double> result(size);
    random_device rd;
    mt19937 gen(rd());
    uniform_real_distribution<> dis(min_val, max_val);
    
    for (auto& val : result) {
        val = dis(gen);
    }
    
    return result;
}

vector<double> generate_vector_parallel(size_t size, double min_val, double max_val) {
    vector<double> result(size);
    vector<mt19937> generators;
    random_device rd;
    
    for (size_t i = 0; i < thread::hardware_concurrency(); ++i) {
        generators.emplace_back(mt19937(rd()));
    }
    
    vector<thread> threads;
    size_t chunk_size = size / thread::hardware_concurrency();
    
    for (size_t i = 0; i < thread::hardware_concurrency(); ++i) {
        size_t start = i * chunk_size;
        size_t end = (i == thread::hardware_concurrency() - 1) ? size : start + chunk_size;
        
        threads.emplace_back([&, start, end, i]() {
            uniform_real_distribution<> dis(min_val, max_val);
            for (size_t j = start; j < end; ++j) {
                result[j] = dis(generators[i]);
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    return result;
}

template<typename Func>
auto measure_time(Func&& f, const string& operation_name) {
    auto start = chrono::high_resolution_clock::now();
    auto result = f();
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    
    safe_print(operation_name + " took " + to_string(duration) + " ms");
    return make_pair(result, duration);
}

int main() {
    const size_t num_threads = thread::hardware_concurrency();
    safe_print("System supports up to " + to_string(num_threads) + " concurrent threads");
    safe_print("Using " + to_string(num_threads) + " threads for parallel operations");
    
    // Adjusted vector size to match CKKS slot count
    const size_t poly_modulus_degree = 8192;
    const size_t vector_size = poly_modulus_degree / 2; // 4096 elements
    const double min_val = 0.0;
    const double max_val = 10.0;
    
    vector<double> vec_serial, vec_parallel;
    long serial_time, parallel_time;
    
    tie(vec_serial, serial_time) = measure_time(
        [&]() { return generate_vector_serial(vector_size, min_val, max_val); },
        "Serial vector generation"
    );
    
    tie(vec_parallel, parallel_time) = measure_time(
        [&]() { return generate_vector_parallel(vector_size, min_val, max_val); },
        "Parallel vector generation"
    );
    
    if (vec_serial.size() != vec_parallel.size()) {
        cerr << "Error: Vector size mismatch!" << endl;
        return 1;
    }
    
    safe_print("\nPerformance comparison:");
    safe_print("Serial time:   " + to_string(serial_time) + " ms");
    safe_print("Parallel time: " + to_string(parallel_time) + " ms");
    safe_print("Speedup:       " + to_string(static_cast<double>(serial_time) / max(parallel_time, 1L)) + "x");
    
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    
    double scale = pow(2.0, 40);
    
    SEALContext context(parms);
    safe_print("\nEncryption parameters:");
    safe_print("- scheme: CKKS");
    safe_print("- poly_modulus_degree: " + to_string(poly_modulus_degree));
    safe_print("- coeff_modulus size: " + to_string(parms.coeff_modulus().size()));
    safe_print("- slots: " + to_string(vector_size));
    
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    CKKSEncoder encoder(context);
    
    safe_print("\nBatch encoding the parallel-generated vector...");
    Plaintext plain_vec;
    measure_time(
        [&]() { 
            encoder.encode(vec_parallel, scale, plain_vec); 
            return 0; 
        },
        "Batch encoding"
    );
    
    safe_print("\nEncrypting...");
    Ciphertext encrypted_vec;
    measure_time(
        [&]() { 
            encryptor.encrypt(plain_vec, encrypted_vec); 
            return 0; 
        },
        "Encryption"
    );
    
    safe_print("\nPerforming computations (add and multiply)...");
    Ciphertext encrypted_result;
    
    measure_time(
        [&]() {
            Plaintext plain_one;
            encoder.encode(1.0, scale, plain_one);
            evaluator.add_plain_inplace(encrypted_vec, plain_one);
            
            Plaintext plain_two;
            encoder.encode(2.0, scale, plain_two);
            evaluator.multiply_plain_inplace(encrypted_vec, plain_two);
            
            evaluator.relinearize_inplace(encrypted_vec, relin_keys);
            evaluator.rescale_to_next_inplace(encrypted_vec);
            
            encrypted_result = encrypted_vec;
            return 0;
        },
        "Computation pipeline"
    );
    
    safe_print("\nDecrypting and decoding result...");
    Plaintext plain_result;
    vector<double> result;
    
    measure_time(
        [&]() {
            decryptor.decrypt(encrypted_result, plain_result);
            encoder.decode(plain_result, result);
            return 0;
        },
        "Decryption and decoding"
    );
    
    safe_print("\nFirst 5 elements of the result:");
    for (size_t i = 0; i < min(static_cast<size_t>(5), result.size()); ++i) {
        safe_print("Element " + to_string(i) + ": " + to_string(result[i]));
    }
    
    safe_print("\nThread utilization statistics:");
    safe_print("- Vector generation used " + to_string(num_threads) + " threads in parallel");
    safe_print("- All cryptographic operations executed serially");
    
    return 0;
}