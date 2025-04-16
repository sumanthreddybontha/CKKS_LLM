#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <cmath>
#include <algorithm>
#include "seal/seal.h"

using namespace seal;
using namespace std;

class OptimizedDotProduct {
private:
    // SEAL Components
    shared_ptr<SEALContext> context;
    unique_ptr<CKKSEncoder> encoder;
    unique_ptr<Encryptor> encryptor;
    unique_ptr<Evaluator> evaluator;
    unique_ptr<Decryptor> decryptor;
    RelinKeys relin_keys;
    PublicKey public_key;
    SecretKey secret_key;
    double scale;
    size_t poly_modulus_degree;

    // Thread Safety
    mutex crypto_mutex;

    // RAG Hardware Knowledge Base
    struct HardwareProfile {
        string name;
        unsigned thread_count;
        size_t optimal_chunk;
    };

    const vector<HardwareProfile> hardware_db = {
        {"Mobile/Low-End", 2, 1024},
        {"Desktop/Mid-Range", 4, 2048},
        {"Workstation/High-End", 8, 4096},
        {"Server", 16, 8192}
    };

    // Get optimal hardware profile
    const HardwareProfile& get_hardware_profile() const {
        const unsigned hw_threads = thread::hardware_concurrency();
        for (const auto& profile : hardware_db) {
            if (hw_threads >= profile.thread_count) {
                cout << "Using hardware profile: " << profile.name 
                     << " (Threads: " << profile.thread_count
                     << ", Chunk: " << profile.optimal_chunk << ")\n";
                return profile;
            }
        }
        return hardware_db.back();
    }

public:
    OptimizedDotProduct(size_t poly_degree = 8192) : poly_modulus_degree(poly_degree) {
        // Initialize SEAL context
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(poly_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_degree, {50, 40, 50}));

        context = make_shared<SEALContext>(parms);
        encoder = make_unique<CKKSEncoder>(*context);

        // Generate keys
        KeyGenerator keygen(*context);
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);

        encryptor = make_unique<Encryptor>(*context, public_key);
        decryptor = make_unique<Decryptor>(*context, secret_key);
        evaluator = make_unique<Evaluator>(*context);

        scale = pow(2.0, 40);
    }

    // Parallel vector initialization
    vector<double> initialize_vector(size_t size) {
        vector<double> vec(size);
        const auto& hw = get_hardware_profile();
        vector<thread> workers;
        const size_t chunk_size = min(hw.optimal_chunk, size/hw.thread_count);

        auto init_worker = [&](size_t start, size_t end) {
            for (size_t i = start; i < end; i++) {
                vec[i] = (i % 100) / 10.0; // Sample data pattern
            }
        };

        for (unsigned t = 0; t < hw.thread_count; t++) {
            size_t start = t * chunk_size;
            size_t end = (t == hw.thread_count-1) ? size : start + chunk_size;
            workers.emplace_back(init_worker, start, end);
        }

        for (auto& t : workers) t.join();
        return vec;
    }

    // Thread-safe encryption
    Ciphertext encrypt_vector(const vector<double>& vec) {
        lock_guard<mutex> lock(crypto_mutex);
        vector<double> padded_vec(poly_modulus_degree/2, 0.0);
        copy(vec.begin(), vec.end(), padded_vec.begin());

        Plaintext pt;
        encoder->encode(padded_vec, scale, pt);
        Ciphertext ct;
        encryptor->encrypt(pt, ct);
        return ct;
    }

    // Thread-safe dot product computation
    Ciphertext compute_dot_product(const Ciphertext& ct1, const Ciphertext& ct2) {
        lock_guard<mutex> lock(crypto_mutex);
        Ciphertext result;
        evaluator->multiply(ct1, ct2, result);
        evaluator->relinearize_inplace(result, relin_keys);
        evaluator->rescale_to_next_inplace(result);
        return result;
    }

    // Thread-safe decryption
    vector<double> decrypt_result(const Ciphertext& ct) {
        lock_guard<mutex> lock(crypto_mutex);
        Plaintext pt;
        decryptor->decrypt(ct, pt);
        vector<double> result;
        encoder->decode(pt, result);
        return result;
    }
};

int main() {
    OptimizedDotProduct odp;

    // Parallel initialization
    cout << "Initializing vectors..." << endl;
    auto vec1 = odp.initialize_vector(4096);
    auto vec2 = odp.initialize_vector(4096);

    // Serial crypto operations
    cout << "Encrypting vectors..." << endl;
    auto ct1 = odp.encrypt_vector(vec1);
    auto ct2 = odp.encrypt_vector(vec2);

    cout << "Computing dot product..." << endl;
    auto result_ct = odp.compute_dot_product(ct1, ct2);

    cout << "Decrypting result..." << endl;
    auto result = odp.decrypt_result(result_ct);

    // Print sample results
    cout << "First 5 slots of result:" << endl;
    for (int i = 0; i < 5; i++) {
        cout << result[i] << " ";
    }
    cout << endl;

    return 0;
}