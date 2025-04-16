#include <iostream>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <cmath>
#include <seal/seal.h>

using namespace std;
using namespace seal;

class ParallelCKKSMultiplier {
public:
    ParallelCKKSMultiplier(size_t poly_modulus_degree = 8192,
                         vector<int> bit_sizes = {50, 30, 30, 40},
                         double scale = pow(2.0, 40),
                         size_t num_threads = thread::hardware_concurrency())
        : num_threads_(num_threads ? num_threads : 4) {
        
        // Initialize SEAL context (serial operation)
        EncryptionParameters params(scheme_type::ckks);
        params.set_poly_modulus_degree(poly_modulus_degree);
        params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, bit_sizes));
        
        context_ = make_shared<SEALContext>(params);
        
        // Generate keys (serial operation)
        KeyGenerator keygen(*context_);
        secret_key_ = keygen.secret_key();
        keygen.create_public_key(public_key_);
        keygen.create_relin_keys(relin_keys_);
        
        // Initialize thread-safe components
        encoder_ = make_shared<CKKSEncoder>(*context_);
        encryptor_ = make_shared<Encryptor>(*context_, public_key_);
        evaluator_ = make_shared<Evaluator>(*context_);
        
        scale_ = scale;
        slot_count_ = encoder_->slot_count();
        chunk_size_ = min(static_cast<size_t>(1024), slot_count_);
    }

    vector<double> parallel_multiply(const vector<double>& vec1, const vector<double>& vec2) {
        if (vec1.size() != vec2.size()) {
            throw invalid_argument("Vectors must be of equal length");
        }

        const size_t total_size = vec1.size();
        vector<double> result(total_size, 0.0);
        mutex result_mutex;

        // Parallel vector processing
        auto process_range = [&](size_t start, size_t end) {
            vector<double> local_result(total_size, 0.0);
            Decryptor thread_decryptor(*context_, secret_key_); // Thread-local decryptor

            for (size_t i = start; i < end; i += chunk_size_) {
                size_t current_chunk_size = min(chunk_size_, total_size - i);
                
                // Process chunks
                auto ct1 = process_chunk(vec1, i, current_chunk_size);
                auto ct2 = process_chunk(vec2, i, current_chunk_size);
                
                // Multiply (serial within thread)
                Ciphertext product;
                {
                    lock_guard<mutex> lock(eval_mutex_);
                    evaluator_->multiply(ct1, ct2, product);
                    evaluator_->relinearize_inplace(product, relin_keys_);
                    evaluator_->rescale_to_next_inplace(product);
                }
                
                // Decrypt and decode
                vector<double> chunk_result = decrypt_and_decode(product, thread_decryptor, current_chunk_size);
                
                // Store results
                copy(chunk_result.begin(), chunk_result.end(), local_result.begin() + i);
            }
            
            // Aggregate results
            lock_guard<mutex> lock(result_mutex);
            transform(result.begin(), result.end(), local_result.begin(), result.begin(), plus<double>());
        };

        // Distribute work across threads
        vector<thread> threads;
        size_t chunk = (total_size + num_threads_ - 1) / num_threads_;
        chunk = ((chunk + chunk_size_ - 1) / chunk_size_) * chunk_size_; // Align to chunk boundaries

        for (size_t t = 0; t < num_threads_; ++t) {
            size_t start = t * chunk;
            size_t end = min(start + chunk, total_size);
            if (start < total_size) {
                threads.emplace_back(process_range, start, end);
            }
        }

        // Wait for threads to complete
        for (auto& t : threads) {
            t.join();
        }

        return result;
    }

private:
    shared_ptr<SEALContext> context_;
    SecretKey secret_key_;
    PublicKey public_key_;
    RelinKeys relin_keys_;
    shared_ptr<CKKSEncoder> encoder_;
    shared_ptr<Encryptor> encryptor_;
    shared_ptr<Evaluator> evaluator_;
    mutex eval_mutex_;
    
    double scale_;
    size_t chunk_size_;
    size_t slot_count_;
    size_t num_threads_;

    Ciphertext process_chunk(const vector<double>& vec, size_t start, size_t length) {
        vector<double> chunk(slot_count_, 0.0);
        copy(vec.begin() + start, vec.begin() + start + length, chunk.begin());
        
        Plaintext plain;
        encoder_->encode(chunk, scale_, plain);
        
        Ciphertext cipher;
        encryptor_->encrypt(plain, cipher);
        
        return cipher;
    }

    vector<double> decrypt_and_decode(const Ciphertext& cipher, Decryptor& decryptor, size_t output_length) {
        Plaintext plain;
        decryptor.decrypt(cipher, plain);
        
        vector<double> result;
        encoder_->decode(plain, result);
        result.resize(output_length);
        
        return result;
    }
};

int main() {
    try {
        // Platform-specific memory optimization
#ifdef __linux__
        mlockall(MCL_CURRENT | MCL_FUTURE); // Lock memory to prevent swapping
#endif
        
        ParallelCKKSMultiplier multiplier;
        
        // Parallel vector initialization
        const size_t vec_size = 10000;
        vector<double> vec1(vec_size);
        vector<double> vec2(vec_size);
        
        auto init_vector = [](vector<double>& v, double start, double step) {
            iota(v.begin(), v.end(), start);
            for (auto& x : v) x *= step;
        };
        
        thread t1(init_vector, ref(vec1), 0.0, 0.1);
        thread t2(init_vector, ref(vec2), 1.0, 0.1);
        t1.join();
        t2.join();
        
        cout << "Starting parallel CKKS multiplication..." << endl;
        auto result = multiplier.parallel_multiply(vec1, vec2);
        
        // Verify results
        cout << "\nVerification (first 5 elements):" << endl;
        for (size_t i = 0; i < 5; ++i) {
            cout << vec1[i] << " * " << vec2[i] << " ≈ " << result[i] 
                 << " (expected: " << vec1[i] * vec2[i] << ")" << endl;
        }
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}