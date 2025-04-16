#include <seal/seal.h>
#include <vector>
#include <numeric>
#include <thread>
#include <atomic>
#include <memory>
#include <iostream>
#include <algorithm>
#include <cmath>
#include <mutex>

using namespace seal;
using namespace std;

class ParallelDotProduct {
    unique_ptr<SEALContext> context;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;

    unique_ptr<Encryptor> encryptor;
    unique_ptr<Evaluator> evaluator;
    unique_ptr<Decryptor> decryptor;
    unique_ptr<CKKSEncoder> encoder;

    // Parallel processing state
    size_t optimal_chunk_size;
    unsigned optimal_threads;
    mutex performance_mutex;

    double scale;

    void initialize_seal() {
        EncryptionParameters parms(scheme_type::ckks);
        const size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 60}));

        context = make_unique<SEALContext>(parms);
        KeyGenerator keygen(*context);
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);

        encryptor = make_unique<Encryptor>(*context, public_key);
        evaluator = make_unique<Evaluator>(*context);
        decryptor = make_unique<Decryptor>(*context, secret_key);
        encoder = make_unique<CKKSEncoder>(*context);

        scale = pow(2.0, 30);  // Safer scale to avoid overflow

        optimal_threads = max(thread::hardware_concurrency(), 1u);
        optimal_chunk_size = 512;
    }

    double process_chunk(const vector<double>& vec1,
                         const vector<double>& vec2,
                         size_t start,
                         size_t end) {
        vector<double> chunk(end - start);
        transform(vec1.begin() + start, vec1.begin() + end,
                  vec2.begin() + start, chunk.begin(),
                  multiplies<double>());

        Plaintext plain;
        encoder->encode(chunk, scale, plain);

        Ciphertext encrypted;
        encryptor->encrypt(plain, encrypted);
        evaluator->square_inplace(encrypted);
        evaluator->relinearize_inplace(encrypted, relin_keys);

        Plaintext plain_result;
        decryptor->decrypt(encrypted, plain_result);

        vector<double> result;
        encoder->decode(plain_result, result);
        return accumulate(result.begin(), result.end(), 0.0);
    }

    void update_performance_metrics(size_t vector_size,
                                    size_t chunk_size,
                                    double duration_ms) {
        lock_guard<mutex> lock(performance_mutex);
        const double learning_rate = 0.1;
        size_t new_chunk_size = static_cast<size_t>(
            optimal_chunk_size * (1 - learning_rate) +
            chunk_size * learning_rate);

        optimal_chunk_size = 1 << static_cast<size_t>(log2(new_chunk_size) + 0.5);

        cout << "Performance update:\n"
             << "  Chunk size: " << optimal_chunk_size << "\n"
             << "  Threads: " << optimal_threads << "\n"
             << "  Duration: " << duration_ms << "ms\n";
    }

public:
    ParallelDotProduct() {
        initialize_seal();
    }

    double compute(const vector<double>& vec1, const vector<double>& vec2) {
        if (vec1.size() != vec2.size()) {
            throw invalid_argument("Vectors must be same size");
        }

        const size_t total_size = vec1.size();
        size_t chunk_size = min(optimal_chunk_size, total_size);
        unsigned num_threads = min<unsigned>(optimal_threads,
                                             (total_size + chunk_size - 1) / chunk_size);

        vector<thread> workers;
        vector<double> partial_results(num_threads, 0.0);
        atomic<size_t> current_index(0);

        auto start_time = chrono::high_resolution_clock::now();

        for (unsigned t = 0; t < num_threads; ++t) {
            workers.emplace_back([&, t] {
                while (true) {
                    size_t start = current_index.fetch_add(chunk_size);
                    if (start >= total_size) break;

                    size_t end = min(start + chunk_size, total_size);
                    partial_results[t] += process_chunk(vec1, vec2, start, end);
                }
            });
        }

        for (auto& t : workers) t.join();

        auto end_time = chrono::high_resolution_clock::now();
        double duration = chrono::duration_cast<chrono::milliseconds>(
                              end_time - start_time)
                              .count();

        update_performance_metrics(total_size, chunk_size, duration);
        return accumulate(partial_results.begin(), partial_results.end(), 0.0);
    }

    void print_config() const {
        cout << "Current configuration:\n"
             << "  Optimal threads: " << optimal_threads << "\n"
             << "  Optimal chunk size: " << optimal_chunk_size << "\n"
             << "  Slot capacity: " << encoder->slot_count() << endl;
    }
};

int main() {
    try {
        ParallelDotProduct pdp;
        pdp.print_config();

        const size_t test_size = 10000;
        vector<double> vec1(test_size), vec2(test_size);

        auto parallel_init = [](vector<double>& v, double init_val) {
            const unsigned threads = thread::hardware_concurrency();
            vector<thread> workers;
            const size_t chunk = v.size() / threads;

            for (unsigned t = 0; t < threads; ++t) {
                size_t start = t * chunk;
                size_t end = (t == threads - 1) ? v.size() : start + chunk;
                workers.emplace_back([&, start, end, init_val] {
                    for (size_t i = start; i < end; ++i) {
                        v[i] = init_val + i;
                    }
                });
            }

            for (auto& t : workers) t.join();
        };

        parallel_init(vec1, 1.0);
        parallel_init(vec2, 0.5);

        double result = pdp.compute(vec1, vec2);
        double expected = inner_product(vec1.begin(), vec1.end(), vec2.begin(), 0.0);

        cout << "\nResults:\n"
             << "  Computed: " << result << "\n"
             << "  Expected: " << expected << "\n"
             << "  Error: " << abs(result - expected) / expected << endl;

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
