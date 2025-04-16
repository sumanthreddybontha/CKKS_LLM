#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <random>
#include <seal/seal.h>
#include <mach/mach.h> // macOS specific memory usage

using namespace std;
using namespace seal;

// macOS specific memory usage function
size_t get_current_rss() {
    task_vm_info_data_t vmInfo;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    kern_return_t result = task_info(mach_task_self(), TASK_VM_INFO, 
                                   (task_info_t) &vmInfo, &count);
    if (result != KERN_SUCCESS) {
        return 0;
    }
    return vmInfo.phys_footprint / (1024 * 1024); // Convert to MB
}

// Thread-safe random number generation
mutex rng_mutex;
double random_double(double min, double max) {
    lock_guard<mutex> lock(rng_mutex);
    static random_device rd;
    static mt19937 gen(rd());
    uniform_real_distribution<> dis(min, max);
    return dis(gen);
}

// Function to initialize a portion of the vector
void initialize_vector_part(vector<double>& vec, size_t start, size_t end, double min_val, double max_val) {
    for (size_t i = start; i < end; ++i) {
        vec[i] = random_double(min_val, max_val);
    }
}

// Parallel vector initialization
vector<double> parallel_initialize_vector(size_t size, size_t num_threads, double min_val, double max_val) {
    vector<double> vec(size);
    vector<thread> threads;
    
    size_t chunk_size = size / num_threads;
    size_t remainder = size % num_threads;
    
    size_t start = 0;
    for (size_t i = 0; i < num_threads; ++i) {
        size_t end = start + chunk_size + (i < remainder ? 1 : 0);
        threads.emplace_back(initialize_vector_part, ref(vec), start, end, min_val, max_val);
        start = end;
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    return vec;
}

// Serial vector initialization for comparison
vector<double> serial_initialize_vector(size_t size, double min_val, double max_val) {
    vector<double> vec(size);
    for (size_t i = 0; i < size; ++i) {
        vec[i] = random_double(min_val, max_val);
    }
    return vec;
}

int main() {
    try {
        // CKKS parameters
        EncryptionParameters params(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        params.set_poly_modulus_degree(poly_modulus_degree);
        
        // More conservative coefficient modulus for better stability
        vector<int> bit_sizes = {50, 30, 30, 50};
        params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, bit_sizes));
        
        SEALContext context(params);
        // print_parameters(context);
        
        KeyGenerator keygen(context);
        auto secret_key = keygen.secret_key();
        PublicKey public_key;
        keygen.create_public_key(public_key);
        
        Encryptor encryptor(context, public_key);
        Evaluator evaluator(context);
        Decryptor decryptor(context, secret_key);
        
        CKKSEncoder encoder(context);
        size_t slot_count = encoder.slot_count();
        cout << "Number of slots: " << slot_count << endl;
        
        // Test parameters
        const size_t vector_size = slot_count;
        const double min_val = 0.0;
        const double max_val = 1.0;
        const size_t num_threads = thread::hardware_concurrency();
        cout << "Using " << num_threads << " threads for parallel initialization" << endl;
        
        // Choose a more appropriate scale based on the parameters
        double scale = pow(2.0, 30);
        
        // 1. Parallel initialization
        cout << "\n=== Parallel Initialization ===" << endl;
        auto start_time = chrono::high_resolution_clock::now();
        
        cout << "Memory before initialization: " << get_current_rss() << "MB" << endl;
        vector<double> input_vec = parallel_initialize_vector(vector_size, num_threads, min_val, max_val);
        
        auto init_end_time = chrono::high_resolution_clock::now();
        cout << "Memory after initialization (pre-encryption): " << get_current_rss() << "MB" << endl;
        
        // Serial cryptographic operations
        Plaintext plain;
        cout << "Encoding with scale: " << scale << endl;
        encoder.encode(input_vec, scale, plain);
        
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);
        
        auto encrypt_end_time = chrono::high_resolution_clock::now();
        
        // Measure times
        auto parallel_init_time = chrono::duration_cast<chrono::milliseconds>(init_end_time - start_time).count();
        auto parallel_encrypt_time = chrono::duration_cast<chrono::milliseconds>(encrypt_end_time - init_end_time).count();
        auto parallel_total_time = chrono::duration_cast<chrono::milliseconds>(encrypt_end_time - start_time).count();
        
        cout << "Parallel initialization time: " << parallel_init_time << "ms" << endl;
        cout << "Encryption time: " << parallel_encrypt_time << "ms" << endl;
        cout << "Total time (parallel): " << parallel_total_time << "ms" << endl;
        
        // 2. Serial initialization for comparison
        cout << "\n=== Serial Initialization ===" << endl;
        start_time = chrono::high_resolution_clock::now();
        
        cout << "Memory before initialization: " << get_current_rss() << "MB" << endl;
        input_vec = serial_initialize_vector(vector_size, min_val, max_val);
        
        init_end_time = chrono::high_resolution_clock::now();
        cout << "Memory after initialization (pre-encryption): " << get_current_rss() << "MB" << endl;
        
        // Serial cryptographic operations
        encoder.encode(input_vec, scale, plain);
        encryptor.encrypt(plain, encrypted);
        
        encrypt_end_time = chrono::high_resolution_clock::now();
        
        // Measure times
        auto serial_init_time = chrono::duration_cast<chrono::milliseconds>(init_end_time - start_time).count();
        auto serial_encrypt_time = chrono::duration_cast<chrono::milliseconds>(encrypt_end_time - init_end_time).count();
        auto serial_total_time = chrono::duration_cast<chrono::milliseconds>(encrypt_end_time - start_time).count();
        
        cout << "Serial initialization time: " << serial_init_time << "ms" << endl;
        cout << "Encryption time: " << serial_encrypt_time << "ms" << endl;
        cout << "Total time (serial): " << serial_total_time << "ms" << endl;
        
        // Calculate speedup
        double init_speedup = static_cast<double>(serial_init_time) / parallel_init_time;
        double total_speedup = static_cast<double>(serial_total_time) / parallel_total_time;
        
        cout << "\n=== Results ===" << endl;
        cout << "Initialization speedup: " << init_speedup << "x" << endl;
        cout << "Total speedup: " << total_speedup << "x" << endl;
        
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }
    
    return 0;
}