#include <iostream>
#include <vector>
#include <memory>
#include <chrono>
#include <seal/seal.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#endif

using namespace std;
using namespace seal;

size_t get_current_memory_usage() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
    return pmc.WorkingSetSize / 1024;
#else
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss; // KB on Linux, bytes on Mac
#endif
}

void print_memory_usage(const string& phase) {
    size_t mem_usage = get_current_memory_usage();
    cout << "Memory usage at " << phase << ": " << mem_usage << " KB" << endl;
}

vector<double> process_in_chunks(const vector<double>& input1, 
                               const vector<double>& input2,
                               size_t chunk_size,
                               const SEALContext& context,
                               const CKKSEncoder& encoder,
                               const Encryptor& encryptor,
                               Decryptor& decryptor,  // Removed const
                               const Evaluator& evaluator,
                               const RelinKeys& relin_keys) {  // Changed to RelinKeys
    
    if (input1.size() != input2.size()) {
        throw invalid_argument("Input vectors must have the same size");
    }
    if (chunk_size == 0) {
        throw invalid_argument("Chunk size must be positive");
    }

    size_t total_size = input1.size();
    vector<double> result(total_size, 0.0);

    for (size_t start = 0; start < total_size; start += chunk_size) {
        size_t end = min(start + chunk_size, total_size);
        size_t current_chunk_size = end - start;

        cout << "\nProcessing chunk from " << start << " to " << (end-1) << endl;
        print_memory_usage("start of chunk processing");

        vector<double> chunk1(input1.begin() + start, input1.begin() + end);
        vector<double> chunk2(input2.begin() + start, input2.begin() + end);

        Plaintext plain1;
        encoder.encode(chunk1, context.first_parms_id(), pow(2.0, 40), plain1);
        Ciphertext encrypted1;
        encryptor.encrypt(plain1, encrypted1);

        Plaintext plain2;
        encoder.encode(chunk2, context.first_parms_id(), pow(2.0, 40), plain2);
        Ciphertext encrypted2;
        encryptor.encrypt(plain2, encrypted2);

        print_memory_usage("after encryption");

        Ciphertext encrypted_result;
        evaluator.multiply(encrypted1, encrypted2, encrypted_result);
        evaluator.relinearize_inplace(encrypted_result, relin_keys);  // Fixed
        evaluator.rescale_to_next_inplace(encrypted_result);

        print_memory_usage("after multiplication");

        Plaintext plain_result;
        decryptor.decrypt(encrypted_result, plain_result);
        vector<double> chunk_result;
        encoder.decode(plain_result, chunk_result);

        for (size_t i = 0; i < current_chunk_size; i++) {
            result[start + i] = chunk_result[i];
        }

        print_memory_usage("end of chunk processing");
    }

    return result;
}

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    SEALContext context(parms);
    print_memory_usage("after context creation");

    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);  // Not const
    CKKSEncoder encoder(context);

    const size_t chunk_size = 1024;
    const size_t total_size = 10 * chunk_size;
    vector<double> input1(total_size), input2(total_size);
    
    for (size_t i = 0; i < total_size; i++) {
        input1[i] = 1.1 * i;
        input2[i] = 0.9 * i;
    }

    print_memory_usage("before processing");

    auto start_time = chrono::high_resolution_clock::now();
    vector<double> result = process_in_chunks(input1, input2, chunk_size, 
                                            context, encoder, encryptor, 
                                            decryptor, evaluator, relin_keys);
    auto end_time = chrono::high_resolution_clock::now();

    print_memory_usage("after processing");

    cout << "\nVerifying results..." << endl;
    for (size_t i = 0; i < min(static_cast<size_t>(5), total_size); i++) {
        double expected = input1[i] * input2[i];
        cout << "Result[" << i << "]: " << result[i] 
             << " (expected: " << expected 
             << ", error: " << abs(result[i] - expected) << ")" << endl;
    }

    auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
    cout << "\nTotal processing time: " << duration.count() << " ms" << endl;

    return 0;
}