#include <iostream>
#include <vector>
#include <memory>
#include <chrono>
#include <seal/seal.h>
#include <thread>
#include <mutex>
#include <algorithm>
#include <numeric>

using namespace std;
using namespace seal;

mutex cout_mutex;

struct SystemConfig {
    size_t poly_modulus_degree = 8192;  // Reduced from 16384 for better performance
    vector<int> bit_sizes = {50, 40, 40, 50};  // Adjusted primes
    size_t batch_size = 4;
    size_t num_modulus_levels = 3;
    size_t num_threads = thread::hardware_concurrency();
    size_t large_data_threshold = 1000000;
    double scale = pow(2.0, 40);
};

struct ValidationResult {
    vector<double> plain_result;
    vector<double> decrypted_result;
    double max_error;
    double mean_error;
};

void print_parameters(const SEALContext& context) {
    auto& context_data = *context.key_context_data();
    auto& parms = context_data.parms();
    auto& coeff_modulus = parms.coeff_modulus();
    
    cout << "\nEncryption Parameters:" << endl;
    cout << "Scheme: CKKS" << endl;
    cout << "Poly modulus degree: " << parms.poly_modulus_degree() << endl;
    cout << "Coeff modulus size: " << coeff_modulus.size() << " (";
    for (size_t i = 0; i < coeff_modulus.size(); i++) {
        cout << coeff_modulus[i].bit_count() << (i < coeff_modulus.size() - 1 ? ", " : "");
    }
    cout << " bits)" << endl;
}

unique_ptr<SEALContext> create_context(const SystemConfig& config) {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(config.poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        config.poly_modulus_degree, config.bit_sizes));
    
    return make_unique<SEALContext>(parms, true, sec_level_type::tc128);
}

vector<vector<double>> create_batch_data(size_t total_elements, size_t batch_size) {
    vector<vector<double>> batches;
    size_t num_batches = (total_elements + batch_size - 1) / batch_size;

    for (size_t i = 0; i < num_batches; ++i) {
        size_t start = i * batch_size;
        size_t end = min(start + batch_size, total_elements);
        vector<double> batch(end - start);

        for (size_t j = 0; j < batch.size(); ++j) {
            batch[j] = 0.1 * (start + j + 1);
        }

        batches.push_back(move(batch));
    }

    return batches;
}

void encrypted_multiply(
    const CKKSEncoder& encoder,
    const Encryptor& encryptor,
    const Evaluator& evaluator,
    Decryptor& decryptor,
    const RelinKeys& relin_keys,
    const vector<double>& vec1,
    const vector<double>& vec2,
    ValidationResult& result,
    double scale)
{
    try {
        Plaintext plain1, plain2;
        encoder.encode(vec1, scale, plain1);
        encoder.encode(vec2, scale, plain2);

        Ciphertext encrypted1, encrypted2;
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);

        // CKKS multiplication
        evaluator.multiply_inplace(encrypted1, encrypted2);
        evaluator.relinearize_inplace(encrypted1, relin_keys);
        evaluator.rescale_to_next_inplace(encrypted1);

        Plaintext plain_result;
        decryptor.decrypt(encrypted1, plain_result);
        vector<double> decoded_result;
        encoder.decode(plain_result, decoded_result);

        // Compute expected result
        vector<double> expected_result(vec1.size());
        transform(vec1.begin(), vec1.end(), vec2.begin(), expected_result.begin(), multiplies<double>());

        // Calculate errors
        vector<double> errors(expected_result.size());
        transform(expected_result.begin(), expected_result.end(), decoded_result.begin(), errors.begin(),
            [](double a, double b) { return abs(a - b); });

        result.plain_result = move(expected_result);
        result.decrypted_result = move(decoded_result);
        result.max_error = *max_element(errors.begin(), errors.end());
        result.mean_error = accumulate(errors.begin(), errors.end(), 0.0) / errors.size();

    } catch (const exception& e) {
        cerr << "Error in multiplication: " << e.what() << endl;
        throw;
    }
}

int main() {
    try {
        SystemConfig config;
        
        // Create context
        auto context = create_context(config);
        print_parameters(*context);

        // Generate keys
        KeyGenerator keygen(*context);
        auto secret_key = keygen.secret_key();
        PublicKey public_key;
        keygen.create_public_key(public_key);
        RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);

        // Create crypto tools
        CKKSEncoder encoder(*context);
        Encryptor encryptor(*context, public_key);
        Evaluator evaluator(*context);
        Decryptor decryptor(*context, secret_key);

        // Test data
        vector<double> vec1 = {0.1, 0.2, 0.3, 0.4};
        vector<double> vec2 = {0.5, 0.6, 0.7, 0.8};
        
        ValidationResult result;
        encrypted_multiply(
            encoder, encryptor, evaluator, decryptor, relin_keys,
            vec1, vec2, result, config.scale);

        cout << "\nResults:" << endl;
        cout << "Plaintext result: ";
        for (auto v : result.plain_result) cout << v << " ";
        cout << "\nDecrypted result: ";
        for (auto v : result.decrypted_result) cout << v << " ";
        cout << "\nMax error: " << result.max_error << endl;
        cout << "Mean error: " << result.mean_error << endl;

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}