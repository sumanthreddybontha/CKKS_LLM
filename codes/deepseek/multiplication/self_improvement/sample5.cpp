#include <iostream>
#include <vector>
#include <cmath>
#include <numeric>
#include "seal/seal.h"

using namespace std;
using namespace seal;

int main() {
    // Configuration parameters
    const size_t poly_modulus_degree = 8192;
    const size_t num_slots = poly_modulus_degree / 2;  // 4096 complex slots
    const double scale = pow(2.0, 40);
    const vector<int> bit_sizes = {50, 40, 40, 50};  // Optimal for 8192-degree

    // Set up encryption parameters
    EncryptionParameters params(scheme_type::ckks);
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, bit_sizes));

    // Create context
    SEALContext context(params);
    if (!context.parameters_set()) {
        cerr << "Error: Invalid encryption parameters" << endl;
        return -1;
    }

    // Key generation
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    // Create helper objects
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Generate test vectors
    vector<double> vec1(num_slots), vec2(num_slots);
    for (size_t i = 0; i < num_slots; ++i) {
        vec1[i] = 1.0 + 0.1 * i;
        vec2[i] = 0.5 + 0.01 * i;
    }

    // Encode and encrypt vectors
    Plaintext plain1, plain2;
    encoder.encode(vec1, scale, plain1);
    encoder.encode(vec2, scale, plain2);

    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Perform packed multiplication
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted1, encrypted2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);

    // Decrypt and decode the result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_product, plain_result);
    
    vector<double> packed_result;
    encoder.decode(plain_result, packed_result);

    // Compute plaintext result for comparison
    vector<double> plain_result_vec(num_slots);
    for (size_t i = 0; i < num_slots; ++i) {
        plain_result_vec[i] = vec1[i] * vec2[i];
    }

    // Selective extraction: first 5 and last element
    cout << "Packed vs Plaintext Results:" << endl;
    cout << "Index\tPacked\t\tPlaintext\tDifference" << endl;
    for (size_t i = 0; i < 5; ++i) {
        cout << i << "\t" << packed_result[i] << "\t" 
             << plain_result_vec[i] << "\t" 
             << abs(packed_result[i] - plain_result_vec[i]) << endl;
    }
    cout << "..." << endl;
    cout << num_slots-1 << "\t" << packed_result.back() << "\t" 
         << plain_result_vec.back() << "\t" 
         << abs(packed_result.back() - plain_result_vec.back()) << endl;

    // Calculate and show average error
    double total_error = 0.0;
    for (size_t i = 0; i < num_slots; ++i) {
        total_error += abs(packed_result[i] - plain_result_vec[i]);
    }
    cout << "\nAverage absolute error: " << total_error / num_slots << endl;

    return 0;
}