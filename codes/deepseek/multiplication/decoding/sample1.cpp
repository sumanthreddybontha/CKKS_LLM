#include <iostream>
#include <vector>
#include <chrono>
#include "seal/seal.h"

using namespace std;
using namespace seal;

void basic_ckks_matrix_multiplication() {
    // Step 1: Set up parameters with more appropriate values
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    
    // Adjusted coefficient modulus - larger primes for better scale handling
    params.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, 
        {50, 30, 30, 50}  // More balanced primes
    ));
    
    // Step 2: Create context
    SEALContext context(params);
    
    // Step 3: Generate keys
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    
    // Step 4: Set up encryptor, evaluator, decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    // Step 5: Create encoder
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    
    // Step 6: Prepare input data
    vector<double> input_matrix(100, 0.0); // 10x10 matrix
    vector<double> kernel(9, 0.0); // 3x3 kernel
    
    // Fill with sample data (scaled down to avoid overflow)
    for (size_t i = 0; i < 100; i++) {
        input_matrix[i] = static_cast<double>(i % 10) / 10.0; // Scaled down
    }
    for (size_t i = 0; i < 9; i++) {
        kernel[i] = 0.1; // Smaller kernel values
    }
    
    // Step 7: Encode and encrypt with more reasonable scale
    double scale = pow(2.0, 30);  // Reduced from 40 to 30
    Plaintext plain_matrix, plain_kernel;
    encoder.encode(input_matrix, scale, plain_matrix);
    encoder.encode(kernel, scale, plain_kernel);
    
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    
    // Step 8: Perform multiplication
    evaluator.multiply_plain_inplace(encrypted_matrix, plain_kernel);
    evaluator.rescale_to_next_inplace(encrypted_matrix);
    
    // Step 9: Decrypt and decode
    Plaintext plain_result;
    vector<double> result;
    decryptor.decrypt(encrypted_matrix, plain_result);
    encoder.decode(plain_result, result);
    
    // Print first few results
    cout << "First 10 result values: ";
    for (size_t i = 0; i < 10; i++) {
        cout << result[i] << " ";
    }
    cout << endl;
}

int main() {
    basic_ckks_matrix_multiplication();
    return 0;
}