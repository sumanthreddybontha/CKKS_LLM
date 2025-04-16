#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

void batch_encoding_matrix_multiplication() {
    // Parameters optimized for batch processing
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 16384;  // Larger poly degree for more slots
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, 
        {50, 30, 30, 50}  // Balanced primes
    ));
    
    SEALContext context(params);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    size_t slot_count = encoder.slot_count();
    cout << "Total slots available: " << slot_count << endl;
    
    // Calculate how many 10x10 matrices we can fit (100 elements each)
    size_t matrices_per_batch = slot_count / 100;
    cout << "Can process " << matrices_per_batch << " matrices simultaneously" << endl;
    
    // Prepare batched data
    vector<double> batched_input(matrices_per_batch * 100);
    vector<double> batched_kernel(matrices_per_batch * 9);
    
    // Fill each matrix with different patterns
    for (size_t mat = 0; mat < matrices_per_batch; mat++) {
        for (size_t i = 0; i < 100; i++) {
            batched_input[mat * 100 + i] = static_cast<double>((i + mat) % 10) / 10.0;
        }
        for (size_t i = 0; i < 9; i++) {
            batched_kernel[mat * 9 + i] = 0.1 * (mat + 1);  // Different kernels
        }
    }
    
    // Encode and encrypt
    double scale = pow(2.0, 30);
    Plaintext plain_matrix, plain_kernel;
    encoder.encode(batched_input, scale, plain_matrix);
    encoder.encode(batched_kernel, scale, plain_kernel);
    
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    
    // Perform batched multiplication
    evaluator.multiply_plain_inplace(encrypted_matrix, plain_kernel);
    evaluator.rescale_to_next_inplace(encrypted_matrix);
    
    // Decrypt and decode
    Plaintext plain_result;
    vector<double> result;
    decryptor.decrypt(encrypted_matrix, plain_result);
    encoder.decode(plain_result, result);
    
    // Extract and print results for each matrix
    for (size_t mat = 0; mat < matrices_per_batch; mat++) {
        cout << "Matrix " << mat << " results (first 3 values): ";
        for (size_t i = 0; i < 3; i++) {
            cout << result[mat * 100 + i] << " ";
        }
        cout << endl;
    }
}

int main() {
    batch_encoding_matrix_multiplication();
    return 0;
}