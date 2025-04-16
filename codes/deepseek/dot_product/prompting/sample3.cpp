#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void example_ckks_dot_product_batched();

int main() {
    example_ckks_dot_product_batched();
    return 0;
}

void example_ckks_dot_product_batched() {
    cout << "\nCKKS Dot Product: Batched Implementation\n" << endl;

    // Configuration
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    // Context
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    // Keys
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    GaloisKeys gal_keys = keygen.galois_keys();

    // Utilities
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    // Prepare multiple dot products
    size_t num_vectors = 4;
    size_t vec_size = slot_count / num_vectors;
    
    vector<double> vec1(slot_count, 0.0);
    vector<double> vec2(slot_count, 0.0);
    
    // Fill vectors with sample data for multiple dot products
    for (size_t i = 0; i < num_vectors; i++) {
        for (size_t j = 0; j < vec_size; j++) {
            vec1[i * vec_size + j] = (i + 1) * (j + 1);
            vec2[i * vec_size + j] = (i + 1) + (j + 1);
        }
    }

    // Encode and encrypt
    Plaintext plain_vec1, plain_vec2;
    encoder.encode(vec1, pow(2.0, 40), plain_vec1);
    encoder.encode(vec2, pow(2.0, 40), plain_vec2);

    Ciphertext encrypted_vec1, encrypted_vec2;
    encryptor.encrypt(plain_vec1, encrypted_vec1);
    encryptor.encrypt(plain_vec2, encrypted_vec2);

    // Compute element-wise multiplication
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted_vec1, encrypted_vec2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);

    // Sum each vector's elements separately
    Ciphertext encrypted_sums = encrypted_product;
    for (size_t i = vec_size; i < slot_count; i *= 2) {
        Ciphertext rotated;
        evaluator.rotate_vector(encrypted_sums, i, gal_keys, rotated);
        evaluator.add_inplace(encrypted_sums, rotated);
    }

    // Decrypt and decode
    Plaintext plain_sums;
    decryptor.decrypt(encrypted_sums, plain_sums);
    vector<double> sums;
    encoder.decode(plain_sums, sums);

    // Print results for each dot product
    for (size_t i = 0; i < num_vectors; i++) {
        double expected = 0.0;
        for (size_t j = 0; j < vec_size; j++) {
            expected += vec1[i * vec_size + j] * vec2[i * vec_size + j];
        }
        cout << "Dot product " << i+1 << ": " << sums[i * vec_size] 
             << " (expected: " << expected << ")" << endl;
    }
}