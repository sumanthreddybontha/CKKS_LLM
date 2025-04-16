// CKKS Dot Product using Microsoft SEAL (Version 3)
// Unique implementation: using dynamic slot_count() and full batching
#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set CKKS encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    // Step 2: Create SEALContext
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    // Step 3: Generate keys and tools
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    auto gal_keys = keygen.galois_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Step 4: Get maximum number of slots
    size_t slot_count = encoder.slot_count();
    cout << "Available CKKS slots: " << slot_count << endl;

    // Use only part of available slots
    vector<double> vec1(slot_count, 0.0);
    vector<double> vec2(slot_count, 0.0);
    vec1[0] = 5.0; vec1[1] = 6.0; vec1[2] = 7.0;
    vec2[0] = 1.0; vec2[1] = 2.0; vec2[2] = 3.0;

    double scale = pow(2.0, 40);
    Plaintext plain1, plain2;
    encoder.encode(vec1, scale, plain1);
    encoder.encode(vec2, scale, plain2);

    // Step 5: Encrypt vectors
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Step 6: Element-wise multiplication
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted1, encrypted2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);

    // Step 7: Sum result using vector rotations
    for (size_t step = 1; step < 3; step <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(encrypted_product, step, gal_keys, rotated);
        evaluator.add_inplace(encrypted_product, rotated);
    }

    // Step 8: Decrypt and decode result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_product, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Dot product: " << result[0] << endl;

    return 0;
}