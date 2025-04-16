// CKKS Dot Product using Microsoft SEAL (Version 2)
// Unique implementation: vector size = 3, uses different modulus chain and scaling
#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main() {
    // Step 1: CKKS encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 16384; // Larger poly_modulus_degree for higher precision
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 60 }));

    // Step 2: Create SEALContext
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    // Step 3: Key generation
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    auto gal_keys = keygen.galois_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Step 4: Define vectors
    vector<double> vec1 = {1.1, 2.2, 3.3};
    vector<double> vec2 = {3.0, 2.0, 1.0};

    double scale = pow(2.0, 40);
    Plaintext plain1, plain2;
    encoder.encode(vec1, scale, plain1);
    encoder.encode(vec2, scale, plain2);

    // Step 5: Encrypt vectors
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Step 6: Multiply encrypted vectors element-wise
    Ciphertext encrypted_mul;
    evaluator.multiply(encrypted1, encrypted2, encrypted_mul);
    evaluator.relinearize_inplace(encrypted_mul, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_mul);

    // Step 7: Sum the elements using rotations
    Ciphertext rotated;
    for (size_t i = 1; i < vec1.size(); i <<= 1) {
        evaluator.rotate_vector(encrypted_mul, i, gal_keys, rotated);
        evaluator.add_inplace(encrypted_mul, rotated);
    }

    // Step 8: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted_mul, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Dot product: " << result[0] << endl;

    return 0;
}