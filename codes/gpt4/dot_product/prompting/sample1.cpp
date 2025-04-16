// CKKS Dot Product using Microsoft SEAL (Version 1)
// Unique implementation: vector size = 4, using manual scale and encoding
#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set encryption parameters for CKKS
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    // Step 2: Create SEALContext
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    // Step 3: Key generation
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // Step 4: Prepare vectors and encode
    vector<double> vec1 = {1.0, 2.0, 3.0, 4.0};
    vector<double> vec2 = {4.0, 3.0, 2.0, 1.0};

    double scale = pow(2.0, 40);
    Plaintext plain1, plain2;
    encoder.encode(vec1, scale, plain1);
    encoder.encode(vec2, scale, plain2);

    // Step 5: Encrypt the vectors
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Step 6: Element-wise multiplication
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted1, encrypted2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);

    // Step 7: Sum all elements in the encrypted vector
    // First, align the levels
    auto new_parms_id = encrypted_product.parms_id();
    encoder.encode(1.0, encrypted_product.scale(), plain1); // dummy plain for rotation weights

    GaloisKeys gal_keys = keygen.galois_keys_local();
    for (size_t i = 1; i < vec1.size(); i <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(encrypted_product, i, gal_keys, rotated);
        evaluator.add_inplace(encrypted_product, rotated);
    }

    // Step 8: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted_product, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    // Output the dot product (first element of result)
    cout << "Dot product: " << result[0] << endl;

    return 0;
}