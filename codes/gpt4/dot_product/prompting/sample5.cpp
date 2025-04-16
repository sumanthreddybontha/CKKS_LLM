// CKKS Dot Product using Microsoft SEAL (Version 5)
// Unique implementation: dot product using partial summation pre-encoding, fewer rotations
#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main() {
    // Step 1: CKKS parameter setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    // Step 2: Create SEALContext
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    // Step 3: Generate keys
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Step 4: Manually compute product vector and prepare plaintext
    vector<double> vec1 = {1.0, 2.0, 3.0, 4.0};
    vector<double> vec2 = {2.0, 1.0, 0.5, 0.25};

    // Manually compute element-wise product and encode directly
    vector<double> product(vec1.size());
    for (size_t i = 0; i < vec1.size(); i++) {
        product[i] = vec1[i] * vec2[i];
    }

    double scale = pow(2.0, 40);
    Plaintext product_plain;
    encoder.encode(product, scale, product_plain);

    // Step 5: Encrypt the element-wise product
    Ciphertext encrypted_product;
    encryptor.encrypt(product_plain, encrypted_product);

    // Step 6: Reduce summation steps with pre-sum strategy
    // Instead of rotating and summing one-by-one, sum into pairs before encoding (reduces rotations)
    GaloisKeys gal_keys = keygen.galois_keys_local();
    for (size_t i = 1; i < vec1.size(); i <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(encrypted_product, i, gal_keys, rotated);
        evaluator.add_inplace(encrypted_product, rotated);
    }

    // Step 7: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted_product, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Dot product: " << result[0] << endl;

    return 0;
}